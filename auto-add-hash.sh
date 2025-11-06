#!/bin/sh
# Auto-add hash service for nginxhashlock
# Automatically adds 40-character hex path identifiers to the dynamic allowlist when authenticated users access them

DYNAMIC_PATHS_FILE="${DYNAMIC_PATHS_FILE:-/tmp/dynamic_paths/allowed.txt}"
DEFAULT_TTL=3600  # 1 hour
LISTEN_PORT=9997

echo "Starting auto-add hash service on port $LISTEN_PORT"
echo "Adding hashes to: $DYNAMIC_PATHS_FILE"
echo "Default TTL: $DEFAULT_TTL seconds"

# Create a Node.js server to handle the requests
cat > /tmp/auto-add-hash-server.js <<'JSEOF'
const http = require('http');
const fs = require('fs');

const DYNAMIC_PATHS_FILE = process.env.DYNAMIC_PATHS_FILE || '/tmp/dynamic_paths/allowed.txt';
const DEFAULT_TTL = 3600; // 1 hour in seconds
const LISTEN_PORT = 9997;
const AUTH_SERVICE_URL = 'http://127.0.0.1:9999/nhl-auth/check';

// Helper function to check if IP is from Docker internal network
function isDockerInternalIP(ip) {
    // Remove IPv6 prefix if present
    ip = ip.replace(/^::ffff:/, '');

    // Localhost
    if (ip === '127.0.0.1' || ip === '::1') return true;

    const parts = ip.split('.');
    if (parts.length !== 4) return false;

    const first = parseInt(parts[0]);
    const second = parseInt(parts[1]);

    // Docker network ranges
    // 10.0.0.0/8
    if (first === 10) return true;

    // 172.16.0.0/12
    if (first === 172 && second >= 16 && second <= 31) return true;

    // 192.168.0.0/16
    if (first === 192 && second === 168) return true;

    return false;
}

const server = http.createServer((req, res) => {
    const originalUri = req.headers['x-original-uri'] || '';
    const cookie = req.headers['cookie'] || '';
    const hashMatch = originalUri.match(/[a-f0-9]{40}/);
    const hash = hashMatch ? hashMatch[0] : null;

    if (!hash) {
        res.writeHead(403);
        res.end();
        return;
    }

    // Handle request errors to prevent crashes
    req.on('error', (err) => {
        console.error('[AUTO-ADD] Request error:', err);
        try {
            res.writeHead(500);
            res.end();
        } catch (e) {
            console.error('[AUTO-ADD] Failed to send error response:', e);
        }
    });

    res.on('error', (err) => {
        console.error('[AUTO-ADD] Response error:', err);
    });

    // Check if request is from Docker internal network (container-to-container)
    const remoteAddr = req.headers['x-real-ip'] || req.connection.remoteAddress || '';
    const isInternalRequest = isDockerInternalIP(remoteAddr);

    if (isInternalRequest) {
        // Internal requests from Stremio server itself - always allow and add to allowlist
        console.log(`[AUTO-ADD] Internal request from ${remoteAddr} for hash ${hash} - bypassing auth`);
        if (!isHashAllowed(hash)) {
            addHashToAllowlist(hash);
        }
        res.writeHead(204);
        res.end();
        return;
    }

    // FIRST check if hash is already in allowlist (for subsequent requests)
    if (isHashAllowed(hash)) {
        res.writeHead(204);
        res.end();
        return;
    }

    // Hash not in allowlist - check if user is authenticated to add it
    // Check multiple sources for the auth hash parameter
    const referer = req.headers['referer'] || '';
    let authUri = originalUri;

    // Check for hash in multiple places (in order of preference)
    let authHash = null;

    // 1. Check original URI
    if (originalUri.includes('hash=')) {
        const match = originalUri.match(/[?&]hash=([^&]+)/);
        if (match) authHash = match[1];
    }

    // 2. Check referer
    if (!authHash && referer.includes('hash=')) {
        const match = referer.match(/[?&]hash=([^&]+)/);
        if (match) authHash = match[1];
    }

    // 3. Check for hash in a custom header (set by the browser on XHR/fetch requests)
    const xAuthHash = req.headers['x-auth-hash'] || '';
    if (!authHash && xAuthHash) {
        authHash = xAuthHash;
    }

    // Append hash to URI for auth check if we found one
    if (authHash && !originalUri.includes('hash=')) {
        authUri = originalUri + (originalUri.includes('?') ? '&' : '?') + 'hash=' + authHash;
    }

    const authReq = http.request(AUTH_SERVICE_URL, {
        method: 'GET',
        headers: {
            'Cookie': cookie,
            'X-Original-URI': authUri
        }
    }, (authRes) => {
        if (authRes.statusCode === 200 || authRes.statusCode === 204) {
            // User is authenticated - add hash to allowlist and allow
            addHashToAllowlist(hash);
            res.writeHead(204);
            res.end();
        } else {
            // Not authenticated - deny access
            res.writeHead(403);
            res.end();
        }
    });

    authReq.on('error', (err) => {
        // Auth service error - fall back to dynamic allowlist check
        console.error('[AUTO-ADD] Auth service connection error:', err.message);
        if (isHashAllowed(hash)) {
            res.writeHead(204);
            res.end();
        } else {
            res.writeHead(403);
            res.end();
        }
    });

    // Add timeout to prevent hanging connections
    authReq.setTimeout(5000, () => {
        console.error('[AUTO-ADD] Auth service request timeout');
        authReq.destroy();
    });

    authReq.end();
});

function isHashAllowed(hash) {
    const currentTime = Math.floor(Date.now() / 1000);
    try {
        if (fs.existsSync(DYNAMIC_PATHS_FILE)) {
            const content = fs.readFileSync(DYNAMIC_PATHS_FILE, 'utf8');
            const lines = content.split('\n').filter(line => line.trim());
            for (const line of lines) {
                const [allowedHash, expiryTime] = line.split(':');
                if (allowedHash === hash && parseInt(expiryTime) > currentTime) {
                    return true;
                }
            }
        }
    } catch (err) {
        console.error('[AUTO-ADD] Error checking hash:', err);
    }
    return false;
}

function addHashToAllowlist(hash) {
    try {
        const currentTime = Math.floor(Date.now() / 1000);
        const expiryTime = currentTime + DEFAULT_TTL;

        // Read existing entries
        let entries = [];
        if (fs.existsSync(DYNAMIC_PATHS_FILE)) {
            const content = fs.readFileSync(DYNAMIC_PATHS_FILE, 'utf8');
            entries = content.split('\n').filter(line => line.trim());
        }

        // Check if hash already exists with valid expiry
        const existingIndex = entries.findIndex(line => {
            const [existingHash, existingExpiry] = line.split(':');
            return existingHash === hash && parseInt(existingExpiry) > currentTime;
        });

        if (existingIndex === -1) {
            // Add new entry
            entries.push(`${hash}:${expiryTime}`);

            // Clean up expired entries
            entries = entries.filter(line => {
                const [, expiry] = line.split(':');
                return parseInt(expiry) > currentTime;
            });

            // Keep only last 100 entries
            if (entries.length > 100) {
                entries = entries.slice(-100);
            }

            // Write back to file
            fs.writeFileSync(DYNAMIC_PATHS_FILE, entries.join('\n') + '\n');
            console.log(`[AUTO-ADD] Added hash ${hash} (expires in ${DEFAULT_TTL}s)`);
        } else {
            console.log(`[AUTO-ADD] Hash ${hash} already in allowlist`);
        }
    } catch (err) {
        console.error('[AUTO-ADD] Error adding hash:', err);
    }
}

// Handle server-level errors
server.on('error', (err) => {
    console.error('[AUTO-ADD] Server error:', err);
});

server.on('clientError', (err, socket) => {
    console.error('[AUTO-ADD] Client error:', err.message);
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

server.listen(LISTEN_PORT, '127.0.0.1', () => {
    console.log(`[AUTO-ADD] Listening on port ${LISTEN_PORT}`);
});

// Prevent crashes from uncaught exceptions
process.on('uncaughtException', (err) => {
    console.error('[AUTO-ADD] Uncaught exception:', err);
    console.error('[AUTO-ADD] Service continuing...');
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('[AUTO-ADD] Unhandled rejection at:', promise, 'reason:', reason);
    console.error('[AUTO-ADD] Service continuing...');
});
JSEOF

# Run the Node.js server with auto-restart
while true; do
    echo "[AUTO-ADD] Starting service..."
    node /tmp/auto-add-hash-server.js
    EXIT_CODE=$?
    echo "[AUTO-ADD] Service exited with code $EXIT_CODE, restarting in 2 seconds..."
    sleep 2
done
