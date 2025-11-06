#!/bin/sh
# Dynamic path auth checker service for nginxhashlock
# Listens on localhost:9998 and checks if requested paths are in the allowlist

DYNAMIC_PATHS_FILE="${DYNAMIC_PATHS_FILE:-/tmp/dynamic_paths/allowed.txt}"
LISTEN_PORT=9998

echo "Starting dynamic auth checker on port $LISTEN_PORT"
echo "Watching file: $DYNAMIC_PATHS_FILE"

# Create a simple Node.js server instead of using netcat (more reliable)
cat > /tmp/dynamic-auth-server.js <<'JSEOF'
const http = require('http');
const fs = require('fs');

const DYNAMIC_PATHS_FILE = process.env.DYNAMIC_PATHS_FILE || '/tmp/dynamic_paths/allowed.txt';
const LISTEN_PORT = 9998;

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
    // Handle request errors to prevent crashes
    req.on('error', (err) => {
        console.error('[DYNAMIC-AUTH] Request error:', err);
        try {
            res.writeHead(500);
            res.end();
        } catch (e) {
            console.error('[DYNAMIC-AUTH] Failed to send error response:', e);
        }
    });

    res.on('error', (err) => {
        console.error('[DYNAMIC-AUTH] Response error:', err);
    });

    // Extract the original URI from header
    const originalUri = req.headers['x-original-uri'] || '';

    // Extract hash from URI (40 hex chars)
    const hashMatch = originalUri.match(/[a-f0-9]{40}/);
    const hash = hashMatch ? hashMatch[0] : null;

    if (!hash) {
        res.writeHead(403);
        res.end();
        return;
    }

    // Check if request is from Docker internal network (container-to-container)
    const remoteAddr = req.headers['x-real-ip'] || req.connection.remoteAddress || '';
    const isInternalRequest = isDockerInternalIP(remoteAddr);

    if (isInternalRequest) {
        // Internal requests from Stremio server itself - always allow
        console.log(`[DYNAMIC-AUTH] Internal request from ${remoteAddr} for hash ${hash} - allowing`);
        res.writeHead(204);
        res.end();
        return;
    }

    // Check if hash is in allowlist with valid timestamp
    const currentTime = Math.floor(Date.now() / 1000);
    let allowed = false;

    try {
        if (fs.existsSync(DYNAMIC_PATHS_FILE)) {
            const content = fs.readFileSync(DYNAMIC_PATHS_FILE, 'utf8');
            const lines = content.split('\n').filter(line => line.trim());

            for (const line of lines) {
                const [allowedHash, expiryTime] = line.split(':');
                if (allowedHash === hash && parseInt(expiryTime) > currentTime) {
                    allowed = true;
                    break;
                }
            }
        }
    } catch (err) {
        console.error('Error reading dynamic paths file:', err);
    }

    if (allowed) {
        res.writeHead(204); // No Content - auth passed
    } else {
        res.writeHead(403); // Forbidden
    }
    res.end();
});

// Handle server-level errors
server.on('error', (err) => {
    console.error('[DYNAMIC-AUTH] Server error:', err);
});

server.on('clientError', (err, socket) => {
    console.error('[DYNAMIC-AUTH] Client error:', err.message);
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

server.listen(LISTEN_PORT, '127.0.0.1', () => {
    console.log(`Dynamic auth checker listening on port ${LISTEN_PORT}`);
});

// Prevent crashes from uncaught exceptions
process.on('uncaughtException', (err) => {
    console.error('[DYNAMIC-AUTH] Uncaught exception:', err);
    console.error('[DYNAMIC-AUTH] Service continuing...');
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('[DYNAMIC-AUTH] Unhandled rejection at:', promise, 'reason:', reason);
    console.error('[DYNAMIC-AUTH] Service continuing...');
});
JSEOF

# Run the Node.js server with auto-restart
while true; do
    echo "[DYNAMIC-AUTH] Starting service..."
    node /tmp/dynamic-auth-server.js
    EXIT_CODE=$?
    echo "[DYNAMIC-AUTH] Service exited with code $EXIT_CODE, restarting in 2 seconds..."
    sleep 2
done