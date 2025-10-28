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

const server = http.createServer((req, res) => {
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

server.listen(LISTEN_PORT, '127.0.0.1', () => {
    console.log(`Dynamic auth checker listening on port ${LISTEN_PORT}`);
});
JSEOF

# Run the Node.js server
exec node /tmp/dynamic-auth-server.js