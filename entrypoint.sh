#!/bin/sh

echo "Starting nginxhashlock..."

# On first run, save the original template
if [ ! -f /etc/nginx/nginx.conf.template ]; then
    echo "Saving original nginx.conf as template..."
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.template
fi

# Always start with a clean copy from template
echo "Copying clean template to working config..."
if ! cp /etc/nginx/nginx.conf.template /etc/nginx/nginx.conf; then
    echo "ERROR: Failed to copy template to working config"
    exit 1
fi

# Validate inputs before using in sed replacements
if ! echo "$BACKEND_HOST" | grep -qE '^[a-zA-Z0-9._-]+$'; then
    echo "ERROR: Invalid BACKEND_HOST (only alphanumeric, dots, underscores, and hyphens allowed)"
    exit 1
fi

if ! echo "$BACKEND_PORT" | grep -qE '^[0-9]+$' || [ "$BACKEND_PORT" -lt 1 ] || [ "$BACKEND_PORT" -gt 65535 ]; then
    echo "ERROR: Invalid BACKEND_PORT (must be 1-65535)"
    exit 1
fi

if ! echo "$LISTEN_PORT" | grep -qE '^[0-9]+$' || [ "$LISTEN_PORT" -lt 1 ] || [ "$LISTEN_PORT" -gt 65535 ]; then
    echo "ERROR: Invalid LISTEN_PORT (must be 1-65535)"
    exit 1
fi

# Replace basic placeholders
sed -i "s/BACKEND_HOST_PLACEHOLDER/$BACKEND_HOST/g" /etc/nginx/nginx.conf
sed -i "s/BACKEND_PORT_PLACEHOLDER/$BACKEND_PORT/g" /etc/nginx/nginx.conf
sed -i "s/LISTEN_PORT_PLACEHOLDER/$LISTEN_PORT/g" /etc/nginx/nginx.conf

# Determine authentication mode
AUTH_MODE="none"
if [ -n "$AUTH_HASH" ] && [ -n "$USER" ] && [ -n "$PASSWORD" ]; then
    AUTH_MODE="both"
elif [ -n "$AUTH_HASH" ]; then
    AUTH_MODE="hash_only"
elif [ -n "$USER" ] && [ -n "$PASSWORD" ]; then
    AUTH_MODE="credentials_only"
fi

echo "========================================="
echo "Authentication Mode: $AUTH_MODE"
echo "========================================="

# Start auth service if credentials are configured
if [ "$AUTH_MODE" = "credentials_only" ] || [ "$AUTH_MODE" = "both" ]; then
    echo "Starting authentication service..."
    export SESSION_DURATION_HOURS="${SESSION_DURATION_HOURS:-720}"
    cd /app/auth-service
    node app.js > /var/log/auth-service.log 2>&1 &
    AUTH_SERVICE_PID=$!
    echo "Auth service started with PID: $AUTH_SERVICE_PID"
    cd /

    # Wait for auth service to be ready with timeout
    echo "Waiting for auth service to be ready..."
    TIMEOUT=10
    for i in $(seq 1 $TIMEOUT); do
        # Try curl first, fall back to nc (netcat) port check
        if command -v curl > /dev/null 2>&1; then
            if curl -sf --max-time 2 http://127.0.0.1:9999/health > /dev/null 2>&1; then
                echo "Auth service is ready"
                break
            fi
        elif command -v nc > /dev/null 2>&1; then
            if nc -z 127.0.0.1 9999 > /dev/null 2>&1; then
                echo "Auth service is ready (port check)"
                break
            fi
        else
            # No curl or nc available, just wait and trust the logs
            if [ $i -ge 3 ]; then
                echo "Auth service assumed ready (no health check tools available)"
                break
            fi
        fi

        if [ $i -eq $TIMEOUT ]; then
            echo "ERROR: Auth service failed to start within ${TIMEOUT}s"
            echo "Last 20 lines of auth service log:"
            tail -20 /var/log/auth-service.log
            exit 1
        fi
        sleep 1
    done
fi

# Build the authentication check block based on AUTH_MODE
AUTH_CHECK_BLOCK=""

case "$AUTH_MODE" in
    "none")
        echo "No authentication configured - allowing all requests"
        AUTH_CHECK_BLOCK="            # No authentication required"
        ;;

    "hash_only")
        echo "Hash-only authentication configured"
        AUTH_CHECK_BLOCK="            # Hash-only authentication
            if (\$arg_hash != \"$AUTH_HASH\") {
                return 403;
            }"
        ;;

    "credentials_only")
        echo "Credentials-only authentication configured"
        AUTH_CHECK_BLOCK="            # Credentials-only authentication
            auth_request /internal-auth-check;
            auth_request_set \$auth_cookie \$upstream_http_set_cookie;
            add_header Set-Cookie \$auth_cookie;
            error_page 401 = @auth_failed_login;"

        # Add named location for auth failure handling
        sed -i 's|location / {|location @auth_failed_login {\
            return 302 /login?redirect=$request_uri;\
        }\
\
        location / {|' /etc/nginx/nginx.conf
        ;;

    "both")
        echo "Both hash and credentials authentication configured"
        AUTH_CHECK_BLOCK="            # Auth service checks both hash and session
            auth_request /internal-auth-check;
            auth_request_set \$auth_cookie \$upstream_http_set_cookie;
            add_header Set-Cookie \$auth_cookie;
            error_page 401 = @auth_failed_login;"

        # Use same simple redirect as credentials_only
        # Auth service handles hash checking internally
        sed -i 's|location / {|location @auth_failed_login {\
            return 302 /login?redirect=$request_uri;\
        }\
\
        location / {|' /etc/nginx/nginx.conf
        ;;
esac

# Prepare authentication block for insertion (deferred until after dynamic paths configuration)
AUTH_CHECK_ESCAPED=$(echo "$AUTH_CHECK_BLOCK" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\$/\\$/g' | sed 's/\//\\\//g')

# Handle ALLOWED_EXTENSIONS
if [ -n "$ALLOWED_EXTENSIONS" ]; then
    echo "Configuring allowed extensions: $ALLOWED_EXTENSIONS"
    # Convert comma-separated to regex format: js,css,png -> (js|css|png)
    EXTENSIONS_REGEX=$(echo "$ALLOWED_EXTENSIONS" | sed 's/,/|/g')
    EXTENSIONS_REGEX="($EXTENSIONS_REGEX)"
    echo "Extensions regex: $EXTENSIONS_REGEX"
    # Escape forward slashes for sed (pipes and parentheses should NOT be escaped for nginx regex)
    EXTENSIONS_ESCAPED=$(echo "$EXTENSIONS_REGEX" | sed 's/\//\\\//g')
    sed -i "s/ALLOWED_EXTENSIONS_PLACEHOLDER/$EXTENSIONS_ESCAPED/g" /etc/nginx/nginx.conf
else
    echo "No allowed extensions configured - removing extensions block"
    # Remove the entire extensions location block if no extensions specified
    sed -i '/# Allow specific file extensions/,/^        }/d' /etc/nginx/nginx.conf
fi

# Handle ALLOWED_PATHS
if [ -n "$ALLOWED_PATHS" ]; then
    echo "Configuring allowed paths: $ALLOWED_PATHS"
    # Normalize paths: strip leading/trailing slashes and spaces from each comma-separated value
    # This handles: "/guild,/auth" -> "guild,auth"
    #              "login, /api/health/, /guild" -> "login,api/health,guild"
    #              "page/\",/something/else/" -> "page/\",something/else"
    NORMALIZED_PATHS=$(echo "$ALLOWED_PATHS" | \
        sed 's/^[ \/]\+//;s/[ \/]\+$//;s/[ \/]\+,/,/g;s/,[ \/]\+/,/g' | \
        sed 's/,\+/,/g')
    echo "Normalized paths: $NORMALIZED_PATHS"
    # Convert comma-separated to regex format: login,api/health -> (login|api/health)
    PATHS_REGEX=$(echo "$NORMALIZED_PATHS" | sed 's/,/|/g')
    PATHS_REGEX="($PATHS_REGEX)"
    echo "Paths regex: $PATHS_REGEX"
    # Escape only forward slashes for sed substitution (pipes and parentheses should NOT be escaped for nginx regex)
    PATHS_ESCAPED=$(echo "$PATHS_REGEX" | sed 's/\//\\\//g')
    sed -i "s/ALLOWED_PATHS_PLACEHOLDER/$PATHS_ESCAPED/g" /etc/nginx/nginx.conf
else
    echo "No allowed paths configured - removing paths block"
    # Remove the entire paths location block if no paths specified
    sed -i '/# Allow specific paths/,/^        }/d' /etc/nginx/nginx.conf
fi

# Handle ALLOW_HASH_CONTENT_PATHS (for Stremio and similar apps that use 40-char hex paths)
if [ "$ALLOW_HASH_CONTENT_PATHS" = "true" ] || [ "$ALLOW_HASH_CONTENT_PATHS" = "1" ]; then
    echo "Enabling hash content paths bypass (40-character hex paths)"

    # Create hash paths config file - allows paths like /bca2d44dcd7655ecfdffe81659a569d3525f0195/...
    cat > /tmp/hash_content_paths.conf <<EOF
        # Allow 40-character hex content paths without authentication
        # Used by Stremio and similar apps where the hash itself is the access token
        location ~ "^/[a-f0-9]{40}" {
            proxy_pass http://$BACKEND_HOST:$BACKEND_PORT;
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
        }
EOF

    # Insert the include directive before main location
    if ! grep -q "include /tmp/hash_content_paths.conf" /etc/nginx/nginx.conf; then
        sed -i '0,/# Main location - authentication logic/s//        include \/tmp\/hash_content_paths.conf;\n\n        &/' /etc/nginx/nginx.conf
    fi

    echo "Hash content paths enabled - paths matching /[a-f0-9]{40}* bypass authentication"
else
    echo "Hash content paths disabled (set ALLOW_HASH_CONTENT_PATHS=true to enable)"
fi

# Apply authentication block to nginx configuration
sed -i "s/AUTH_CHECK_BLOCK_PLACEHOLDER/$AUTH_CHECK_ESCAPED/" /etc/nginx/nginx.conf

echo "========================================="
echo "Final nginx configuration:"
echo "========================================="
cat /etc/nginx/nginx.conf
echo "========================================="

# Start nginx
echo "Starting nginx..."
exec nginx -g "daemon off;"

