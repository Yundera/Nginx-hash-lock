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

# Subdomain hash extraction setup
SUBDOMAIN_HASH_ENABLED="${SUBDOMAIN_HASH_ENABLED:-false}"
BACKEND_HASH="${BACKEND_HASH:-serverhash}"
SUBDOMAIN_PATTERN="${SUBDOMAIN_PATTERN:-^([^-]+)-}"
SUBDOMAIN_HASH_LENGTH="${SUBDOMAIN_HASH_LENGTH:-24}"

# Validate SUBDOMAIN_PATTERN to prevent injection (only allow safe regex chars)
if [ "$SUBDOMAIN_HASH_ENABLED" = "true" ] && ! echo "$SUBDOMAIN_PATTERN" | grep -qE '^[\^$()[\].+*?|-]+$'; then
    echo "ERROR: Invalid SUBDOMAIN_PATTERN (only basic regex characters allowed)"
    exit 1
fi

# Validate secondary backend if dual routing is enabled
if [ -n "$SECONDARY_BACKEND_HOST" ]; then
    if ! echo "$SECONDARY_BACKEND_HOST" | grep -qE '^[a-zA-Z0-9._-]+$'; then
        echo "ERROR: Invalid SECONDARY_BACKEND_HOST"
        exit 1
    fi
fi

if [ -n "$SECONDARY_BACKEND_PORT" ]; then
    if ! echo "$SECONDARY_BACKEND_PORT" | grep -qE '^[0-9]+$' || [ "$SECONDARY_BACKEND_PORT" -lt 1 ] || [ "$SECONDARY_BACKEND_PORT" -gt 65535 ]; then
        echo "ERROR: Invalid SECONDARY_BACKEND_PORT (must be 1-65535)"
        exit 1
    fi
fi

if [ "$SUBDOMAIN_HASH_ENABLED" = "true" ]; then
    # Truncate backend hash to specified length for subdomain comparison
    # This addresses DNS label length limits (63 chars max)
    SUBDOMAIN_HASH_SHORT=$(echo "$BACKEND_HASH" | cut -c1-"$SUBDOMAIN_HASH_LENGTH")
    echo "Subdomain hash extraction enabled"
    echo "Pattern: $SUBDOMAIN_PATTERN"
    echo "Backend hash: $BACKEND_HASH"
    echo "Subdomain hash (first $SUBDOMAIN_HASH_LENGTH chars): $SUBDOMAIN_HASH_SHORT"
fi

# Secondary backend for dual routing
SECONDARY_BACKEND_HOST="${SECONDARY_BACKEND_HOST:-}"
SECONDARY_BACKEND_PORT="${SECONDARY_BACKEND_PORT:-}"

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
if [ "$SUBDOMAIN_HASH_ENABLED" = "true" ]; then
    echo "Subdomain Routing: Enabled"
fi
if [ -n "$SECONDARY_BACKEND_HOST" ]; then
    echo "Secondary Backend: $SECONDARY_BACKEND_HOST:$SECONDARY_BACKEND_PORT"
fi
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

# Note: AUTH_CHECK_BLOCK will be escaped and inserted later (after all modifications)

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

# Dynamic paths are no longer used - using subdomain authentication instead

# Handle hash-authenticated path (optional, for app cross-device auth)
HASH_AUTH_PATH="${HASH_AUTH_PATH:-}"

if [ -n "$HASH_AUTH_PATH" ]; then
    echo "Configuring hash-authenticated path: $HASH_AUTH_PATH"

    # Build the hash auth path block
    HASH_AUTH_BLOCK="        # Dedicated hash-authenticated path for cross-device app authentication
        location ~ ^${HASH_AUTH_PATH}(/.*)?$ {
            # Hash validation happens in auth check
            auth_request /internal-auth-check;
            error_page 401 = @auth_failed_hashpath;

            # Capture the path after prefix
            set \$backend_path \$1;
            if (\$backend_path = \"\") {
                set \$backend_path \"/\";
            }

            # Proxy to backend, stripping prefix but keeping query string
            proxy_pass http://${BACKEND_HOST}:${BACKEND_PORT}\$backend_path\$is_args\$args;
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection \"upgrade\";
        }

        location @auth_failed_hashpath {
            default_type application/json;
            return 401 '{\"error\": \"Unauthorized\", \"message\": \"Invalid or missing hash\"}';
        }
"

    # Escape for sed
    HASH_AUTH_ESCAPED=$(echo "$HASH_AUTH_BLOCK" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\$/\\$/g' | sed 's/\//\\\//g')
    sed -i "s/HASH_AUTH_PATH_BLOCK_PLACEHOLDER/$HASH_AUTH_ESCAPED/" /etc/nginx/nginx.conf
else
    echo "No hash-authenticated path configured"
    # Remove the placeholder
    sed -i '/HASH_AUTH_PATH_BLOCK_PLACEHOLDER/d' /etc/nginx/nginx.conf
fi

# Handle subdomain hash extraction and dual routing
if [ "$SUBDOMAIN_HASH_ENABLED" = "true" ] && [ -n "$BACKEND_HASH" ]; then
    echo "Configuring subdomain hash extraction..."

    # Add map directive for subdomain hash extraction
    SUBDOMAIN_MAP="
    # Extract hash from subdomain using configured pattern
    map \$host \$subdomain_hash {
        default \"\";
        ~$SUBDOMAIN_PATTERN \$1;
    }"

    SUBDOMAIN_MAP_ESCAPED=$(echo "$SUBDOMAIN_MAP" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\$/\\$/g' | sed 's/\//\\\//g')
    sed -i "s/SUBDOMAIN_HASH_MAP_PLACEHOLDER/$SUBDOMAIN_MAP_ESCAPED/" /etc/nginx/nginx.conf

    # Add dual routing logic if secondary backend is configured
    if [ -n "$SECONDARY_BACKEND_HOST" ] && [ -n "$SECONDARY_BACKEND_PORT" ]; then
        echo "Configuring dual backend routing..."

        # Add internal proxy locations before main location
        DUAL_ROUTING_BLOCK="
        # Internal proxy to primary backend
        location /primary_backend_proxy {
            internal;
            rewrite ^/primary_backend_proxy(.*)\$ \$1 break;
            proxy_pass http://${BACKEND_HOST}:${BACKEND_PORT};
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host \$host;
            proxy_cache_bypass \$http_upgrade;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

            # Increase timeouts for video streaming/transcoding operations
            proxy_connect_timeout 300s;
            proxy_send_timeout 300s;
            proxy_read_timeout 300s;
            send_timeout 300s;
        }

        # Internal proxy to secondary backend
        location /secondary_backend_proxy {
            internal;
            rewrite ^/secondary_backend_proxy(.*)\$ \$1 break;
            proxy_pass http://${SECONDARY_BACKEND_HOST}:${SECONDARY_BACKEND_PORT};
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host \$host;
            proxy_cache_bypass \$http_upgrade;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        }
"

        # Only insert if primary_backend_proxy doesn't already exist
        if ! grep -q "location /primary_backend_proxy" /etc/nginx/nginx.conf; then
            DUAL_ROUTING_ESCAPED=$(echo "$DUAL_ROUTING_BLOCK" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\$/\\$/g' | sed 's/\//\\\//g')
            sed -i "0,/# Main location/s//$DUAL_ROUTING_ESCAPED\\n        &/" /etc/nginx/nginx.conf
        else
            echo "primary_backend_proxy location already exists, skipping insertion"
        fi

        # Add session establishment support for hash-based auth
        # Browser requests with ?hash= need to establish a session first
        if ! grep -q "establish-session" /etc/nginx/nginx.conf; then
            # Insert after the /nhl-auth/ location block (after its closing brace)
            # Find the /nhl-auth/ block and insert the new block after it
            sed -i '/location \/nhl-auth\/ {/,/^        }/ {
                /^        }/a\
\
        location /nhl-auth/establish-session {\
            proxy_pass http://127.0.0.1:9999/nhl-auth/establish-session;\
            proxy_http_version 1.1;\
            proxy_set_header Host $host;\
            proxy_set_header X-Real-IP $remote_addr;\
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\
            proxy_set_header Cookie $http_cookie;\
        }
            }' /etc/nginx/nginx.conf
        fi

        # Modify AUTH_CHECK_BLOCK to include routing logic
        # Use shortened hash for subdomain comparison (DNS label limits)
        ROUTING_LOGIC="
            # Check if subdomain hash matches (routes to primary backend)
            if (\$subdomain_hash = \"$SUBDOMAIN_HASH_SHORT\") {
                rewrite ^ /primary_backend_proxy\$uri last;
            }

            # If subdomain hash is present but doesn't match, BLOCK (not authenticated)
            set \$block 0;
            if (\$subdomain_hash != \"\") {
                set \$block 1;
            }
            if (\$block = 1) {
                return 403;
            }

            # Browser requests with ?hash= redirect to establish session
            set \$need_session 0;
            if (\$arg_hash != \"\") {
                set \$need_session 1;
            }
            if (\$http_accept ~* \"text/html\") {
                set \$need_session \${need_session}1;
            }
            if (\$need_session = 11) {
                return 307 /nhl-auth/establish-session?hash=\$arg_hash&return_to=\$uri;
            }

            # Only if no subdomain hash: use normal auth for secondary backend
            auth_request /internal-auth-check;
            error_page 401 = @auth_failed_login;

            # If auth succeeds, proxy directly to secondary backend (no rewrite)
            proxy_pass http://${SECONDARY_BACKEND_HOST}:${SECONDARY_BACKEND_PORT};
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host \$host;
            proxy_cache_bypass \$http_upgrade;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;"

        AUTH_CHECK_BLOCK="$ROUTING_LOGIC"

        # Add auth failure handler (only if not already present)
        if ! grep -q "location @auth_failed_login" /etc/nginx/nginx.conf; then
            sed -i 's|location / {|location @auth_failed_login {\
            return 302 /login?redirect=$request_uri;\
        }\
\
        location / {|' /etc/nginx/nginx.conf
        fi

        # Remove the backend proxy block placeholder since routing is handled by internal locations
        sed -i '/BACKEND_PROXY_BLOCK_PLACEHOLDER/d' /etc/nginx/nginx.conf
    fi
else
    # Remove placeholder if subdomain hash not enabled
    sed -i '/SUBDOMAIN_HASH_MAP_PLACEHOLDER/d' /etc/nginx/nginx.conf
fi

# Apply authentication block to nginx configuration
AUTH_CHECK_ESCAPED=$(echo "$AUTH_CHECK_BLOCK" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\$/\\$/g' | sed 's/\//\\\//g' | sed 's/&/\\&/g')
sed -i "s/AUTH_CHECK_BLOCK_PLACEHOLDER/$AUTH_CHECK_ESCAPED/" /etc/nginx/nginx.conf

# Apply backend proxy block if not using dual routing
if grep -q "BACKEND_PROXY_BLOCK_PLACEHOLDER" /etc/nginx/nginx.conf; then
    echo "Adding default backend proxy block"
    BACKEND_PROXY_BLOCK="            proxy_pass http://${BACKEND_HOST}:${BACKEND_PORT};
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection \"upgrade\";
            proxy_set_header Cookie \$http_cookie;"

    BACKEND_PROXY_ESCAPED=$(echo "$BACKEND_PROXY_BLOCK" | sed ':a;N;$!ba;s/\n/\\n/g' | sed 's/\$/\\$/g' | sed 's/\//\\\//g')
    sed -i "s/BACKEND_PROXY_BLOCK_PLACEHOLDER/$BACKEND_PROXY_ESCAPED/" /etc/nginx/nginx.conf
fi

echo "========================================="
echo "Final nginx configuration:"
echo "========================================="
cat /etc/nginx/nginx.conf
echo "========================================="

# Start nginx
echo "Starting nginx..."
exec nginx -g "daemon off;"

