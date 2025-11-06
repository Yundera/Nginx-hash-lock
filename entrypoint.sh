#!/bin/sh

echo "Starting nginxhashlock..."

# Copy template to working config
cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup

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

    # Wait for auth service to be ready
    sleep 2
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
    # Normalize paths: strip leading/trailing slashes from each comma-separated value
    # This handles: "/guild,/auth" -> "guild,auth"
    #              "login,/api/health/,/guild" -> "login,api/health,guild"
    #              "page/\",/something/else/" -> "page/\",something/else"
    NORMALIZED_PATHS=$(echo "$ALLOWED_PATHS" | \
        sed 's/^\/\+//;s/\/\+$//;s/,\/\+/,/g;s/\/\+,/,/g' | \
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

# Handle DYNAMIC_PATHS (optional - for temporary path allowlisting)
if [ -n "$DYNAMIC_PATHS_FILE" ]; then
    echo "Configuring dynamic paths with file: $DYNAMIC_PATHS_FILE"

    # Create the directory if it doesn't exist
    DYNAMIC_DIR=$(dirname "$DYNAMIC_PATHS_FILE")
    mkdir -p "$DYNAMIC_DIR"

    # Create empty file if it doesn't exist
    touch "$DYNAMIC_PATHS_FILE"

    # Default TTL is 5 minutes if not specified
    export DYNAMIC_PATHS_TTL="${DYNAMIC_PATHS_TTL:-300}"

    # Start the dynamic auth checker service
    echo "Starting dynamic auth checker service..."
    # Fix any CRLF line endings
    dos2unix /dynamic-auth-checker.sh 2>/dev/null || sed -i 's/\r$//' /dynamic-auth-checker.sh
    chmod +x /dynamic-auth-checker.sh
    sh /dynamic-auth-checker.sh > /var/log/dynamic-auth.log 2>&1 &
    DYNAMIC_AUTH_PID=$!
    echo "Dynamic auth checker started with PID: $DYNAMIC_AUTH_PID"

    # Start the auto-add hash service
    echo "Starting auto-add hash service..."
    dos2unix /auto-add-hash.sh 2>/dev/null || sed -i 's/\r$//' /auto-add-hash.sh
    chmod +x /auto-add-hash.sh
    sh /auto-add-hash.sh > /var/log/auto-add-hash.log 2>&1 &
    AUTO_ADD_PID=$!
    echo "Auto-add hash service started with PID: $AUTO_ADD_PID"

    sleep 1

    # Add geo block to detect Docker internal network requests
    echo "Adding Docker internal network detection..."
    if ! grep -q "geo \$docker_internal" /etc/nginx/nginx.conf; then
        sed -i '/scgi_temp_path/a\
\n    # Detect requests from Docker internal network (container-to-container)\
    geo $docker_internal {\
        default 0;\
        127.0.0.1 1;           # Localhost\
        10.0.0.0/8 1;          # Docker network range\
        172.16.0.0/12 1;       # Docker network range\
        192.168.0.0/16 1;      # Docker network range\
    }' /etc/nginx/nginx.conf
    fi

    # Create dynamic paths config file
    cat > /tmp/dynamic_paths.conf <<'EOF'
        # Dynamic path checking for temporary allowlist
        location ~ "^/[a-f0-9]{40}" {
            # Internal Docker requests bypass auth (Stremio server probing itself)
            # External requests go through auth
            auth_request /internal-dynamic-auth;
            error_page 401 = @auth_failed_dynamic;

            proxy_pass http://BACKEND_HOST_PLACEHOLDER:BACKEND_PORT_PLACEHOLDER;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }

        location @auth_failed_dynamic {
            return 302 /login?redirect=$request_uri;
        }

        location = /internal-dynamic-auth {
            internal;
            proxy_pass http://127.0.0.1:9997;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Original-URI $request_uri;
            proxy_set_header Cookie $http_cookie;
            proxy_set_header Referer $http_referer;
        }

        location = /internal-dynamic-check {
            internal;
            proxy_pass http://127.0.0.1:9998;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Original-URI $request_uri;
        }

        location @require_auth {
            # Fall back to main auth flow
            return 418;
        }
EOF

    # Replace placeholders in dynamic paths config
    sed -i "s/BACKEND_HOST_PLACEHOLDER/$BACKEND_HOST/g" /tmp/dynamic_paths.conf
    sed -i "s/BACKEND_PORT_PLACEHOLDER/$BACKEND_PORT/g" /tmp/dynamic_paths.conf

    # Insert the include directive before main location (only if not already present)
    if ! grep -q "include /tmp/dynamic_paths.conf" /etc/nginx/nginx.conf; then
        sed -i '0,/# Main location - authentication logic/s//        include \/tmp\/dynamic_paths.conf;\n&/' /etc/nginx/nginx.conf
    fi

    # Add session establishment logic (only when auth service is running AND we need sessions)
    # This is needed for "both" mode or when hash+dynamic paths (for auto-add service)
    if [ "$AUTH_MODE" != "hash" ] && ! grep -q "/nhl-auth/establish-session" /etc/nginx/nginx.conf; then
        # Add the map for session checking
        sed -i '/scgi_temp_path/a\
\n    # Redirect to establish-session when hash parameter is present\
    map $arg_hash $need_session {\
        default 0;\
        "~.+" 1;\
    }' /etc/nginx/nginx.conf

        # Add the establish-session endpoint
        sed -i '/location \/nhl-auth\/ {/a\
        location /nhl-auth/establish-session {\
            proxy_pass http://127.0.0.1:9999/nhl-auth/establish-session;\
            proxy_http_version 1.1;\
            proxy_set_header Host $host;\
            proxy_set_header X-Real-IP $remote_addr;\
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\
            proxy_set_header Cookie $http_cookie;\
        }\
' /etc/nginx/nginx.conf

        # Add the redirect logic in main location
        sed -i '/AUTH_CHECK_BLOCK_PLACEHOLDER/a\
            # If hash parameter is present and no session cookie, redirect to establish session first\
            if ($need_session = 1) {\
                return 307 /nhl-auth/establish-session?hash=$arg_hash\&return_to=$request_uri;\
            }' /etc/nginx/nginx.conf
    fi


    echo "Dynamic paths TTL: $DYNAMIC_PATHS_TTL seconds"
else
    echo "No dynamic paths configured"
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

