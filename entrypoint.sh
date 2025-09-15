#!/bin/sh

echo "Starting nginxhashlock..."

# Copy template to working config
cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup

# Replace basic placeholders
sed -i "s/AUTH_HASH_PLACEHOLDER/$AUTH_HASH/g" /etc/nginx/nginx.conf
sed -i "s/BACKEND_HOST_PLACEHOLDER/$BACKEND_HOST/g" /etc/nginx/nginx.conf
sed -i "s/BACKEND_PORT_PLACEHOLDER/$BACKEND_PORT/g" /etc/nginx/nginx.conf
sed -i "s/LISTEN_PORT_PLACEHOLDER/$LISTEN_PORT/g" /etc/nginx/nginx.conf

# Handle ALLOWED_EXTENSIONS
if [ -n "$ALLOWED_EXTENSIONS" ]; then
    echo "Configuring allowed extensions: $ALLOWED_EXTENSIONS"
    # Convert comma-separated to regex format: js,css,png -> (js|css|png)
    EXTENSIONS_REGEX=$(echo "$ALLOWED_EXTENSIONS" | sed 's/,/|/g')
    EXTENSIONS_REGEX="($EXTENSIONS_REGEX)"
    echo "Extensions regex: $EXTENSIONS_REGEX"
    # Escape forward slashes and pipes for sed
    EXTENSIONS_ESCAPED=$(echo "$EXTENSIONS_REGEX" | sed 's/[|()]/\\&/g')
    sed -i "s/ALLOWED_EXTENSIONS_PLACEHOLDER/$EXTENSIONS_ESCAPED/g" /etc/nginx/nginx.conf
else
    echo "No allowed extensions configured - removing extensions block"
    # Remove the entire extensions location block if no extensions specified
    sed -i '/# Allow specific file extensions/,/^        }/d' /etc/nginx/nginx.conf
fi

# Handle ALLOWED_PATHS
if [ -n "$ALLOWED_PATHS" ]; then
    echo "Configuring allowed paths: $ALLOWED_PATHS"
    # Convert comma-separated to regex format: login,api/health -> (login|api/health)
    PATHS_REGEX=$(echo "$ALLOWED_PATHS" | sed 's/,/|/g')
    PATHS_REGEX="($PATHS_REGEX)"
    echo "Paths regex: $PATHS_REGEX"
    # Escape forward slashes and pipes for sed
    PATHS_ESCAPED=$(echo "$PATHS_REGEX" | sed 's/[|()\/]/\\&/g')
    sed -i "s/ALLOWED_PATHS_PLACEHOLDER/$PATHS_ESCAPED/g" /etc/nginx/nginx.conf
else
    echo "No allowed paths configured - removing paths block"
    # Remove the entire paths location block if no paths specified
    sed -i '/# Allow specific paths/,/^        }/d' /etc/nginx/nginx.conf
fi

echo "Final nginx configuration:"
cat /etc/nginx/nginx.conf

# Start nginx
echo "Starting nginx..."
exec nginx -g "daemon off;"
