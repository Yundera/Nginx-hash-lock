#!/bin/sh

# Simple replacement of placeholders
sed -i "s/BACKEND_HOST_PLACEHOLDER/$BACKEND_HOST/g" /etc/nginx/nginx.conf
sed -i "s/BACKEND_PORT_PLACEHOLDER/$BACKEND_PORT/g" /etc/nginx/nginx.conf
sed -i "s/LISTEN_PORT_PLACEHOLDER/$LISTEN_PORT/g" /etc/nginx/nginx.conf
sed -i "s/AUTH_HASH_PLACEHOLDER/$AUTH_HASH/g" /etc/nginx/nginx.conf

# Start NGINX
exec nginx -g "daemon off;"
