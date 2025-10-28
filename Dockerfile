FROM nginx:latest

# Install Node.js and npm
RUN apt-get update && \
    apt-get install -y curl && \
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create required nginx cache directories
RUN mkdir -p /var/cache/nginx/{client_temp,proxy_temp,fastcgi_temp,uwsgi_temp,scgi_temp} && \
    chown -R nginx:nginx /var/cache/nginx && \
    chmod -R 755 /var/cache/nginx

# Force cache invalidation for configuration files
ARG CACHE_BUST=1
RUN echo "Build timestamp: $(date)" > /build-info

# Copy nginx configuration files
COPY nginx.conf /etc/nginx/nginx.conf
COPY 403.html /usr/share/nginx/html/403.html
COPY login.html /usr/share/nginx/html/login.html

# Copy and install auth service
COPY auth-service /app/auth-service
WORKDIR /app/auth-service
RUN npm install --production

# Copy entrypoint, dynamic auth checker, and auto-add hash scripts
COPY entrypoint.sh /entrypoint.sh
COPY dynamic-auth-checker.sh /dynamic-auth-checker.sh
COPY auto-add-hash.sh /auto-add-hash.sh
RUN chmod +x /entrypoint.sh /dynamic-auth-checker.sh /auto-add-hash.sh

WORKDIR /

ENTRYPOINT ["/entrypoint.sh"]

