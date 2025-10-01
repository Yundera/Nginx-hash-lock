FROM nginx:latest

# Create required nginx cache directories
RUN mkdir -p /var/cache/nginx/{client_temp,proxy_temp,fastcgi_temp,uwsgi_temp,scgi_temp} && \
    chown -R nginx:nginx /var/cache/nginx && \
    chmod -R 755 /var/cache/nginx

# Force cache invalidation for configuration files
ARG CACHE_BUST=1
RUN echo "Build timestamp: $(date)" > /build-info

COPY nginx.conf /etc/nginx/nginx.conf
COPY 403.html /usr/share/nginx/html/403.html
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

