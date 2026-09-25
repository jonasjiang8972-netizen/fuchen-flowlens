FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Unprivileged nginx: runs as a non-root user and listens on 8080/8443.
FROM nginxinc/nginx-unprivileged:1.27-alpine
ARG VERSION=dev
LABEL org.opencontainers.image.title="flowlens-web" \
      org.opencontainers.image.description="FlowLens web console" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=builder /app/dist /usr/share/nginx/html
COPY security-headers.conf /etc/nginx/snippets/security-headers.conf
# Owned by the nginx user (101) so 40-flowlens-https.sh can switch it to HTTPS.
COPY --chown=101:0 nginx.conf /etc/nginx/conf.d/default.conf
COPY nginx-https.conf /etc/nginx/templates-https/default.conf
# FLOWLENS_WEB_HTTPS=true switches to the HTTPS server config at start-up
# (certificate and key mounted at /etc/nginx/certs/).
COPY docker-entrypoint.d/40-flowlens-https.sh /docker-entrypoint.d/40-flowlens-https.sh

EXPOSE 8080 8443
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
CMD ["nginx", "-g", "daemon off;"]
