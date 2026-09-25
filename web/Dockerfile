FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Unprivileged nginx: runs as a non-root user and listens on 8080/8443.
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY nginx-https.conf /etc/nginx/templates-https/default.conf

EXPOSE 8080 8443
CMD ["nginx", "-g", "daemon off;"]
