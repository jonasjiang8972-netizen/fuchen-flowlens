#!/bin/sh
# Run by the nginx image entrypoint before nginx starts.
set -e
case "${FLOWLENS_WEB_HTTPS:-false}" in
  true|1|yes) ;;
  *) exit 0 ;;
esac
for f in /etc/nginx/certs/server.crt /etc/nginx/certs/server.key; do
  if [ ! -r "$f" ]; then
    echo "40-flowlens-https: FLOWLENS_WEB_HTTPS=true but $f is missing or unreadable" >&2
    exit 1
  fi
done
# The redirect target is the port clients reach from outside the container.
port="${FLOWLENS_HTTPS_PUBLIC_PORT:-8443}"
case "$port" in
  *[!0-9]*|"") echo "40-flowlens-https: invalid FLOWLENS_HTTPS_PUBLIC_PORT=$port" >&2; exit 1 ;;
  443) target='https://$host$request_uri' ;;
  *) target="https://\$host:${port}\$request_uri" ;;
esac
sed "s|https://\$host:8443\$request_uri|${target}|" \
  /etc/nginx/templates-https/default.conf > /etc/nginx/conf.d/default.conf
echo "40-flowlens-https: HTTPS enabled, HTTP redirects to port ${port}"
