#!/bin/sh
# Writes sample API gateway access-log lines (JSON, one per line) for the
# POC agent. Rate: DEMO_RATE requests per second.
set -eu
LOG=/var/log/gateway/access.log
RATE="${DEMO_RATE:-5}"
touch "$LOG"
chmod 0644 "$LOG"

rand() { # rand N -> 0..N-1
  echo $(( $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % $1 ))
}

pick() { # pick word...
  shift "$(rand $#)"
  echo "$1"
}

echo "demo-traffic: writing ${RATE} req/s to ${LOG}"
while :; do
  i=0
  while [ "$i" -lt "$RATE" ]; do
    i=$((i + 1))
    ip="10.20.$(rand 4).$(( $(rand 200) + 10 ))"
    id=$(( $(rand 5000) + 1 ))
    case $(rand 20) in
      0|1|2|3|4|5) m=GET;    u="/api/v1/users/${id}";         svc=user-svc ;;
      6|7|8)       m=GET;    u="/api/v1/orders?page=$(rand 50)"; svc=order-svc ;;
      9|10)        m=POST;   u="/api/v1/orders";              svc=order-svc ;;
      11|12)       m=GET;    u="/api/v1/accounts/${id}/balance"; svc=account-svc ;;
      13)          m=POST;   u="/api/v1/auth/login";          svc=auth-svc ;;
      14)          m=PUT;    u="/api/v1/users/${id}/profile"; svc=user-svc ;;
      15)          m=DELETE; u="/api/v1/orders/${id}";        svc=order-svc ;;
      16)          m=GET;    u="/api/v1/admin/export?all=true"; svc=admin-svc ;;
      17)          m=GET;    u="/internal/debug/vars";        svc=user-svc ;;
      *)           m=GET;    u="/api/v1/products/$(rand 300)"; svc=product-svc ;;
    esac
    st=$(pick 200 200 200 200 200 200 200 201 204 400 401 403 404 500)
    printf '{"request":{"method":"%s","uri":"%s","host":"demo.flowlens.local"},"response":{"status":%s},"client_ip":"%s","upstream_addr":"10.30.0.%s:8080","request_length":%s,"bytes_sent":%s,"request_time":0.%03d,"route":{"name":"%s"}}\n' \
      "$m" "$u" "$st" "$ip" "$(( $(rand 8) + 1 ))" "$(( $(rand 900) + 100 ))" "$(( $(rand 20000) + 200 ))" "$(rand 400)" "$svc" >> "$LOG"
  done
  # Keep the demo log from growing without bound.
  if [ "$(wc -c < "$LOG")" -gt 104857600 ]; then
    : > "$LOG"
  fi
  sleep 1
done
