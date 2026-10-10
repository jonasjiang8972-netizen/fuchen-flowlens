#!/bin/sh
# Writes sample API gateway access-log lines (JSON, Kong-style fields, one
# per line) for the POC agent. Rate: DEMO_RATE requests per second of
# ordinary traffic, plus attack scenarios so each detection has something
# to show:
#   - every second: account u-scraper walks /api/v1/users/<id> in order
#     (object traversal, and a scripted 1 s rhythm)
#   - every 30 s: an SSRF probe at the cloud metadata address
#   - every 45 s: an external address calls a management endpoint
#   - every 60 s: an export call with ID card and phone parameters
#   - every 2 min: 25 failed logins from one address (brute force)
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

NOW=""
line() { # line METHOD URI STATUS CLIENT_IP SERVICE [USER]
  if [ -n "${6:-}" ]; then
    headers=$(printf ',"headers":{"x-user-id":"%s","user-agent":"demo-client/1.0"}' "$6")
  else
    headers=',"headers":{"user-agent":"demo-client/1.0"}'
  fi
  printf '{"time":"%s","request":{"method":"%s","uri":"%s","host":"demo.flowlens.local"%s},"response":{"status":%s},"client_ip":"%s","upstream_addr":"10.30.0.%s:8080","request_length":%s,"bytes_sent":%s,"request_time":0.%03d,"route":{"name":"%s"}}\n' \
    "$NOW" "$1" "$2" "$headers" "$3" "$4" "$(( $(rand 8) + 1 ))" "$(( $(rand 900) + 100 ))" "$(( $(rand 20000) + 200 ))" "$(rand 400)" "$5" >> "$LOG"
}

echo "demo-traffic: writing ${RATE} req/s to ${LOG}, with periodic attack scenarios"
tick=0
scrape=1000
while :; do
  tick=$((tick + 1))
  NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  scrape=$((scrape + 1))
  line GET "/api/v1/users/${scrape}" 200 10.20.9.9 user-svc u-scraper
  if [ $((tick % 30)) -eq 0 ]; then
    line GET "/api/v1/preview?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F" 200 198.51.100.23 content-svc
  fi
  if [ $((tick % 45)) -eq 20 ]; then
    line GET /api/v1/admin/users 200 198.51.100.77 admin-svc
  fi
  if [ $((tick % 60)) -eq 40 ]; then
    line GET "/api/v1/customers/export?id_card=110101********4514&phone=138****8000&format=csv" 200 10.20.5.5 customer-svc u-analyst
  fi
  if [ $((tick % 120)) -eq 60 ]; then
    j=0
    while [ "$j" -lt 25 ]; do
      line POST /api/v1/auth/login 401 203.0.113.66 auth-svc
      j=$((j + 1))
    done
  fi

  i=0
  while [ "$i" -lt "$RATE" ]; do
    i=$((i + 1))
    ip="10.20.$(rand 4).$(( $(rand 200) + 10 ))"
    id=$(( $(rand 5000) + 1 ))
    case $(rand 20) in
      0|1|2|3|4|5) m=GET;    u="/api/v1/users/${id}";            svc=user-svc ;;
      6|7|8)       m=GET;    u="/api/v1/orders?page=$(rand 50)"; svc=order-svc ;;
      9|10)        m=POST;   u="/api/v1/orders";                 svc=order-svc ;;
      11|12)       m=GET;    u="/api/v1/accounts/${id}/balance"; svc=account-svc ;;
      13)          m=POST;   u="/api/v1/auth/login";             svc=auth-svc ;;
      14)          m=PUT;    u="/api/v1/users/${id}/profile";    svc=user-svc ;;
      15)          m=DELETE; u="/api/v1/orders/${id}";           svc=order-svc ;;
      16)          m=GET;    u="/internal/debug/vars";           svc=user-svc ;;
      *)           m=GET;    u="/api/v1/products/$(rand 300)";   svc=product-svc ;;
    esac
    st=$(pick 200 200 200 200 200 200 200 200 200 200 201 204 304 400 404 500)
    # Most calls carry the user the gateway authenticated; some are anonymous.
    if [ "$(rand 10)" -lt 7 ]; then
      line "$m" "$u" "$st" "$ip" "$svc" "u-$(( $(rand 200) + 1 ))"
    else
      line "$m" "$u" "$st" "$ip" "$svc"
    fi
  done
  # Keep the demo log from growing without bound.
  if [ "$(wc -c < "$LOG")" -gt 104857600 ]; then
    : > "$LOG"
  fi
  sleep 1
done
