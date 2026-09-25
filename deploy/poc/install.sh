#!/usr/bin/env bash
# FlowLens POC installer.
#
# Works from either
#   - the offline package (flowlens-poc-<version>-<arch>.tar.gz): loads the
#     bundled images from images/, or
#   - a source checkout (deploy/poc/): builds the images locally.
#
# Re-running is safe: an existing .env (secrets, ports) is kept.
# Needs bash 4.2+ (CentOS 7 and later).
set -euo pipefail

cd "$(dirname "$0")"

HTTPS=false
CERT=""
KEY=""
HOSTS=""
SEED_DEMO=""
PROFILES=()
HTTP_PORT=""
HTTPS_PORT=""
BUILD=auto
ASSUME_YES=false

usage() {
  cat <<'USAGE'
用法: ./install.sh [选项]

  --https               控制台启用 HTTPS（未指定 --cert/--key 时自动生成自签名证书）
  --cert 文件 --key 文件
                        使用指定的证书和私钥（PEM 格式）
  --host 域名或IP       自签名证书包含的域名/IP，可重复（默认：本机主机名和 IP）
  --http-port 端口      HTTP 端口（默认 8080）
  --https-port 端口     HTTPS 端口（默认 8443）
  --with-agent          同时启动 Agent，采集 FLOWLENS_GATEWAY_LOG_DIR 下的网关日志
  --demo                启动 Agent 和演示流量生成器（无需真实网关）
  --seed-demo           向空数据库写入示例资产、告警和采集器
  --build               即使镜像已存在也从源码重新构建
  --no-build            不构建，镜像必须已加载或已存在
  -y, --yes             不询问确认
  -h, --help            显示帮助
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --https) HTTPS=true ;;
    --cert) CERT="${2:?--cert 需要文件参数}"; HTTPS=true; shift ;;
    --key) KEY="${2:?--key 需要文件参数}"; HTTPS=true; shift ;;
    --host) HOSTS="$HOSTS ${2:?--host 需要参数}"; shift ;;
    --http-port) HTTP_PORT="${2:?--http-port 需要参数}"; shift ;;
    --https-port) HTTPS_PORT="${2:?--https-port 需要参数}"; shift ;;
    --with-agent) PROFILES+=(agent) ;;
    --demo) PROFILES+=(demo) ;;
    --seed-demo) SEED_DEMO=true ;;
    --build) BUILD=always ;;
    --no-build) BUILD=never ;;
    -y|--yes) ASSUME_YES=true ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知选项: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

info() { printf '\033[1;34m[flowlens]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[flowlens]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[flowlens]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- version
VERSION=""
if [ -f VERSION ]; then
  VERSION="$(tr -d ' \n' < VERSION)"
elif [ -f ../../pkg/version/version.go ]; then
  VERSION="$(sed -n 's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' ../../pkg/version/version.go)"
fi
[ -n "$VERSION" ] || die "无法确定 FlowLens 版本（缺少 VERSION 文件）。"

# ---------------------------------------------------------------- prerequisites
command -v docker >/dev/null 2>&1 || die "未安装 Docker，请先安装 Docker Engine 20.10 或更高版本。"
docker info >/dev/null 2>&1 || die "无法连接 Docker 服务。请启动 Docker，或以 root / docker 组成员身份运行。"
docker compose version >/dev/null 2>&1 || die "需要 Docker Compose v2（docker compose 插件）。"

COMPOSE=(docker compose --env-file .env -f docker-compose.yaml)

mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
if [ "${mem_kb:-0}" -gt 0 ] && [ "$mem_kb" -lt 3500000 ]; then
  warn "内存不足 4GB，运行可能较慢。"
fi
docker_root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)"
free_kb="$(df -Pk "$docker_root" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)"
if [ "${free_kb:-0}" -gt 0 ] && [ "$free_kb" -lt 10485760 ]; then
  warn "$docker_root 可用空间不足 10GB。"
fi

rand_hex() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$1"
  else
    od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'
  fi
}

set_env() { # set_env KEY VALUE
  local k="$1" v="$2" tmp
  if grep -q "^${k}=" .env; then
    tmp="$(mktemp)"
    awk -v k="$k" -v v="$v" 'index($0, k "=") == 1 {print k "=" v; next} {print}' .env > "$tmp"
    cat "$tmp" > .env
    rm -f "$tmp"
  else
    printf '%s=%s\n' "$k" "$v" >> .env
  fi
}

get_env() { sed -n "s/^$1=//p" .env | tail -n1; }

check_port() {
  case "$1" in
    ''|*[!0-9]*) die "端口无效: $1" ;;
  esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ] || die "端口无效: $1"
}

# ---------------------------------------------------------------- .env
umask 077
if [ ! -f .env ]; then
  info "生成 .env（随机生成数据库口令、Agent 令牌和初始管理员口令）"
  cp .env.example .env
  set_env POSTGRES_PASSWORD "$(rand_hex 24)"
  set_env FLOWLENS_AGENT_TOKEN "$(rand_hex 32)"
  # Meets the password policy (upper, lower, digit, symbol); every bootstrap
  # account must change it at first login.
  set_env FLOWLENS_ADMIN_PASSWORD "Fl-$(rand_hex 6)-X9"
else
  info "保留已有的 .env"
fi
chmod 600 .env
set_env FLOWLENS_VERSION "$VERSION"
if [ -n "$HTTP_PORT" ]; then check_port "$HTTP_PORT"; set_env FLOWLENS_HTTP_PORT "$HTTP_PORT"; fi
if [ -n "$HTTPS_PORT" ]; then check_port "$HTTPS_PORT"; set_env FLOWLENS_HTTPS_PORT "$HTTPS_PORT"; fi
if [ -n "$SEED_DEMO" ]; then set_env FLOWLENS_SEED_DEMO true; fi

pg_pw="$(get_env POSTGRES_PASSWORD)"
case "$pg_pw" in
  ''|*[!A-Za-z0-9._~-]*) die ".env 中的 POSTGRES_PASSWORD 不能为空，且只能包含字母、数字和 . _ ~ -" ;;
esac
[ -n "$(get_env FLOWLENS_AGENT_TOKEN)" ] || die ".env 中的 FLOWLENS_AGENT_TOKEN 为空。"

# ---------------------------------------------------------------- HTTPS
mkdir -p certs
chmod 755 certs
if [ "$HTTPS" = true ]; then
  if [ -n "$CERT" ] || [ -n "$KEY" ]; then
    { [ -r "$CERT" ] && [ -r "$KEY" ]; } || die "--cert 和 --key 必须同时指定且文件可读。"
    cp "$CERT" certs/server.crt
    cp "$KEY" certs/server.key
    info "已安装指定的证书"
  elif [ ! -s certs/server.crt ] || [ ! -s certs/server.key ]; then
    command -v openssl >/dev/null 2>&1 || die "生成自签名证书需要 openssl（或使用 --cert/--key 指定证书）。"
    if [ -z "${HOSTS// /}" ]; then
      HOSTS="$(hostname) localhost 127.0.0.1 $(hostname -I 2>/dev/null || true)"
    fi
    san=""
    cn=""
    for h in $HOSTS; do
      [ -n "$cn" ] || cn="$h"
      if printf '%s' "$h" | grep -Eq '^[0-9.]+$|:'; then
        san="${san:+$san,}IP:$h"
      else
        san="${san:+$san,}DNS:$h"
      fi
    done
    info "生成自签名证书，包含: $HOSTS"
    openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
      -keyout certs/server.key -out certs/server.crt \
      -subj "/O=FlowLens POC/CN=$cn" \
      -addext "subjectAltName=$san" >/dev/null 2>&1 \
      || die "证书生成失败（需要 OpenSSL 1.1.1 或更高版本）。"
  fi
  chmod 644 certs/server.crt
  # nginx in the web container runs as uid 101.
  if [ "$(id -u)" = 0 ]; then
    chown 101:101 certs/server.key
    chmod 600 certs/server.key
  else
    warn "非 root 运行：certs/server.key 已设为所有用户可读，以便容器读取。"
    chmod 644 certs/server.key
  fi
  set_env FLOWLENS_WEB_HTTPS true
  set_env FLOWLENS_COOKIE_SECURE true
fi

# ---------------------------------------------------------------- images
IMAGES=("flowlens-platform:$VERSION" "flowlens-web:$VERSION" "flowlens-agent:$VERSION")
have_images() {
  local img
  for img in "${IMAGES[@]}"; do
    docker image inspect "$img" >/dev/null 2>&1 || return 1
  done
}

bundle="$(ls images/flowlens-images-"$VERSION"*.tar* 2>/dev/null | head -n1 || true)"
if [ -n "$bundle" ] && [ "$BUILD" != always ]; then
  if [ -f SHA256SUMS ] && command -v sha256sum >/dev/null 2>&1; then
    info "校验镜像包"
    grep " images/" SHA256SUMS | sha256sum -c --quiet - || die "镜像包校验失败，安装包可能已损坏。"
  fi
  info "从 $bundle 加载镜像"
  case "$bundle" in
    *.gz) gzip -dc "$bundle" | docker load ;;
    *) docker load -i "$bundle" ;;
  esac
elif [ "$BUILD" = always ] || { [ "$BUILD" = auto ] && ! have_images; }; then
  { [ -f docker-compose.build.yaml ] && [ -f ../../platform/Dockerfile ]; } \
    || die "未找到镜像 flowlens-*:$VERSION，且当前目录不是源码目录，无法构建。请使用离线安装包。"
  info "从源码构建镜像 flowlens-*:$VERSION（需要几分钟）"
  "${COMPOSE[@]}" -f docker-compose.build.yaml build platform web agent
fi
have_images || die "缺少镜像 flowlens-*:$VERSION。"

pg_image="$(get_env FLOWLENS_POSTGRES_IMAGE)"
pg_image="${pg_image:-postgres:16-alpine}"
if ! docker image inspect "$pg_image" >/dev/null 2>&1; then
  info "拉取 $pg_image"
  docker pull "$pg_image" || die "无法拉取 $pg_image。请使用离线安装包，或手动导入该镜像。"
fi

# ---------------------------------------------------------------- start
# Profiles chosen at install time are remembered for flowlens-ctl.sh.
if [ "${#PROFILES[@]}" -gt 0 ]; then
  printf '%s\n' "${PROFILES[@]}" | sort -u > .profiles
elif [ -f .profiles ]; then
  while read -r p; do
    if [ -n "$p" ]; then PROFILES+=("$p"); fi
  done < .profiles
fi
profile_args=()
if [ "${#PROFILES[@]}" -gt 0 ]; then
  for p in "${PROFILES[@]}"; do profile_args+=(--profile "$p"); done
  if [[ " ${PROFILES[*]} " == *" agent "* ]] && [[ " ${PROFILES[*]} " != *" demo "* ]] \
      && [ -z "$(get_env FLOWLENS_GATEWAY_LOG_DIR)" ]; then
    warn "--with-agent：.env 中 FLOWLENS_GATEWAY_LOG_DIR 为空，Agent 会一直等待日志。请设为网关 JSON 访问日志所在目录。"
  fi
fi

if [ "$ASSUME_YES" != true ] && [ -t 0 ]; then
  read -r -p "现在启动 FlowLens $VERSION？[Y/n] " ans
  case "$ans" in [nN]*) info "未启动。稍后可执行 ./flowlens-ctl.sh start"; exit 0 ;; esac
fi

info "启动 FlowLens $VERSION"
"${COMPOSE[@]}" ${profile_args[@]+"${profile_args[@]}"} up -d --no-build

info "等待平台和控制台就绪"
deadline=$(( $(date +%s) + 240 ))
while :; do
  web_id="$("${COMPOSE[@]}" ps -q web 2>/dev/null || true)"
  web_state="$(docker inspect -f '{{.State.Health.Status}}' "$web_id" 2>/dev/null || echo starting)"
  [ "$web_state" = healthy ] && break
  if [ "$(date +%s)" -gt "$deadline" ]; then
    "${COMPOSE[@]}" ps
    die "服务未能按时就绪，请查看日志: ./flowlens-ctl.sh logs platform"
  fi
  sleep 3
done

# ---------------------------------------------------------------- summary
addr="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
addr="${addr:-localhost}"
if [ "$(get_env FLOWLENS_WEB_HTTPS)" = true ]; then
  url="https://$addr:$(get_env FLOWLENS_HTTPS_PORT)"
else
  url="http://$addr:$(get_env FLOWLENS_HTTP_PORT)"
fi
admin_pw="$(get_env FLOWLENS_ADMIN_PASSWORD)"

echo
echo "  FlowLens $VERSION 已启动"
echo
echo "  控制台地址    $url"
echo "  内置账号      sysadmin    系统管理员  -> 系统管理后台"
echo "                auditadmin  审计管理员  -> 系统管理后台"
echo "                secadmin    安全管理员  -> API 安全管理平台"
if [ -n "$admin_pw" ]; then
  echo "  初始口令      $admin_pw   （各账号首次登录须修改口令）"
else
  echo "  初始口令      随机生成，仅在平台日志中打印一次: ./flowlens-ctl.sh logs platform"
fi
echo "  Agent 令牌    见 .env 中的 FLOWLENS_AGENT_TOKEN"
echo "  运维命令      ./flowlens-ctl.sh status | logs | backup | restore | upgrade | uninstall"
echo
echo "  初始口令只在数据库为空时生效，之后修改 FLOWLENS_ADMIN_PASSWORD 无效。"
echo "  .env 含有密钥，请妥善保管。"
echo
