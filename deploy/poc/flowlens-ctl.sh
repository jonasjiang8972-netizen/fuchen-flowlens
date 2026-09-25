#!/usr/bin/env bash
# FlowLens POC operations: start/stop, status, logs, backup/restore,
# upgrade and uninstall. Run from the installation directory's copy.
set -euo pipefail

cd "$(dirname "$0")"

info() { printf '\033[1;34m[flowlens]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[flowlens]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[flowlens]\033[0m %s\n' "$*" >&2; exit 1; }

[ -f .env ] || die "未找到 .env，请先执行 ./install.sh"
command -v docker >/dev/null 2>&1 || die "未安装 Docker。"

get_env() { sed -n "s/^$1=//p" .env | tail -n1; }

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

COMPOSE=(docker compose --env-file .env -f docker-compose.yaml)
PROFILE_ARGS=()
if [ -f .profiles ]; then
  while read -r p; do
    if [ -n "$p" ]; then PROFILE_ARGS+=(--profile "$p"); fi
  done < .profiles
fi
compose() { "${COMPOSE[@]}" ${PROFILE_ARGS[@]+"${PROFILE_ARGS[@]}"} "$@"; }

usage() {
  cat <<'USAGE'
用法: ./flowlens-ctl.sh <命令> [参数]

  start                 启动全部服务
  stop                  停止全部服务（数据保留）
  restart               重启全部服务（修改 .env 后使用）
  status                查看服务状态和版本
  logs [服务] [-f]      查看日志，服务为 platform / web / postgres / agent
  backup [目录]         备份数据库到 backups/（或指定目录）
  restore <备份文件>    从备份恢复数据库（覆盖现有数据）
  upgrade <安装包>      升级到新版本安装包（.tar.gz），自动先备份
  uninstall [--purge]   停止并删除容器；--purge 同时删除数据库数据
  version               显示当前版本

  restore / uninstall --purge 需要确认，加 -y 跳过确认。
USAGE
}

wait_healthy() {
  local deadline id state
  deadline=$(( $(date +%s) + 240 ))
  while :; do
    id="$(compose ps -q web 2>/dev/null || true)"
    state="$(docker inspect -f '{{.State.Health.Status}}' "$id" 2>/dev/null || echo starting)"
    [ "$state" = healthy ] && return 0
    if [ "$(date +%s)" -gt "$deadline" ]; then
      compose ps
      die "服务未能按时就绪，请查看日志: ./flowlens-ctl.sh logs platform"
    fi
    sleep 3
  done
}

confirm() {
  local ans
  [ "$ASSUME_YES" = true ] && return 0
  if [ -t 0 ]; then
    read -r -p "$1 [y/N] " ans
    case "$ans" in [yY]*) return 0 ;; esac
    return 1
  fi
  die "非交互模式下须加 -y 确认：$1"
}

do_backup() {
  local dir="${1:-backups}" file
  mkdir -p "$dir"
  chmod 700 "$dir"
  compose ps --status running -q postgres | grep -q . || die "数据库未运行，请先 ./flowlens-ctl.sh start"
  file="$dir/flowlens-$(get_env FLOWLENS_VERSION)-$(date +%Y%m%d-%H%M%S).dump"
  info "备份数据库到 $file"
  (umask 077; compose exec -T postgres pg_dump -U flowlens -d flowlens -Fc > "$file")
  [ -s "$file" ] || die "备份失败，文件为空。"
  info "备份完成（$(du -h "$file" | cut -f1)）"
  BACKUP_FILE="$file"
}

do_restore() {
  local file="${1:-}"
  [ -n "$file" ] && [ -s "$file" ] || die "请指定有效的备份文件。"
  confirm "恢复会覆盖当前全部数据（账号、审计日志、策略等），确认继续？" || exit 1
  compose up -d postgres
  local i=0
  until compose exec -T postgres pg_isready -U flowlens -d flowlens >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -lt 60 ] || die "数据库未就绪。"; sleep 2
  done
  info "停止平台"
  compose stop web platform agent 2>/dev/null || compose stop web platform
  info "重建数据库并导入 $file"
  compose exec -T postgres dropdb -U flowlens --if-exists --force flowlens
  compose exec -T postgres createdb -U flowlens -O flowlens flowlens
  compose exec -T postgres pg_restore -U flowlens -d flowlens --no-owner --exit-on-error < "$file"
  info "启动平台"
  compose up -d --no-build
  wait_healthy
  info "恢复完成。建议在系统管理后台执行一次审计日志完整性校验。"
}

do_upgrade() {
  local pkg="${1:-}" new_dir new_version
  [ -n "$pkg" ] && [ -f "$pkg" ] || die "请指定新版本安装包（flowlens-poc-<版本>-<架构>.tar.gz）。"
  UPGRADE_TMP="$(mktemp -d)"
  trap 'rm -rf "${UPGRADE_TMP:-}"' EXIT
  info "解压 $pkg"
  tar -xzf "$pkg" -C "$UPGRADE_TMP"
  new_dir="$(find "$UPGRADE_TMP" -maxdepth 2 -name VERSION -type f | head -n1)"
  [ -n "$new_dir" ] || die "安装包中缺少 VERSION 文件。"
  new_dir="$(dirname "$new_dir")"
  new_version="$(tr -d ' \n' < "$new_dir/VERSION")"
  info "当前版本 $(get_env FLOWLENS_VERSION)，目标版本 $new_version"
  if [ -f "$new_dir/SHA256SUMS" ]; then
    (cd "$new_dir" && sha256sum -c --quiet SHA256SUMS) || die "安装包校验失败。"
  fi

  if compose ps --status running -q postgres | grep -q .; then
    do_backup
    info "如升级失败，可用 ./flowlens-ctl.sh restore $BACKUP_FILE 恢复"
  else
    warn "数据库未运行，跳过升级前备份。"
  fi

  local img
  for img in "$new_dir"/images/flowlens-images-*.tar*; do
    [ -f "$img" ] || continue
    info "加载镜像 $(basename "$img")"
    case "$img" in
      *.gz) gzip -dc "$img" | docker load ;;
      *) docker load -i "$img" ;;
    esac
  done
  for img in flowlens-platform flowlens-web flowlens-agent; do
    docker image inspect "$img:$new_version" >/dev/null 2>&1 || die "缺少镜像 $img:$new_version"
  done

  info "更新部署文件（保留 .env、certs、conf/agent-config.yaml）"
  # Replace files through a rename: bash reads this running script lazily,
  # so it must not be overwritten in place.
  local f
  mkdir -p conf docs
  for f in docker-compose.yaml .env.example install.sh flowlens-ctl.sh VERSION SHA256SUMS conf/demo-traffic.sh; do
    [ -f "$new_dir/$f" ] || continue
    cp -p "$new_dir/$f" "$f.new"
    mv -f "$f.new" "$f"
  done
  [ -f conf/agent-config.yaml ] || cp "$new_dir"/conf/agent-config.yaml conf/
  cp -r "$new_dir"/docs/. docs/ 2>/dev/null || true
  set_env FLOWLENS_VERSION "$new_version"

  info "启动 $new_version（数据库结构在平台启动时自动升级）"
  compose up -d --no-build --remove-orphans
  wait_healthy
  info "升级完成：$new_version"
}

do_uninstall() {
  if [ "${1:-}" = --purge ]; then
    confirm "将删除容器和全部数据（数据库卷），且无法恢复。确认继续？" || exit 1
    compose --profile agent --profile demo down -v --remove-orphans
    info "已删除容器和数据卷。.env、certs、backups 仍保留在当前目录。"
  else
    compose --profile agent --profile demo down --remove-orphans
    info "已删除容器，数据卷保留。重新执行 ./install.sh 即可恢复运行。"
  fi
}

ASSUME_YES=false
args=()
for a in "$@"; do
  case "$a" in -y|--yes) ASSUME_YES=true ;; *) args+=("$a") ;; esac
done
set -- ${args[@]+"${args[@]}"}

cmd="${1:-}"
[ $# -gt 0 ] && shift
case "$cmd" in
  start) compose up -d --no-build; wait_healthy; info "已启动" ;;
  stop) compose stop; info "已停止" ;;
  restart) compose up -d --no-build --force-recreate; wait_healthy; info "已重启" ;;
  status)
    echo "版本: $(get_env FLOWLENS_VERSION)"
    compose ps
    ;;
  logs)
    svc=()
    follow=()
    for a in "$@"; do
      case "$a" in -f|--follow) follow=(-f) ;; *) svc+=("$a") ;; esac
    done
    compose logs --tail=200 ${follow[@]+"${follow[@]}"} ${svc[@]+"${svc[@]}"}
    ;;
  backup) do_backup "${1:-}" ;;
  restore) do_restore "${1:-}" ;;
  upgrade) do_upgrade "${1:-}" ;;
  uninstall) do_uninstall "${1:-}" ;;
  version) get_env FLOWLENS_VERSION ;;
  ''|-h|--help|help) usage ;;
  *) echo "未知命令: $cmd" >&2; usage >&2; exit 2 ;;
esac
