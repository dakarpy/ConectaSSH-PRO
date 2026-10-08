#!/bin/bash
# ConectaSSH-PRO CLI + SSH/Xray service (multi-distro Linux/systemd)
# Usage:  sudo bash install.sh
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*"; exit 1; }

# ── config ──────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/sshpanel"
SERVICE_NAME="sshpanel"
LOG_TMPFS_SIZE="${LOG_TMPFS_SIZE:-15m}"
PANEL_LOG_MAX_BYTES="${PANEL_LOG_MAX_BYTES:-1048576}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_VERSION="${GO_VERSION:-$(awk '$1 == "go" {print $2; exit}' "$SCRIPT_DIR/go.mod" 2>/dev/null || echo "1.22.5")}"
REPO_URL="${REPO_URL:-https://github.com/dakarpy/ConectaSSH-PRO.git}"
XRAY_VERSION="${XRAY_VERSION:-v26.3.27}"
XRAY_SHA256_AMD64="${XRAY_SHA256_AMD64:-23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae}"
XRAY_SHA256_ARM64="${XRAY_SHA256_ARM64:-4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c}"
MIN_DISK_GB="${MIN_DISK_GB:-5}"
MIN_RAM_MB="${MIN_RAM_MB:-2048}"
ROLLBACK_DIR=""
INSTALL_SUCCESS=false
INSTALL_STARTED=false
CLEANUP_RUNNING=false
GO_ROLLBACK_DIR=""
MKDIR_BIN="$(command -v mkdir 2>/dev/null || true)"
[[ -n "$MKDIR_BIN" ]] || MKDIR_BIN="/bin/mkdir"
# ────────────────────────────────────────────────────────────────────────────

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash $0"

validate_supported_os() {
  local version_id="${VERSION_ID:-}"
  case "${OS_ID:-}:${version_id}" in
    ubuntu:20.04|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|debian:12) ;;
    *) error "Sistema operativo no soportado: ${OS_PRETTY:-unknown}. Soportados: Ubuntu 20.04, 22.04, 24.04, 26.04 y Debian 12." ;;
  esac
}

check_tcp_ports() {
  local port
  for port in "${REQUIRED_TCP_PORTS[@]}"; do
    if ss -H -ltn "( sport = :$port )" 2>/dev/null | grep -q .; then
      warn "Puerto TCP ${port} ya está ocupado. Se ignora; la instalación continúa sin tocar el servicio existente."
    else
      info "Puerto TCP ${port} disponible; Conecta podrá utilizarlo cuando corresponda."
    fi
  done
  return 0
}

check_udp_ports() {
  local port
  for port in "${REQUIRED_UDP_PORTS[@]}"; do
    if ss -H -lun "( sport = :$port )" 2>/dev/null | grep -q .; then
      warn "Puerto UDP ${port} ya está ocupado. Se ignora; la instalación continúa sin tocar el servicio existente."
    else
      info "Puerto UDP ${port} disponible; Conecta podrá utilizarlo cuando corresponda."
    fi
  done
  return 0
}

preflight_checks() {
  info "[PRECHECK] Validando entorno..."
  [[ "$EUID" -eq 0 ]] || error "El instalador debe ejecutarse como root."
  require_systemd
  case "$(uname -m)" in x86_64|aarch64) ;; *) error "Arquitectura no soportada: $(uname -m)." ;; esac
  [[ -e "$INSTALL_DIR" || -e "/etc/systemd/system/${SERVICE_NAME}.service" ]] && error "Ya existe una instalación de Conecta SSH. Se requiere una VPS limpia."
  local disk_gb ram_mb
  disk_gb="$(df -BG --output=avail / | tail -1 | tr -dc "0-9")"
  [[ "$disk_gb" =~ ^[0-9]+$ ]] || error "No se pudo determinar el espacio libre de /."
  (( disk_gb >= MIN_DISK_GB )) || error "Espacio insuficiente en /: ${disk_gb} GB. Mínimo: ${MIN_DISK_GB} GB."
  ram_mb="$(awk '/MemTotal:/ {printf "%d\n", $2/1024; exit}' /proc/meminfo)"
  (( ram_mb >= MIN_RAM_MB )) || error "RAM insuficiente: ${ram_mb} MB. Mínimo: ${MIN_RAM_MB} MB."
  command -v ss >/dev/null 2>&1 || error "El comando ss es obligatorio."
  command -v getent >/dev/null 2>&1 || error "El comando getent es obligatorio."
  command -v curl >/dev/null 2>&1 || error "curl es obligatorio."
  getent ahosts github.com >/dev/null 2>&1 || error "La resolución DNS hacia github.com falló."
  curl -fsS --connect-timeout 5 --max-time 15 https://github.com/ >/dev/null || error "No hay conectividad HTTPS hacia GitHub."
  check_tcp_ports
  check_udp_ports
  info "  Root/arch/disco/RAM/DNS/Internet/puertos: OK"
}

# Cross-distro helpers -------------------------------------------------------
PKG_MANAGER=""
PKG_DEPS=()
PKG_OPTIONAL_DEPS=()
SYSTEMCTL_BIN=""
SH_BIN="$(command -v sh 2>/dev/null || echo /bin/sh)"
MOUNT_BIN="$(command -v mount 2>/dev/null || echo /bin/mount)"
MOUNTPOINT_BIN="$(command -v mountpoint 2>/dev/null || echo /usr/bin/mountpoint)"
TOUCH_BIN="$(command -v touch 2>/dev/null || echo /usr/bin/touch)"
CHMOD_BIN="$(command -v chmod 2>/dev/null || echo /usr/bin/chmod)"
REQUIRED_TCP_PORTS=(80 443 8080 8880 9090 10086)
REQUIRED_UDP_PORTS=(53 7300)

require_systemd() {
  SYSTEMCTL_BIN="$(command -v systemctl 2>/dev/null || true)"
  if [[ -z "$SYSTEMCTL_BIN" ]]; then
    error "systemd was not found. This installer supports Linux distributions that use systemd for services."
  fi
}

detect_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
  elif command -v zypper >/dev/null 2>&1; then
    PKG_MANAGER="zypper"
  elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"
  elif command -v apk >/dev/null 2>&1; then
    PKG_MANAGER="apk"
  else
    error "No supported package manager found. Supported: apt, dnf, yum, zypper, pacman, apk."
  fi
}

set_package_deps() {
  case "$PKG_MANAGER" in
    apt)
      PKG_DEPS=(curl wget git rsync build-essential postgresql ca-certificates unzip openssh-client openssl python3 tar gzip)
      PKG_OPTIONAL_DEPS=(postgresql-contrib iptables nftables)
      ;;
    dnf|yum)
      PKG_DEPS=(curl wget git rsync gcc make postgresql-server ca-certificates unzip openssh-clients openssl python3 tar gzip)
      PKG_OPTIONAL_DEPS=(postgresql-contrib iptables nftables)
      ;;
    zypper)
      PKG_DEPS=(curl wget git rsync gcc make postgresql-server ca-certificates unzip openssh openssl python3 tar gzip)
      PKG_OPTIONAL_DEPS=(postgresql-contrib iptables nftables)
      ;;
    pacman)
      PKG_DEPS=(curl wget git rsync base-devel postgresql ca-certificates unzip openssh openssl python tar gzip)
      PKG_OPTIONAL_DEPS=(iptables-nft nftables)
      ;;
    apk)
      PKG_DEPS=(curl wget git rsync build-base postgresql ca-certificates unzip openssh-client openssl python3 tar gzip)
      PKG_OPTIONAL_DEPS=(postgresql-contrib iptables nftables)
      ;;
  esac
}

pkg_update() {
  case "$PKG_MANAGER" in
    apt) apt-get update -qq ;;
    dnf) dnf makecache -q ;;
    yum) yum makecache -q ;;
    zypper) zypper --non-interactive refresh ;;
    pacman) pacman -Sy --noconfirm ;;
    apk) apk update ;;
  esac
}

pkg_install() {
  case "$PKG_MANAGER" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" ;;
    dnf) dnf install -y "$@" ;;
    yum) yum install -y "$@" ;;
    zypper) zypper --non-interactive install -y "$@" ;;
    pacman) pacman -S --noconfirm --needed "$@" ;;
    apk) apk add --no-cache "$@" ;;
  esac
}

pkg_install_optional() {
  local pkg
  for pkg in "$@"; do
    pkg_install "$pkg" >/dev/null 2>&1 || warn "  Optional package '$pkg' could not be installed; continuing."
  done
}

postgres_data_dir() {
  for dir in /var/lib/postgresql/data /var/lib/pgsql/data /var/lib/postgres/data; do
    [[ -d "$dir" || -d "$(dirname "$dir")" ]] && { printf '%s\n' "$dir"; return 0; }
  done
  printf '%s\n' /var/lib/postgresql/data
}

init_postgresql_if_needed() {
  case "$PKG_MANAGER" in
    dnf|yum|zypper)
      postgresql-setup --initdb >/dev/null 2>&1 || true
      ;;
    pacman)
      local data_dir
      data_dir="$(postgres_data_dir)"
      if [[ ! -s "$data_dir/PG_VERSION" ]]; then
        mkdir -p "$data_dir"
        chown -R postgres:postgres "$(dirname "$data_dir")"
        if command -v runuser >/dev/null 2>&1; then
          runuser -u postgres -- initdb -D "$data_dir" >/dev/null 2>&1 || true
        else
          su - postgres -c "initdb -D '$data_dir'" >/dev/null 2>&1 || true
        fi
      fi
      ;;
    apk)
      if command -v rc-service >/dev/null 2>&1; then
        rc-service postgresql setup >/dev/null 2>&1 || true
      fi
      ;;
  esac
}

start_enable_postgresql() {
  local started=false svc
  for svc in postgresql postgresql.service; do
    if "$SYSTEMCTL_BIN" start "$svc" >/dev/null 2>&1; then
      "$SYSTEMCTL_BIN" enable "$svc" >/dev/null 2>&1 || true
      started=true
      break
    fi
  done
  if ! $started && command -v service >/dev/null 2>&1; then
    service postgresql start >/dev/null 2>&1 && started=true || true
  fi
  $started || warn "  Could not start PostgreSQL automatically; continuing in case it is already running."
}

ensure_log_tmpfs_mount() {
  local log_dir="${INSTALL_DIR}/logs"
  local opts="rw,nosuid,nodev,noexec,noatime,nofail,size=${LOG_TMPFS_SIZE},mode=0755"
  local tmp_fstab

  mkdir -p "$log_dir"

  if [[ -f /etc/fstab ]]; then
    cp /etc/fstab "/etc/fstab.sshpanel.bak.$(date +%s)" 2>/dev/null || true
    tmp_fstab="$(mktemp)"
    awk -v mp="$log_dir" '!(($1 == "tmpfs") && ($2 == mp) && ($3 == "tmpfs")) {print}' /etc/fstab > "$tmp_fstab"
    printf 'tmpfs %s tmpfs %s 0 0\n' "$log_dir" "$opts" >> "$tmp_fstab"
    cat "$tmp_fstab" > /etc/fstab
    rm -f "$tmp_fstab"
    info "  Log RAM disk automount saved in /etc/fstab: $log_dir (${LOG_TMPFS_SIZE})"
  else
    warn "  /etc/fstab not found; service startup fallback will mount $log_dir as tmpfs"
  fi

  "${SYSTEMCTL_BIN:-systemctl}" daemon-reload >/dev/null 2>&1 || true
  if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$log_dir"; then
    mount -o "remount,size=${LOG_TMPFS_SIZE},mode=0755" "$log_dir" >/dev/null 2>&1 || true
  else
    mount "$log_dir" >/dev/null 2>&1 || mount -t tmpfs -o "size=${LOG_TMPFS_SIZE},mode=0755" tmpfs "$log_dir" >/dev/null 2>&1 || \
      warn "  Could not mount $log_dir as tmpfs now; service startup fallback will try again"
  fi

  touch "$log_dir/panel.log" >/dev/null 2>&1 || true
  chmod 0644 "$log_dir/panel.log" >/dev/null 2>&1 || true
}

echo -e "\n${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}   SSH Panel + Xray-core  ·  Installer     ${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}\n"

create_rollback_snapshot() {
  ROLLBACK_DIR="$(mktemp -d /var/tmp/sshpanel-rollback.XXXXXX)"
  mkdir -p "$ROLLBACK_DIR/files"
  : > "$ROLLBACK_DIR/manifest"
  local path key
  for path in /etc/fstab /etc/resolv.conf /etc/profile.d/go.sh /etc/profile.d/conecta-auto-menu.sh /etc/systemd/system/sshpanel.service /etc/systemd/system/sshpanel-dnstt-redirect.service /usr/local/sbin/sshpanel-dnstt-redirect.sh /usr/local/bin/conecta /usr/local/bin/conectassh; do
    key="$(printf '%s' "$path" | sed 's#^/##; s#[/]#_#g')"
    if [[ -e "$path" || -L "$path" ]]; then
      printf 'EXISTS\t%s\t%s\n' "$path" "$key" >> "$ROLLBACK_DIR/manifest"
      tar -C / -czf "$ROLLBACK_DIR/files/${key}.tar.gz" "${path#/}"
    else
      printf 'ABSENT\t%s\t%s\n' "$path" "$key" >> "$ROLLBACK_DIR/manifest"
    fi
  done
  info "  Snapshot de rollback creado: $ROLLBACK_DIR"
}

restore_rollback_snapshot() {
  [[ -n "$ROLLBACK_DIR" && -f "$ROLLBACK_DIR/manifest" ]] || return 0
  warn "Restaurando configuraciones previas..."
  local state path key archive
  while IFS=$'\t' read -r state path key; do
    [[ -n "$path" ]] || continue
    rm -rf -- "$path"
    if [[ "$state" == "EXISTS" ]]; then
      archive="$ROLLBACK_DIR/files/${key}.tar.gz"
      [[ -f "$archive" ]] && tar -C / -xzf "$archive"
    fi
  done < "$ROLLBACK_DIR/manifest"
  "${SYSTEMCTL_BIN:-systemctl}" daemon-reload >/dev/null 2>&1 || true
}

cleanup() {
  local rc="${1:-0}"
  [[ "$CLEANUP_RUNNING" == "true" ]] && return 0
  CLEANUP_RUNNING=true
  if [[ "$INSTALL_SUCCESS" != "true" && "$INSTALL_STARTED" == "true" ]]; then
    warn "Instalación fallida. Ejecutando rollback..."
    "${SYSTEMCTL_BIN:-systemctl}" stop sshpanel.service sshpanel-dnstt-redirect.service >/dev/null 2>&1 || true
    "${SYSTEMCTL_BIN:-systemctl}" disable sshpanel.service sshpanel-dnstt-redirect.service >/dev/null 2>&1 || true
    if mountpoint -q "$INSTALL_DIR/logs" 2>/dev/null; then
      umount "$INSTALL_DIR/logs" >/dev/null 2>&1 || true
    fi
    restore_rollback_snapshot
    if [[ -n "$GO_ROLLBACK_DIR" && -d "$GO_ROLLBACK_DIR" ]]; then
      rm -rf /usr/local/go
      mv "$GO_ROLLBACK_DIR" /usr/local/go
    fi
    rm -rf "$INSTALL_DIR"
  fi
  rm -rf /tmp/xray.*.zip /tmp/xray-extract.* /tmp/go.tar.gz "$ROLLBACK_DIR"
  return "$rc"
}

trap 'exit 1' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'rc=$?; cleanup "$rc"; exit "$rc"' EXIT

# ── 1. OS / package-manager detection ────────────────────────────────────────
info "[1/10] Detecting Linux distribution and package manager…"
if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_LIKE="${ID_LIKE:-}"
  OS_PRETTY="${PRETTY_NAME:-$OS_ID}"
else
  OS_ID="unknown"
  OS_LIKE=""
  OS_PRETTY="unknown Linux"
fi

require_systemd
detect_pkg_manager
set_package_deps
info "  OS             : $OS_PRETTY"
info "  ID / ID_LIKE   : $OS_ID / ${OS_LIKE:-none}"
info "  Package manager: $PKG_MANAGER"
info "  Service manager: systemd"
validate_supported_os
preflight_checks
create_rollback_snapshot
INSTALL_STARTED=true

# ── 2. System dependencies ───────────────────────────────────────────────────
info "[2/10] Installing system packages…"
pkg_update
pkg_install "${PKG_DEPS[@]}"
pkg_install_optional "${PKG_OPTIONAL_DEPS[@]}"

# ── 3. Go ────────────────────────────────────────────────────────────────────
info "[3/10] Installing Go ${GO_VERSION}…"
NEED_GO=true
if command -v go &>/dev/null; then
  CURRENT_GO=$(go version 2>/dev/null | awk '{print $3}' | sed 's/go//')
  if [[ "$(printf '%s\n' "$GO_VERSION" "$CURRENT_GO" | sort -V | head -1)" == "$GO_VERSION" ]]; then
    info "  Go $CURRENT_GO already installed — skipping"
    NEED_GO=false
  fi
fi

if $NEED_GO; then
  MACHINE=$(uname -m)
  case "$MACHINE" in
    x86_64)  GOARCH="amd64" ;;
    aarch64) GOARCH="arm64" ;;
    armv7l)  GOARCH="armv6l" ;;
    *)       GOARCH="amd64" ;;
  esac
  GO_URL="https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz"
  info "  Downloading $GO_URL"
  wget -q --show-progress -O /tmp/go.tar.gz "$GO_URL"
  if [[ -d /usr/local/go ]]; then
    GO_ROLLBACK_DIR="$ROLLBACK_DIR/previous-go"
    mv /usr/local/go "$GO_ROLLBACK_DIR"
  fi
  tar -C /usr/local -xzf /tmp/go.tar.gz
  rm -f /tmp/go.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
  chmod +x /etc/profile.d/go.sh
fi

export PATH=$PATH:/usr/local/go/bin
go version

# ── 4. Directory layout ──────────────────────────────────────────────────────
info "[4/10] Setting up ${INSTALL_DIR}…"
mkdir -p "$INSTALL_DIR/keys" "$INSTALL_DIR/logs"
ensure_log_tmpfs_mount

# ── 5. Build SSH panel binary ────────────────────────────────────────────────
info "[5/10] Building SSH Panel binary…"
cd "$SCRIPT_DIR"
export GOPATH=/tmp/gopath_sshpanel
export GOCACHE=/tmp/gocache_sshpanel
BUILD_COMMIT="$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || true)"
BUILD_BRANCH="$(git -C "$SCRIPT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BUILD_REPO_URL="$(git -C "$SCRIPT_DIR" config --get remote.origin.url 2>/dev/null || true)"
[[ -n "$BUILD_COMMIT" ]] || BUILD_COMMIT="unknown"
[[ -n "$BUILD_BRANCH" && "$BUILD_BRANCH" != "HEAD" ]] || BUILD_BRANCH="main"
[[ -n "$BUILD_REPO_URL" ]] || BUILD_REPO_URL="$REPO_URL"

go mod download
go build -ldflags="-s -w -X main.buildCommit=$BUILD_COMMIT -X main.buildBranch=$BUILD_BRANCH -X main.buildTime=$BUILD_TIME" -o "$INSTALL_DIR/sshpanel" .
printf '%s\n' "$BUILD_COMMIT" > "$INSTALL_DIR/.installed_commit"
printf '%s\n' "$BUILD_BRANCH" > "$INSTALL_DIR/.installed_branch"
printf '%s\n' "$BUILD_TIME" > "$INSTALL_DIR/.installed_build_time"
printf '%s\n' "$BUILD_REPO_URL" > "$INSTALL_DIR/.installed_repo_url"
chmod 0644 "$INSTALL_DIR/.installed_commit" "$INSTALL_DIR/.installed_branch" "$INSTALL_DIR/.installed_build_time"
chmod 0600 "$INSTALL_DIR/.installed_repo_url"
info "  Binary: $INSTALL_DIR/sshpanel"
info "  Build commit: $BUILD_COMMIT ($BUILD_BRANCH)"
install -m 700 "$SCRIPT_DIR/conectassh_cli.py" "$INSTALL_DIR/conectassh_cli.py"
install -m 700 "$SCRIPT_DIR/uninstall.sh" "$INSTALL_DIR/uninstall.sh"
ln -sfn "$INSTALL_DIR/conectassh_cli.py" /usr/local/bin/conectassh
if [[ ( -e /usr/local/bin/conecta || -L /usr/local/bin/conecta ) && "$(readlink -f /usr/local/bin/conecta 2>/dev/null || true)" != "$INSTALL_DIR/conectassh_cli.py" ]]; then
  CONECTA_BACKUP="/usr/local/bin/conecta.backup.$(date +%s%N)"
  mv /usr/local/bin/conecta "$CONECTA_BACKUP"
  warn "  Previous conecta command saved to $CONECTA_BACKUP"
fi
ln -sfn "$INSTALL_DIR/conectassh_cli.py" /usr/local/bin/conecta
install -m 644 "$SCRIPT_DIR/auto-menu.sh" /etc/profile.d/conecta-auto-menu.sh
info "  ConectaSSH-PRO CLI installed: conecta (also conectassh)"
mkdir -p "$INSTALL_DIR/source"
rsync -a --delete --exclude '.git' --exclude 'source/' --exclude '__pycache__/' "$SCRIPT_DIR/" "$INSTALL_DIR/source/"


install_online_web_pro_module() {
  local module_dir="$INSTALL_DIR/online-bridge"
  local source_dir="$SCRIPT_DIR/cmd/conecta-online-bridge"
  local tmp_bin="$module_dir/conecta-online-bridge.tmp"

  [[ -f "$source_dir/main.go" ]] || error "MODULO ONLINE WEB PRO source is missing."
  [[ -f "$source_dir/conecta-online-bridge.service" ]] || error "MODULO ONLINE WEB PRO service template is missing."

  mkdir -p "$module_dir"
  info "  Building MODULO ONLINE WEB PRO..."
  go build -trimpath -ldflags="-s -w" -o "$tmp_bin" ./cmd/conecta-online-bridge
  chmod 0755 "$tmp_bin"
  mv -f "$tmp_bin" "$module_dir/conecta-online-bridge"

  install -m 0644 "$source_dir/conecta-online-bridge.service" /etc/systemd/system/conecta-online-bridge.service
  "$SYSTEMCTL_BIN" daemon-reload
  "$SYSTEMCTL_BIN" enable --now conecta-online-bridge.service
  info "  MODULO ONLINE WEB PRO: activo por defecto (CPU <= 5%, RAM <= 64 MB)."
}


install_online_web_pro_module


install_official_hcr_binary() {
  local arch src dst
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) src="$SCRIPT_DIR/hcr-server-linux-amd64"; dst="$INSTALL_DIR/hcr/hcr-server-linux-amd64" ;;
    aarch64|arm64) src="$SCRIPT_DIR/hcr-server-linux-arm64"; dst="$INSTALL_DIR/hcr/hcr-server-linux-arm64" ;;
    *) warn "  HCR oficial: arquitectura no soportada: $arch"; return 0 ;;
  esac
  mkdir -p "$INSTALL_DIR/hcr"
  if [[ -f "$src" ]]; then
    install -m 755 "$src" "$dst"
    info "  HCR oficial instalado: $dst ($arch)"
  else
    warn "  Falta $src; agregalo al paquete para habilitar HCR oficial en esta arquitectura."
  fi
}

install_official_hcr_binary
if [[ -f "$SCRIPT_DIR/update.sh" ]]; then
  cp "$SCRIPT_DIR/update.sh" "$INSTALL_DIR/update.sh"
  chmod 700 "$INSTALL_DIR/update.sh"
  info "  Git-based CLI updater copied"
fi

# ── 6. Xray binary ──────────────────────────────────────────────────────────
info "[6/10] Installing fixed Xray-core…"
install_xray() {
  local machine xray_arch xray_sha256 xray_url xray_tmp xray_extract
  machine="$(uname -m)"
  case "$machine" in
    x86_64) xray_arch="64"; xray_sha256="$XRAY_SHA256_AMD64" ;;
    aarch64) xray_arch="arm64-v8a"; xray_sha256="$XRAY_SHA256_ARM64" ;;
    *) error "Arquitectura no soportada para Xray: $machine" ;;
  esac
  xray_url="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${xray_arch}.zip"
  xray_tmp="$(mktemp /tmp/xray.XXXXXX.zip)"
  xray_extract="$(mktemp -d /tmp/xray-extract.XXXXXX)"
  info "  Xray ${XRAY_VERSION} (${xray_arch})"
  wget -q --show-progress -O "$xray_tmp" "$xray_url"
  printf "%s  %s\n" "$xray_sha256" "$xray_tmp" | sha256sum -c -
  unzip -q -o "$xray_tmp" xray -d "$xray_extract"
  install -m 0755 "$xray_extract/xray" "$INSTALL_DIR/xray"
  rm -rf "$xray_extract" "$xray_tmp"
  "$INSTALL_DIR/xray" version
}
install_xray

# ── 7. PostgreSQL ────────────────────────────────────────────────────────────
info "[7/10] Configuring PostgreSQL…"
init_postgresql_if_needed
start_enable_postgresql

DB_NAME="sshpanel"
DB_USER="sshpanel"
DB_PASS=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32 || true)
if [[ ${#DB_PASS} -lt 32 ]]; then
  DB_PASS=$(openssl rand -hex 16 2>/dev/null || date +%s%N)
fi

su -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'\" | grep -q 1 || \
       psql -c \"CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';\"" postgres
# Reinstall-safe: if the role already existed, make the new .env password valid.
su -c "psql -c \"ALTER USER ${DB_USER} WITH PASSWORD '${DB_PASS}';\"" postgres

su -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'\" | grep -q 1 || \
       psql -c \"CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};\"" postgres
# Reinstall-safe: if the database already existed, make sshpanel its owner.
su -c "psql -c \"ALTER DATABASE ${DB_NAME} OWNER TO ${DB_USER};\"" postgres

su -c "psql -d ${DB_NAME} -c \"
CREATE TABLE IF NOT EXISTS ssh_users (
  username              TEXT PRIMARY KEY,
  password              TEXT NOT NULL DEFAULT '',
  max_connections       INT  NOT NULL DEFAULT 0,
  expires_at            TEXT,
  limit_mbps_up         INT  NOT NULL DEFAULT 0,
  limit_mbps_down       INT  NOT NULL DEFAULT 0,
  totp_secret           TEXT NOT NULL DEFAULT '',
  totp_period           INT  NOT NULL DEFAULT 60,
  totp_window           INT  NOT NULL DEFAULT 1,
  totp_digits           INT  NOT NULL DEFAULT 6,
  allow_static_password BOOLEAN NOT NULL DEFAULT FALSE,
  owner_username        TEXT NOT NULL DEFAULT ''
);
ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS totp_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS totp_period INT NOT NULL DEFAULT 60;
ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS totp_window INT NOT NULL DEFAULT 1;
ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS totp_digits INT NOT NULL DEFAULT 6;
ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS allow_static_password BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE ssh_users ADD COLUMN IF NOT EXISTS owner_username TEXT NOT NULL DEFAULT '';
ALTER TABLE ssh_users ALTER COLUMN password SET DEFAULT '';

CREATE TABLE IF NOT EXISTS ssh_iface_totals (
  iface                TEXT PRIMARY KEY,
  total_rx_bytes       BIGINT NOT NULL DEFAULT 0,
  total_tx_bytes       BIGINT NOT NULL DEFAULT 0,
  last_kernel_rx_bytes BIGINT NOT NULL DEFAULT 0,
  last_kernel_tx_bytes BIGINT NOT NULL DEFAULT 0,
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE ssh_iface_totals ADD COLUMN IF NOT EXISTS total_rx_bytes BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ssh_iface_totals ADD COLUMN IF NOT EXISTS total_tx_bytes BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ssh_iface_totals ADD COLUMN IF NOT EXISTS last_kernel_rx_bytes BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ssh_iface_totals ADD COLUMN IF NOT EXISTS last_kernel_tx_bytes BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ssh_iface_totals ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE TABLE IF NOT EXISTS admin_users (
  id            SERIAL PRIMARY KEY,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'reseller',
  max_users     INT  NOT NULL DEFAULT 30,
  expires_at    TIMESTAMPTZ,
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS xray_clients (
  uuid        TEXT PRIMARY KEY,
  name        TEXT NOT NULL DEFAULT '',
  email       TEXT NOT NULL DEFAULT '',
  inbound_tag TEXT NOT NULL DEFAULT '',
  expires_at  TIMESTAMPTZ,
  max_conns   INT NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Telegram sales bot (created idempotently by the app too; mirrored here for a clean install)
CREATE TABLE IF NOT EXISTS bot_users (
  telegram_id           BIGINT PRIMARY KEY,
  username              TEXT NOT NULL DEFAULT '',
  first_name            TEXT NOT NULL DEFAULT '',
  role                  TEXT NOT NULL DEFAULT 'customer',
  linked_admin_username TEXT NOT NULL DEFAULT '',
  credit_balance        INT NOT NULL DEFAULT 0,
  trial_used            BOOLEAN NOT NULL DEFAULT false,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS bot_plans (
  id SERIAL PRIMARY KEY, name TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT 'ssh',
  days INT NOT NULL DEFAULT 30, max_connections INT NOT NULL DEFAULT 1,
  limit_mbps_up INT NOT NULL DEFAULT 0, limit_mbps_down INT NOT NULL DEFAULT 0,
  xray_inbound_tag TEXT NOT NULL DEFAULT '', xray_protocol TEXT NOT NULL DEFAULT '',
  price_cents INT NOT NULL DEFAULT 0, credit_cost INT NOT NULL DEFAULT 1,
  server_id TEXT NOT NULL DEFAULT '', is_active BOOLEAN NOT NULL DEFAULT true, sort_order INT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS bot_credit_packages (
  id SERIAL PRIMARY KEY, name TEXT NOT NULL DEFAULT '', credits INT NOT NULL DEFAULT 0,
  price_cents INT NOT NULL DEFAULT 0, is_active BOOLEAN NOT NULL DEFAULT true, sort_order INT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS bot_transactions (
  id SERIAL PRIMARY KEY, telegram_id BIGINT NOT NULL, type TEXT NOT NULL,
  plan_id INT, package_id INT, credits INT NOT NULL DEFAULT 0, amount_cents INT NOT NULL DEFAULT 0,
  mp_payment_id TEXT NOT NULL DEFAULT '', mp_qr_code TEXT NOT NULL DEFAULT '', mp_qr_base64 TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending', target_username TEXT NOT NULL DEFAULT '', renew_target TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), paid_at TIMESTAMPTZ, expires_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS bot_transactions_mp_payment_id_uidx ON bot_transactions (mp_payment_id) WHERE mp_payment_id <> '';

CREATE TABLE IF NOT EXISTS bot_credits_ledger (
  id SERIAL PRIMARY KEY, telegram_id BIGINT NOT NULL, delta INT NOT NULL, reason TEXT NOT NULL DEFAULT '',
  ref_transaction_id INT, balance_after INT NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS bot_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');

CREATE TABLE IF NOT EXISTS bot_config (
  id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1), enabled BOOLEAN NOT NULL DEFAULT false,
  telegram_mode TEXT NOT NULL DEFAULT 'polling', telegram_webhook_url TEXT NOT NULL DEFAULT '',
  mp_confirm_mode TEXT NOT NULL DEFAULT 'polling', mp_poll_interval TEXT NOT NULL DEFAULT '20s',
  pix_expiration_minutes INT NOT NULL DEFAULT 30, trial_enabled BOOLEAN NOT NULL DEFAULT true,
  trial_hours INT NOT NULL DEFAULT 1, trial_max_connections INT NOT NULL DEFAULT 1,
  trial_kind TEXT NOT NULL DEFAULT 'ssh', trial_inbound_tag TEXT NOT NULL DEFAULT '',
  admin_telegram_ids BIGINT[] NOT NULL DEFAULT '{}', currency TEXT NOT NULL DEFAULT 'BRL',
  public_host TEXT NOT NULL DEFAULT '', xray_public_host TEXT NOT NULL DEFAULT '',
  telegram_token_enc BYTEA, telegram_webhook_secret_enc BYTEA, mp_access_token_enc BYTEA, mp_webhook_secret_enc BYTEA,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO bot_config (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

ALTER SCHEMA public OWNER TO ${DB_USER};
ALTER TABLE IF EXISTS ssh_users OWNER TO ${DB_USER};
ALTER TABLE IF EXISTS ssh_iface_totals OWNER TO ${DB_USER};
ALTER TABLE IF EXISTS admin_users OWNER TO ${DB_USER};
ALTER TABLE IF EXISTS xray_clients OWNER TO ${DB_USER};
ALTER TABLE IF EXISTS bot_users OWNER TO ${DB_USER};
ALTER TABLE IF EXISTS bot_plans OWNER TO ${DB_USER};
ALTER TABLE IF EXISTS bot_credit_packages OWNER TO ${DB_USER};
ALTER TABLE IF EXISTS bot_transactions OWNER TO ${DB_USER};
ALTER TABLE IF EXISTS bot_credits_ledger OWNER TO ${DB_USER};
ALTER TABLE IF EXISTS bot_settings OWNER TO ${DB_USER};
ALTER TABLE IF EXISTS bot_config OWNER TO ${DB_USER};
ALTER SEQUENCE IF EXISTS admin_users_id_seq OWNER TO ${DB_USER};
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
GRANT ALL PRIVILEGES ON SCHEMA public TO ${DB_USER};
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ${DB_USER};
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ${DB_USER};
\"" postgres

info "  PostgreSQL database '${DB_NAME}' ready"

# ── 8. Config files ──────────────────────────────────────────────────────────
info "[8/10] Generating config files…"

# Admin token
ADMIN_TOKEN=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 48 || true)
if [[ ${#ADMIN_TOKEN} -lt 48 ]]; then
  ADMIN_TOKEN=$(openssl rand -hex 24 2>/dev/null || date +%s%N)
fi

# Preserve an admin account for API clients using session authentication.
ADMIN_PASSWORD=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 20 || true)
if [[ ${#ADMIN_PASSWORD} -lt 20 ]]; then
  ADMIN_PASSWORD=$(openssl rand -hex 10 2>/dev/null || date +%s%N)
fi
ADMIN_PASSWORD_HASH=$(printf '%s' "${ADMIN_PASSWORD}" | "$INSTALL_DIR/sshpanel" -hash-admin-password-stdin 2>/dev/null)
[[ "$ADMIN_PASSWORD_HASH" == \$2* ]] || error "Failed to generate admin bcrypt password hash"
su -c "psql -d ${DB_NAME}" postgres <<SQL
INSERT INTO admin_users (username, password_hash, role, max_users, expires_at, is_active)
VALUES ('admin', '${ADMIN_PASSWORD_HASH}', 'superadmin', 0, NULL, TRUE)
ON CONFLICT (username) DO UPDATE SET
  password_hash = EXCLUDED.password_hash,
  role = 'superadmin',
  max_users = 0,
  expires_at = NULL,
  is_active = TRUE;
SQL

# .env
cat > "$INSTALL_DIR/.env" <<EOF
PG_DSN=postgres://${DB_USER}:${DB_PASS}@127.0.0.1:5432/${DB_NAME}?sslmode=disable
ADMIN_TOKEN=${ADMIN_TOKEN}
ADMIN_HTTP_ADDR=127.0.0.1:9090
EOF
chmod 600 "$INSTALL_DIR/.env"

# SSH host key (RSA, required by current build)
if [[ ! -f "$INSTALL_DIR/ssh_host_rsa_key" ]]; then
  ssh-keygen -t rsa -b 2048 -f "$INSTALL_DIR/ssh_host_rsa_key" -N "" -C "sshpanel-hostkey" -q
  info "  Generated RSA host key"
fi

# Server public IP (best-effort)
SERVER_IP=$(curl -sf --max-time 5 https://checkip.amazonaws.com 2>/dev/null \
         || curl -sf --max-time 5 https://api.ipify.org 2>/dev/null \
         || hostname -I | awk '{print $1}')

# config.json
cat > "$INSTALL_DIR/config.json" <<EOF
{
  "listen": "0.0.0.0:80",
  "extra_listen": ["0.0.0.0:8080"],
  "local_ssh_listen": "127.0.0.1:2222",
  "host_key_file": "${INSTALL_DIR}/ssh_host_rsa_key",
  "quiet": false,
  "pam_auth_enabled": true,
  "banner_file": "${INSTALL_DIR}/banner.txt",
  "xray": {
    "enabled": true,
    "mode": "native",
    "native": true,
    "bin_path": "${INSTALL_DIR}/xray",
    "config_file": "${INSTALL_DIR}/xray_config.json",
    "native_config_file": "${INSTALL_DIR}/xray_native_config.json"
  }
}
EOF
touch "$INSTALL_DIR/banner.txt"

# UUID for default VLESS client
UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null \
    || python3 -c "import uuid; print(uuid.uuid4())" 2>/dev/null \
    || echo "11111111-2222-3333-4444-555555555555")

# xray_native_config.json is used by the internal emulator. xray_config.json is
# kept only for optional external-xray mode. Both start with the same default.
cat > "$INSTALL_DIR/xray_native_config.json" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "vless-in",
      "port": 10086,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "${UUID}", "level": 0 }],
        "decryption": "none"
      },
      "streamSettings": { "network": "tcp" }
    },
    {
      "tag": "socks-local",
      "port": 10088,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": { "auth": "noauth", "udp": true }
    }
  ],
  "outbounds": [
    { "tag": "direct",  "protocol": "freedom",  "settings": {} },
    { "tag": "blocked", "protocol": "blackhole", "settings": {} }
  ]
}
EOF
cp -f "$INSTALL_DIR/xray_native_config.json" "$INSTALL_DIR/xray_config.json"
chmod 600 "$INSTALL_DIR/xray_native_config.json" "$INSTALL_DIR/xray_config.json"
info "  VLESS UUID: ${UUID}"

# ── 9. DNSTT DNS/53 redirect ─────────────────────────────────────────────────
info "[9/10] Configuring DNSTT DNS redirect (UDP 53 -> 5300)…"
cat > /usr/local/sbin/sshpanel-dnstt-redirect.sh <<'EOS'
#!/bin/bash
set -euo pipefail
DNS_UPSTREAM="${DNS_UPSTREAM:-1.1.1.1}"
DNSTT_PORT="${DNSTT_PORT:-5300}"

# Never take over UDP 53 if another service already owns it.
# The installer must continue without stopping, killing, disabling, or reconfiguring that service.
if command -v ss >/dev/null 2>&1 && ss -H -lun "( sport = :53 )" 2>/dev/null | grep -q .; then
  echo "WARNING: UDP 53 is occupied; Conecta leaves it untouched and skips the DNSTT redirect." >&2
  exit 0
fi

# UDP 53 is free, so Conecta may configure its DNSTT redirect.
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now systemd-resolved.service >/dev/null 2>&1 || true
fi
rm -f /etc/resolv.conf
printf 'nameserver %s\n' "$DNS_UPSTREAM" > /etc/resolv.conf

# Open DNS/UDP in common Linux firewalls when they are active.
if command -v ufw >/dev/null 2>&1; then
  ufw allow 53/udp >/dev/null 2>&1 || true
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port=53/udp >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
fi

add_iptables_rule() {
  local bin="$1" chain="$2"
  "$bin" -t nat -C "$chain" -p udp --dport 53 -j REDIRECT --to-ports "$DNSTT_PORT" 2>/dev/null \
    || "$bin" -t nat -A "$chain" -p udp --dport 53 -j REDIRECT --to-ports "$DNSTT_PORT"
}

if command -v iptables >/dev/null 2>&1; then
  add_iptables_rule iptables PREROUTING
fi

if command -v ip6tables >/dev/null 2>&1; then
  add_iptables_rule ip6tables PREROUTING || true
fi

# Fallback for minimal systems where only nft is present.
if ! command -v iptables >/dev/null 2>&1 && command -v nft >/dev/null 2>&1; then
  nft add table inet sshpanel_nat 2>/dev/null || true
  nft 'add chain inet sshpanel_nat prerouting { type nat hook prerouting priority dstnat; policy accept; }' 2>/dev/null || true
  nft list chain inet sshpanel_nat prerouting 2>/dev/null | grep -q "udp dport 53 redirect to :$DNSTT_PORT" \
    || nft add rule inet sshpanel_nat prerouting udp dport 53 redirect to :"$DNSTT_PORT"
fi
EOS
chmod +x /usr/local/sbin/sshpanel-dnstt-redirect.sh

cat > /etc/systemd/system/sshpanel-dnstt-redirect.service <<'EOF'
[Unit]
Description=SSH Panel DNSTT DNS redirect (UDP 53 to 5300)
After=network.target
Before=sshpanel.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sshpanel-dnstt-redirect.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

"$SYSTEMCTL_BIN" daemon-reload
"$SYSTEMCTL_BIN" enable --now sshpanel-dnstt-redirect.service || warn "DNSTT DNS redirect service failed; check: journalctl -u sshpanel-dnstt-redirect -e"
info "  DNSTT DNS redirect installed: UDP 53 -> 5300"

# ── 10. Systemd service ──────────────────────────────────────────────────────
info "[10/10] Creating systemd service '${SERVICE_NAME}'…"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=SSH Panel + Xray-core Server
After=local-fs.target network.target postgresql.service sshpanel-dnstt-redirect.service
Wants=postgresql.service sshpanel-dnstt-redirect.service

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
Environment=PANEL_LOG_FILE=${INSTALL_DIR}/logs/panel.log
Environment=PANEL_LOG_MAX_BYTES=${PANEL_LOG_MAX_BYTES}
ExecStartPre=${MKDIR_BIN} -p ${INSTALL_DIR}/logs
ExecStartPre=${SH_BIN} -c '${MOUNTPOINT_BIN} -q ${INSTALL_DIR}/logs || ${MOUNT_BIN} -t tmpfs -o size=${LOG_TMPFS_SIZE},mode=0755 tmpfs ${INSTALL_DIR}/logs || true'
ExecStartPre=${SH_BIN} -c '${TOUCH_BIN} ${INSTALL_DIR}/logs/panel.log && ${CHMOD_BIN} 0644 ${INSTALL_DIR}/logs/panel.log || true'
ExecStart=${INSTALL_DIR}/sshpanel -config ${INSTALL_DIR}/config.json
Restart=always
RestartSec=5
User=root
LimitNOFILE=1048576
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

"$SYSTEMCTL_BIN" daemon-reload
"$SYSTEMCTL_BIN" enable  "$SERVICE_NAME"
"$SYSTEMCTL_BIN" restart "$SERVICE_NAME"

sleep 2
echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}   Installation complete!                  ${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo -e "  Server IP    : ${YELLOW}${SERVER_IP}${NC}"
echo -e "  SSH ports    : 80, 8080  (HTTP-injected SSH)"
echo -e "  Internal SSH : 127.0.0.1:2222  (raw SSH for local proxies)"
echo -e "  VLESS port   : 10086"
echo -e "  VLESS UUID   : ${YELLOW}${UUID}${NC}"
echo -e "  DNSTT DNS    : UDP 53 redirects to local UDP 5300"
echo ""
echo -e "  CLI conecta     : ${YELLOW}conecta${NC} (or sudo conecta outside a root shell)"
echo -e "  API endpoint : ${YELLOW}http://127.0.0.1:9090${NC}"
echo -e "  API password : ${YELLOW}${ADMIN_TOKEN}${NC}"
echo -e "  API session login (integrations): admin / ${ADMIN_PASSWORD}"
echo ""
echo -e "  API token + DB credentials stored in: ${INSTALL_DIR}/.env"
echo -e "  Logs: journalctl -u ${SERVICE_NAME} -f"
echo -e "        tail -f ${INSTALL_DIR}/logs/panel.log"
echo ""
INSTALL_SUCCESS=true
echo -e "${YELLOW}View/rotate the API password later with: sudo conectassh api-password show|change${NC}"
echo ""
"$SYSTEMCTL_BIN" status "$SERVICE_NAME" --no-pager -l || true

# Ownership manifest consumed by the professional uninstaller. It intentionally
# does not claim ownership of shared OS packages or pre-existing databases.
cat > "$INSTALL_DIR/.conecta-install-manifest" <<EOF
PRODUCT=ConectaSSH-PRO
INSTALL_DIR=/opt/sshpanel
DB_NAME=sshpanel
DB_USER=sshpanel
DB_CREATED_BY_CONECTA=0
DB_ROLE_CREATED_BY_CONECTA=0
RESOLVED_WAS_ACTIVE=0
RESOLV_LINK_TARGET=
RESOLV_BACKUP=
FSTAB_TMPFS_ADDED=1
UFW_53_ADDED=0
FIREWALLD_53_ADDED=0
CONECTA_BACKUP=${CONECTA_BACKUP:-}
AUTO_MENU_BACKUP=${AUTO_MENU_BACKUP:-}
EOF
chmod 600 "$INSTALL_DIR/.conecta-install-manifest"
