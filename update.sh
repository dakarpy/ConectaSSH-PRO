#!/bin/bash
# Update the ConectaSSH-PRO CLI from its Git repository.
#
# Preserved:
#   - /opt/sshpanel/.env
#   - /opt/sshpanel/config.json
#   - /opt/sshpanel/xray_config.json
#   - SSH keys, certs, logs, database, users
#
# Usage:
#   sudo bash /opt/sshpanel/update.sh
#   sudo bash update.sh
#
# UPDATE_SOURCE=local sudo bash update.sh applies a checked-out/offline release.
# UPDATE_REF selects an optional remote branch; empty follows remote HEAD.
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*"; exit 1; }

# Config
INSTALL_DIR="${INSTALL_DIR:-/opt/sshpanel}"
SERVICE_NAME="${SERVICE_NAME:-sshpanel}"
LOG_TMPFS_SIZE="${LOG_TMPFS_SIZE:-15m}"
PANEL_LOG_MAX_BYTES="${PANEL_LOG_MAX_BYTES:-1048576}"
REPO_URL="${REPO_URL:-https://github.com/dakarpy/ConectaSSH-PRO.git}"
UPDATE_REF="${UPDATE_REF:-}"
UPDATE_SOURCE="${UPDATE_SOURCE:-git}"
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=/bin/false
SOURCE_CACHE_DIR="${SOURCE_CACHE_DIR:-${INSTALL_DIR}/source}"
MKDIR_BIN="$(command -v mkdir 2>/dev/null || true)"
[[ -n "$MKDIR_BIN" ]] || MKDIR_BIN="/bin/mkdir"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR=""
FETCH_DIR=""
RESTART_NEEDED=false
SERVICE_WAS_ACTIVE=false
UPDATE_SWAP_DONE=false
UPDATE_SUCCESS=false
ROLLBACK_BINARY=""
BUILD_COMMIT=""
BUILD_BRANCH=""
BUILD_TIME=""
BUILD_REPO_URL=""

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash $0"

# SSH safety guard: never change sshd or its active port from these scripts.
detect_active_ssh_port() {
  local session_port="" configured_port=""
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    read -r _ _ _ session_port <<< "$SSH_CONNECTION"
  fi
  if [[ "$session_port" =~ ^[0-9]+$ ]] && (( session_port >= 1 && session_port <= 65535 )); then
    printf '%s\n' "$session_port"
    return 0
  fi
  if command -v sshd >/dev/null 2>&1; then
    configured_port="$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2; exit }')"
  fi
  if [[ "$configured_port" =~ ^[0-9]+$ ]] && (( configured_port >= 1 && configured_port <= 65535 )); then
    printf '%s\n' "$configured_port"
    return 0
  fi
  # Last-resort discovery from listening sockets owned by sshd/ssh.
  configured_port="$(ss -H -ltnp 2>/dev/null | awk '/sshd|"ssh"/ { n=split($4,a,":"); if (n>1) {p=a[n]; if (p ~ /^[0-9]+$/) {print p; exit}} }')"
  [[ "$configured_port" =~ ^[0-9]+$ ]] && (( configured_port >= 1 && configured_port <= 65535 )) || return 1
  printf '%s\n' "$configured_port"
}

ssh_safety_preflight() {
  local port
  port="$(detect_active_ssh_port)" || {
    error "No se pudo detectar el puerto SSH activo. Se aborta por seguridad."
  }
  info "Puerto SSH detectado: ${port}/tcp"
  if ! ss -H -ltn "( sport = :${port} )" 2>/dev/null | grep -q .; then
    error "El puerto SSH detectado (${port}) no aparece escuchando. No se continuará."
  fi
  if [[ -z "${TMUX:-}" && -z "${STY:-}" ]]; then
    warn "No se detectó tmux/screen. Se recomienda una sesión persistente y consola del proveedor."
  fi
  # Intentional invariant: this installer/updater must not edit sshd_config,
  # restart sshd, enable UFW, or flush firewall rules.
}

ssh_safety_preflight

# Standard updates do not mutate global profile hooks or delete legacy files.
remove_legacy_login_hook() { warn "Hook de login conservado; las actualizaciones no modifican /etc/profile.d."; return 0; }

# Cross-distro helpers -------------------------------------------------------
PKG_MANAGER=""
UPDATE_DEPS=()
SYSTEMCTL_BIN=""
SH_BIN="$(command -v sh 2>/dev/null || echo /bin/sh)"
MOUNT_BIN="$(command -v mount 2>/dev/null || echo /bin/mount)"
MOUNTPOINT_BIN="$(command -v mountpoint 2>/dev/null || echo /usr/bin/mountpoint)"
TOUCH_BIN="$(command -v touch 2>/dev/null || echo /usr/bin/touch)"
CHMOD_BIN="$(command -v chmod 2>/dev/null || echo /usr/bin/chmod)"

require_systemd() {
  SYSTEMCTL_BIN="$(command -v systemctl 2>/dev/null || true)"
  if [[ -z "$SYSTEMCTL_BIN" ]]; then
    error "systemd was not found. This updater supports Linux distributions that use systemd for services."
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

set_update_deps() {
  case "$PKG_MANAGER" in
    apt)
      UPDATE_DEPS=(git rsync wget ca-certificates python3 gcc make tar gzip)
      ;;
    dnf|yum)
      UPDATE_DEPS=(git rsync wget ca-certificates python3 gcc make tar gzip)
      ;;
    zypper)
      UPDATE_DEPS=(git rsync wget ca-certificates python3 gcc make tar gzip)
      ;;
    pacman)
      UPDATE_DEPS=(git rsync wget ca-certificates python gcc make tar gzip)
      ;;
    apk)
      UPDATE_DEPS=(git rsync wget ca-certificates python3 gcc make tar gzip)
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

ensure_update_dependencies() {
  local missing=false cmd
  for cmd in git rsync wget tar gzip gcc make; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing=true
    fi
  done
  if ! command -v python3 >/dev/null 2>&1; then
    missing=true
  fi
  if $missing; then
    warn "One or more updater dependencies are missing. Installing them with $PKG_MANAGER..."
    pkg_update
    pkg_install "${UPDATE_DEPS[@]}"
  fi
  if ! command -v python3 >/dev/null 2>&1 && command -v python >/dev/null 2>&1; then
    ln -sf "$(command -v python)" /usr/local/bin/python3 2>/dev/null || true
  fi
}

echo -e "\n${GREEN}==========================================${NC}"
echo -e "${GREEN}   ConectaSSH-PRO / SSH Panel Updater       ${NC}"
echo -e "${GREEN}==========================================${NC}\n"

# Helpers
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || error "Required command not found: $1"
}


install_git_if_missing() {
  if command -v git >/dev/null 2>&1; then
    return 0
  fi
  warn "git is not installed. Trying to install it..."
  pkg_update
  pkg_install git ca-certificates
}

prepare_source_from_git() {
  if [[ "$UPDATE_SOURCE" == "local" ]]; then
    SOURCE_DIR="${SOURCE_DIR:-$SCRIPT_DIR}"
    if [[ ! -f "$SOURCE_DIR/go.mod" ]]; then
      SOURCE_DIR="$SOURCE_CACHE_DIR"
    fi
    info "[1/7] Using local CLI source: $SOURCE_DIR"
  elif [[ "$UPDATE_SOURCE" == "git" ]]; then
    FETCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/conectassh-update.XXXXXXXX")"
    info "[1/7] Fetching CLI source from $REPO_URL..."
    if [[ -n "$UPDATE_REF" ]]; then
      git clone --depth 1 --branch "$UPDATE_REF" "$REPO_URL" "$FETCH_DIR" || error "Git fetch failed; service and installed files were not changed"
    else
      git clone --depth 1 "$REPO_URL" "$FETCH_DIR" || error "Git fetch failed; service and installed files were not changed"
    fi
    SOURCE_DIR="$FETCH_DIR"
  else
    error "UPDATE_SOURCE must be git or local"
  fi
  [[ -f "$SOURCE_DIR/go.mod" && -f "$SOURCE_DIR/conectassh_cli.py" && -f "$SOURCE_DIR/sshplus_backup.py" && -f "$SOURCE_DIR/update.sh" ]] || \
    error "Update source is missing go.mod, conectassh_cli.py, sshplus_backup.py, or update.sh; service was not changed"
}

cleanup_fetch() {
  local rc=$?
  if [[ "$UPDATE_SUCCESS" != "true" ]]; then
    if [[ "$UPDATE_SWAP_DONE" == "true" && -n "$ROLLBACK_BINARY" && -f "$ROLLBACK_BINARY" ]]; then
      warn "Update incompleto: restaurando binario anterior automáticamente."
      local staged="$INSTALL_DIR/.sshpanel.rollback.$$"
      if install -m 0755 "$ROLLBACK_BINARY" "$staged" && mv -f "$staged" "$INSTALL_DIR/sshpanel"; then
        "$SYSTEMCTL_BIN" daemon-reload >/dev/null 2>&1 || true
      else
        warn "No se pudo restaurar automáticamente el binario; respaldo: $ROLLBACK_BINARY"
      fi
    fi
    if [[ "$SERVICE_WAS_ACTIVE" == "true" ]]; then
      "$SYSTEMCTL_BIN" start "$SERVICE_NAME" >/dev/null 2>&1 || \
        warn "El servicio no pudo arrancar durante rollback; revisar journalctl -u $SERVICE_NAME"
    fi
  fi
  if [[ -n "$FETCH_DIR" && -d "$FETCH_DIR" ]]; then
    rm -rf -- "$FETCH_DIR"
  fi
  return "$rc"
}
trap cleanup_fetch EXIT

install_go_if_needed() {
  local go_version machine goarch go_url current_go need_go
  go_version="$(awk '$1 == "go" {print $2; exit}' "$SOURCE_DIR/go.mod" 2>/dev/null || echo "1.22.5")"
  need_go=true

  info "[2/7] Checking Go toolchain..."
  info "  Required Go: $go_version"

  if command -v go >/dev/null 2>&1; then
    current_go="$(go version 2>/dev/null | awk '{print $3}' | sed 's/go//')"
    if [[ "$(printf '%s\n' "$go_version" "$current_go" | sort -V | head -1)" == "$go_version" ]]; then
      info "  Go $current_go already installed."
      need_go=false
    fi
  fi

  if $need_go; then
    machine="$(uname -m)"
    case "$machine" in
      x86_64)  goarch="amd64" ;;
      aarch64) goarch="arm64" ;;
      armv7l)  goarch="armv6l" ;;
      *)       goarch="amd64" ;;
    esac
    go_url="https://go.dev/dl/go${go_version}.linux-${goarch}.tar.gz"
    info "  Downloading Go ${go_version} (${goarch})..."
    need_cmd wget
    wget -q --show-progress -O /tmp/go.tar.gz "$go_url"
    GO_TOOLCHAIN_DIR="${TMPDIR:-/tmp}/conecta-go-${go_version}-$(uname -m)"
    mkdir -p "$GO_TOOLCHAIN_DIR"
    tar -C "$GO_TOOLCHAIN_DIR" --strip-components=1 -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
    export PATH="$GO_TOOLCHAIN_DIR/bin:$PATH"
  fi

  if [[ -x "${GO_TOOLCHAIN_DIR:-}/bin/go" ]]; then export PATH="${GO_TOOLCHAIN_DIR}/bin:$PATH"; elif [[ -x /usr/local/go/bin/go ]]; then export PATH="/usr/local/go/bin:$PATH"; fi
  go version
}

build_binary() {
  info "[3/7] Building new sshpanel binary..."
  cd "$SOURCE_DIR"
  export GOPATH=/tmp/gopath_sshpanel
  export GOCACHE=/tmp/gocache_sshpanel

  BUILD_COMMIT="$(git -C "$SOURCE_DIR" rev-parse HEAD 2>/dev/null || true)"
  BUILD_BRANCH="$(git -C "$SOURCE_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ "$UPDATE_SOURCE" == "local" ]]; then
    BUILD_REPO_URL="$(git -C "$SOURCE_DIR" config --get remote.origin.url 2>/dev/null || true)"
    [[ -n "$BUILD_REPO_URL" ]] || BUILD_REPO_URL="ConectaSSH-PRO local release"
  else
    BUILD_REPO_URL="$REPO_URL"
  fi
  [[ -n "$BUILD_COMMIT" ]] || BUILD_COMMIT="unknown"
  [[ -n "$BUILD_BRANCH" && "$BUILD_BRANCH" != "HEAD" ]] || BUILD_BRANCH="${UPDATE_REF:-unknown}"

  # Do not mutate go.mod/go.sum during an ordinary update.
  go mod download
  go build -ldflags="-s -w -X main.buildCommit=$BUILD_COMMIT -X main.buildBranch=$BUILD_BRANCH -X main.buildTime=$BUILD_TIME" -o /tmp/sshpanel_new .
  info "  Build commit: $BUILD_COMMIT ($BUILD_BRANCH)"
  info "  Build complete."
}

stop_service() {
  info "[4/7] Stopping panel service (never ssh/sshd)..."
  if "$SYSTEMCTL_BIN" is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    SERVICE_WAS_ACTIVE=true
    RESTART_NEEDED=true
    "$SYSTEMCTL_BIN" stop "$SERVICE_NAME"
    info "  $SERVICE_NAME stopped."
  else
    SERVICE_WAS_ACTIVE=false
    RESTART_NEEDED=false
    warn "  $SERVICE_NAME was not running."
  fi
}

copy_optional_script() {
  local name mode staged
  name="$1"
  mode="$2"
  if [[ -f "$SOURCE_DIR/$name" ]]; then
    staged="$(mktemp "$INSTALL_DIR/.${name}.XXXXXX")"
    install -m "$mode" "$SOURCE_DIR/$name" "$staged"
    mv -f "$staged" "$INSTALL_DIR/$name"
    info "  Updated $name"
  fi
}

update_online_web_pro_module() {
  local module_dir="$INSTALL_DIR/online-bridge"
  local source_dir="$SOURCE_DIR/cmd/conecta-online-bridge"
  local tmp_bin="$module_dir/conecta-online-bridge.tmp"
  local had_unit=false
  local was_enabled=false

  [[ -f "$source_dir/main.go" && -f "$source_dir/conecta-online-bridge.service" ]] || return 0

  # Repair the incorrect ownership flag written by older releases only when
  # both the existing binary and unit match the installed product exactly.
  if grep -qx 'OWNED_UNIT_ONLINE_BRIDGE=0' "$INSTALL_DIR/.conecta-install-manifest" &&
     [[ -f /etc/systemd/system/conecta-online-bridge.service &&
        ! -L /etc/systemd/system/conecta-online-bridge.service &&
        -x "$INSTALL_DIR/online-bridge/conecta-online-bridge" ]] &&
     cmp -s "$source_dir/conecta-online-bridge.service" /etc/systemd/system/conecta-online-bridge.service; then
    local manifest_tmp
    manifest_tmp="$(mktemp "$INSTALL_DIR/.conecta-install-manifest.XXXXXX")"
    if sed 's/^OWNED_UNIT_ONLINE_BRIDGE=0$/OWNED_UNIT_ONLINE_BRIDGE=1/' "$INSTALL_DIR/.conecta-install-manifest" > "$manifest_tmp"; then
      chmod 0600 "$manifest_tmp"
      chown root:root "$manifest_tmp"
      mv -f -- "$manifest_tmp" "$INSTALL_DIR/.conecta-install-manifest"
      info "  Repaired verified legacy online-bridge ownership marker."
    else
      rm -f -- "$manifest_tmp"
      warn "  Could not repair bridge ownership marker; leaving bridge untouched."
      return 0
    fi
  fi

  grep -qx 'OWNED_UNIT_ONLINE_BRIDGE=1' "$INSTALL_DIR/.conecta-install-manifest" || { info "Bridge ownership not declared; update leaves it untouched."; return 0; }
  [[ -f /etc/systemd/system/conecta-online-bridge.service ]] || { info "Bridge unit absent; update will not create it."; return 0; }
  had_unit=true
  "$SYSTEMCTL_BIN" is-enabled --quiet conecta-online-bridge.service 2>/dev/null && was_enabled=true

  mkdir -p "$module_dir"
  (cd "$SOURCE_DIR" && go build -trimpath -ldflags="-s -w" -o "$tmp_bin" ./cmd/conecta-online-bridge)
  chmod 0755 "$tmp_bin"
  mv -f "$tmp_bin" "$module_dir/conecta-online-bridge"
  install -m 0644 "$source_dir/conecta-online-bridge.service" /etc/systemd/system/conecta-online-bridge.service
  "$SYSTEMCTL_BIN" daemon-reload

  if $was_enabled; then "$SYSTEMCTL_BIN" enable conecta-online-bridge.service; else "$SYSTEMCTL_BIN" disable conecta-online-bridge.service >/dev/null 2>&1 || true; fi
  info "  MODULO ONLINE WEB PRO updated (existing activation state preserved)."
}




apply_update() {
  info "[5/7] Applying update..."

  mkdir -p "$INSTALL_DIR/logs" "$INSTALL_DIR/certs"

  if [[ -f "$INSTALL_DIR/sshpanel" ]]; then
    ROLLBACK_BINARY="$INSTALL_DIR/sshpanel.rollback.$(date -u +%Y%m%dT%H%M%SZ)"
    cp -p "$INSTALL_DIR/sshpanel" "$ROLLBACK_BINARY"
    cp -p "$INSTALL_DIR/sshpanel" "$INSTALL_DIR/sshpanel.bak"
    info "  Versioned rollback copy: $ROLLBACK_BINARY"
  else
    error "No existe el binario actual; se aborta para no dejar una instalación sin respaldo."
  fi

  # Stage in the same filesystem; atomic rename prevents a partially copied binary.
  local staged="$INSTALL_DIR/.sshpanel.new.$$"
  install -m 0755 /tmp/sshpanel_new "$staged"
  # Set before rename so SIGTERM between rename and the next shell command
  # still triggers restoration from the versioned backup.
  UPDATE_SWAP_DONE=true
  mv -f "$staged" "$INSTALL_DIR/sshpanel"
  info "  Binary atomically replaced."

  printf '%s\n' "$BUILD_COMMIT" > "$INSTALL_DIR/.installed_commit"
  printf '%s\n' "$BUILD_BRANCH" > "$INSTALL_DIR/.installed_branch"
  printf '%s\n' "$BUILD_TIME" > "$INSTALL_DIR/.installed_build_time"
  printf '%s\n' "$BUILD_REPO_URL" > "$INSTALL_DIR/.installed_repo_url"
  chmod 0644 "$INSTALL_DIR/.installed_commit" "$INSTALL_DIR/.installed_branch" "$INSTALL_DIR/.installed_build_time"
  chmod 0600 "$INSTALL_DIR/.installed_repo_url"
  info "  Build metadata updated."

  install -m 700 "$SOURCE_DIR/conectassh_cli.py" "$INSTALL_DIR/conectassh_cli.py"
  install -m 700 "$SOURCE_DIR/sshplus_backup.py" "$INSTALL_DIR/sshplus_backup.py"
  ln -sfn "$INSTALL_DIR/conectassh_cli.py" /usr/local/bin/conectassh
  ln -sfn "$INSTALL_DIR/conectassh_cli.py" /usr/local/bin/conecta

  # The generic /usr/local/bin/menu command is outside this product's ownership; preserve it.

  # CRITICAL SSH SAFETY: updates must never create or re-enable login hooks.
  # Existing disabled hooks remain disabled. CLI stays manual (`conecta`).
  info "  ConectaSSH-PRO CLI updated as conecta; existing menu preserved."

  copy_optional_script "update.sh" 700
  copy_optional_script "install.sh" 700
  copy_optional_script "uninstall.sh" 700

  # Keep a local copy of the latest source for easier support and future updates.
  if [[ "$SOURCE_DIR" != "$SOURCE_CACHE_DIR" ]]; then
    mkdir -p "$SOURCE_CACHE_DIR"
    rsync -a --exclude '.git' "$SOURCE_DIR/" "$SOURCE_CACHE_DIR/"
    info "  Source files copied to $SOURCE_CACHE_DIR"
  fi

  update_online_web_pro_module

  [[ -f "$INSTALL_DIR/banner.txt" ]] || touch "$INSTALL_DIR/banner.txt"
}

patch_configs() {
  info "[6/7] Patching config files without overwriting user settings..."

  local cfg xcfg
  cfg="$INSTALL_DIR/config.json"
  xcfg="$INSTALL_DIR/xray_config.json"

  native_xcfg="$INSTALL_DIR/xray_native_config.json"
  if [[ ! -f "$native_xcfg" && -f "$xcfg" ]]; then
    cp -f "$xcfg" "$native_xcfg"
    chmod 600 "$native_xcfg" || true
    info "  Created independent native Xray config: $native_xcfg"
  fi

  if [[ -f "$cfg" ]]; then
    python3 - "$cfg" <<'PYEOF'
import ipaddress, json, sys
path = sys.argv[1]
try:
    with open(path) as f:
        d = json.load(f)
except Exception as e:
    print(f"[!] Could not parse {path}: {e}")
    sys.exit(0)
changed = False
if 'banner_file' not in d:
    d['banner_file'] = '/opt/sshpanel/banner.txt'
    changed = True
local_ssh = str(d.get('local_ssh_listen') or '').strip()
local_ssh_valid = False
try:
    if local_ssh.startswith('['):
        end = local_ssh.index(']')
        host = local_ssh[1:end]
        if local_ssh[end + 1:end + 2] != ':':
            raise ValueError('missing port')
        port = int(local_ssh[end + 2:])
    else:
        host, port_text = local_ssh.rsplit(':', 1)
        port = int(port_text)
    local_ssh_valid = ipaddress.ip_address(host).is_loopback and 1 <= port <= 65535
except (ValueError, IndexError):
    pass
if not local_ssh_valid:
    d['local_ssh_listen'] = '127.0.0.1:2222'
    changed = True
x = d.get('xray')
if isinstance(x, dict):
    mode = str(x.get('mode') or '').strip().lower()
    if mode not in ('native', 'external'):
        x['mode'] = 'native'
        x['native'] = True
        changed = True
    elif mode == 'native' and x.get('native') is not True:
        x['native'] = True
        changed = True
    elif mode == 'external' and x.get('native') is not False:
        x['native'] = False
        changed = True
    x.setdefault('bin_path', '/opt/sshpanel/xray')
    x.setdefault('config_file', '/opt/sshpanel/xray_config.json')
    x.setdefault('native_config_file', '/opt/sshpanel/xray_native_config.json')
if changed:
    with open(path, 'w') as f:
        json.dump(d, f, indent=2)
        f.write('\n')
PYEOF
    info "  config.json checked."
  fi

  if [[ -f "$xcfg" ]] && grep -q '"geoip:private"' "$xcfg" 2>/dev/null; then
    python3 - "$xcfg" <<'PYEOF'
import json, sys
path = sys.argv[1]
try:
    with open(path) as f:
        d = json.load(f)
except Exception as e:
    print(f"[!] Could not parse {path}: {e}")
    sys.exit(0)
routing = d.get('routing', {})
rules = routing.get('rules', [])
new_rules = [r for r in rules if 'geoip:private' not in r.get('ip', [])]
if new_rules != rules:
    if new_rules:
        d.setdefault('routing', {})['rules'] = new_rules
    else:
        d.pop('routing', None)
    with open(path, 'w') as f:
        json.dump(d, f, indent=2)
        f.write('\n')
PYEOF
    info "  Removed geoip:private routing rule from xray_config.json"
  fi
}

# Standard update never changes DNSTT, DNS, firewall, NAT rules or auxiliary redirect units.

restart_service() {
  info "[7/7] Restarting service..."

  if $RESTART_NEEDED; then
    info "  Starting $SERVICE_NAME after update..."
  else
    warn "  $SERVICE_NAME was not running before update; starting it now."
  fi

  if ! "$SYSTEMCTL_BIN" start "$SERVICE_NAME"; then
    error "$SERVICE_NAME could not start. Restore $INSTALL_DIR/sshpanel.bak and inspect journalctl -u $SERVICE_NAME"
  fi
  sleep 2
  if "$SYSTEMCTL_BIN" is-active --quiet "$SERVICE_NAME"; then
    info "  $SERVICE_NAME is running."
  else
    warn "  $SERVICE_NAME failed to start. Check logs:"
    warn "    journalctl -u $SERVICE_NAME -n 50 --no-pager"
    if [[ -f "$INSTALL_DIR/sshpanel.bak" ]]; then
      warn "  Restore command:"
      warn "    cp $INSTALL_DIR/sshpanel.bak $INSTALL_DIR/sshpanel && systemctl start $SERVICE_NAME"
    fi
    error "$SERVICE_NAME is not running after the update"
    exit 1
  fi
}

# Pre-flight
info "[0/7] Pre-flight checks..."
require_systemd
[[ -d "$INSTALL_DIR" ]] || error "Install dir $INSTALL_DIR not found. Run install.sh first."
[[ -f "$INSTALL_DIR/.conecta-install-manifest" ]] || error "Ownership manifest missing; refusing to update an unverified directory."
grep -qx 'PRODUCT=ConectaSSH-PRO' "$INSTALL_DIR/.conecta-install-manifest" || error "Ownership manifest not recognized; refusing update."
if grep -q '^STATE=' "$INSTALL_DIR/.conecta-install-manifest"; then
  grep -qx 'STATE=installed' "$INSTALL_DIR/.conecta-install-manifest" || error "Installation state is not committed; recover/reinstall before updating."
fi
[[ -f "$INSTALL_DIR/sshpanel" && -f "$INSTALL_DIR/.env" ]] || error "Installation incomplete; refusing in-place update without binary and .env."
for cli_path in /usr/local/bin/conecta /usr/local/bin/conectassh; do
  if [[ -e "$cli_path" || -L "$cli_path" ]]; then
    [[ -L "$cli_path" && "$(readlink -f "$cli_path" 2>/dev/null || true)" == "$INSTALL_DIR/conectassh_cli.py" ]] || error "CLI ajeno detectado en $cli_path; se conserva y no se actualiza."
  fi
done
detect_pkg_manager
set_update_deps
ensure_update_dependencies
need_cmd python3
need_cmd rsync
need_cmd wget

info "  Install dir      : $INSTALL_DIR"
info "  Cache dir        : $SOURCE_CACHE_DIR"
info "  Update source    : $UPDATE_SOURCE"
info "  Package manager  : $PKG_MANAGER"
info "  Service manager  : systemd"

prepare_source_from_git
install_go_if_needed
build_binary
stop_service
apply_update
patch_configs
restart_service

echo ""
echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}   Update complete!                        ${NC}"
echo -e "${GREEN}==========================================${NC}"
echo ""
echo -e "  Updated from: ${YELLOW}${REPO_URL}${NC}"
echo -e "  Source ref  : ${YELLOW}${BUILD_BRANCH} (${BUILD_COMMIT})${NC}"
echo -e "  Source cache: ${YELLOW}${SOURCE_CACHE_DIR}${NC}"
echo -e "  Logs        : ${YELLOW}journalctl -u ${SERVICE_NAME} -f${NC}"
echo -e "                ${YELLOW}tail -f ${INSTALL_DIR}/logs/panel.log${NC}"
echo -e "  Backup      : ${YELLOW}${INSTALL_DIR}/sshpanel.bak${NC}"
echo ""
echo -e "${YELLOW}Updated:${NC}"
echo -e "  - sshpanel binary"
echo -e "  - ConectaSSH-PRO CLI and API"
echo -e "  - update.sh / install.sh / helper scripts when available"
echo ""
echo -e "${YELLOW}Preserved:${NC}"
echo -e "  - .env"
echo -e "  - config.json"
echo -e "  - xray_config.json"
echo -e "  - SSH keys, certs, logs, database and users"
echo ""

# Mark transaction committed so the EXIT trap will not roll back.
UPDATE_SUCCESS=true
