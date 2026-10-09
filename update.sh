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
BUILD_COMMIT=""
BUILD_BRANCH=""
BUILD_TIME=""
BUILD_REPO_URL=""

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash $0"

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
  [[ -f "$SOURCE_DIR/go.mod" && -f "$SOURCE_DIR/conectassh_cli.py" && -f "$SOURCE_DIR/update.sh" ]] || \
    error "Update source is missing go.mod, conectassh_cli.py, or update.sh; service was not changed"
}

cleanup_fetch() {
  if [[ -n "$FETCH_DIR" && -d "$FETCH_DIR" ]]; then
    rm -rf -- "$FETCH_DIR"
  fi
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
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
    chmod +x /etc/profile.d/go.sh
  fi

  export PATH=$PATH:/usr/local/go/bin
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

  go mod download
  go mod tidy
  go build -ldflags="-s -w -X main.buildCommit=$BUILD_COMMIT -X main.buildBranch=$BUILD_BRANCH -X main.buildTime=$BUILD_TIME" -o /tmp/sshpanel_new .
  info "  Build commit: $BUILD_COMMIT ($BUILD_BRANCH)"
  info "  Build complete."
}

stop_service() {
  info "[4/7] Stopping service..."
  if "$SYSTEMCTL_BIN" is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    "$SYSTEMCTL_BIN" stop "$SERVICE_NAME"
    RESTART_NEEDED=true
    info "  $SERVICE_NAME stopped."
  else
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

  [[ -f /etc/systemd/system/conecta-online-bridge.service ]] && had_unit=true
  "$SYSTEMCTL_BIN" is-enabled --quiet conecta-online-bridge.service 2>/dev/null && was_enabled=true

  mkdir -p "$module_dir"
  (cd "$SOURCE_DIR" && go build -trimpath -ldflags="-s -w" -o "$tmp_bin" ./cmd/conecta-online-bridge)
  chmod 0755 "$tmp_bin"
  mv -f "$tmp_bin" "$module_dir/conecta-online-bridge"
  install -m 0644 "$source_dir/conecta-online-bridge.service" /etc/systemd/system/conecta-online-bridge.service
  "$SYSTEMCTL_BIN" daemon-reload

  if $was_enabled || ! $had_unit; then
    "$SYSTEMCTL_BIN" enable --now conecta-online-bridge.service
  else
    "$SYSTEMCTL_BIN" disable --now conecta-online-bridge.service >/dev/null 2>&1 || true
  fi
  info "  MODULO ONLINE WEB PRO updated (existing activation state preserved)."
}


apply_update() {
  info "[5/7] Applying update..."

  mkdir -p "$INSTALL_DIR/logs" "$INSTALL_DIR/certs"
  ensure_log_tmpfs_mount

  if [[ -f "$INSTALL_DIR/sshpanel" ]]; then
    cp "$INSTALL_DIR/sshpanel" "$INSTALL_DIR/sshpanel.bak"
    info "  Old binary backed up to $INSTALL_DIR/sshpanel.bak"
  fi

  mv /tmp/sshpanel_new "$INSTALL_DIR/sshpanel"
  chmod 755 "$INSTALL_DIR/sshpanel"
  info "  Binary updated."

  printf '%s\n' "$BUILD_COMMIT" > "$INSTALL_DIR/.installed_commit"
  printf '%s\n' "$BUILD_BRANCH" > "$INSTALL_DIR/.installed_branch"
  printf '%s\n' "$BUILD_TIME" > "$INSTALL_DIR/.installed_build_time"
  printf '%s\n' "$BUILD_REPO_URL" > "$INSTALL_DIR/.installed_repo_url"
  chmod 0644 "$INSTALL_DIR/.installed_commit" "$INSTALL_DIR/.installed_branch" "$INSTALL_DIR/.installed_build_time"
  chmod 0600 "$INSTALL_DIR/.installed_repo_url"
  info "  Build metadata updated."

  install -m 700 "$SOURCE_DIR/conectassh_cli.py" "$INSTALL_DIR/conectassh_cli.py"
  ln -sfn "$INSTALL_DIR/conectassh_cli.py" /usr/local/bin/conectassh
  if [[ ( -e /usr/local/bin/conecta || -L /usr/local/bin/conecta ) && "$(readlink -f /usr/local/bin/conecta 2>/dev/null || true)" != "$INSTALL_DIR/conectassh_cli.py" ]]; then
    CONECTA_BACKUP="/usr/local/bin/conecta.backup.$(date +%s%N)"
    mv /usr/local/bin/conecta "$CONECTA_BACKUP"
    warn "  Previous conecta command saved to $CONECTA_BACKUP"
  fi
  ln -sfn "$INSTALL_DIR/conectassh_cli.py" /usr/local/bin/conecta

  # Compatibility repair for releases that previously hijacked the generic menu command.
  if [[ -L /usr/local/bin/menu ]] && [[ "$(readlink -f /usr/local/bin/menu 2>/dev/null || true)" == "$INSTALL_DIR/conectassh_cli.py" ]]; then
    mkdir -p "$INSTALL_DIR/compat-backups"
    mv /usr/local/bin/menu "$INSTALL_DIR/compat-backups/menu-conectassh-disabled.$(date +%s%N)"
    MENU_BACKUP="$(find /usr/local/bin -maxdepth 1 \( -name "menu.backup.*" -type f -o -name "menu.backup.*" -type l \) 2>/dev/null | sort | tail -n 1)"
    if [[ -n "$MENU_BACKUP" ]]; then
      mv "$MENU_BACKUP" /usr/local/bin/menu
      warn "  Restored the previous menu command."
    else
      warn "  Removed the ConectaSSH-PRO menu override; no legacy menu backup was found."
    fi
  fi

  # Disable old login hook without deleting it; keep it for audit/recovery.
  if [[ -f /etc/profile.d/conecta-auto-menu.sh ]]; then
    mkdir -p "$INSTALL_DIR/compat-backups"
    mv /etc/profile.d/conecta-auto-menu.sh "$INSTALL_DIR/compat-backups/conecta-auto-menu.sh.disabled.$(date +%s%N)"
    warn "  Disabled the legacy automatic SSH-login menu hook."
  fi
  info "  ConectaSSH-PRO CLI updated as conecta; existing menu preserved."

  copy_optional_script "update.sh" 700
  copy_optional_script "install.sh" 700

  # Keep a local copy of the latest source for easier support and future updates.
  if [[ "$SOURCE_DIR" != "$SOURCE_CACHE_DIR" ]]; then
    mkdir -p "$SOURCE_CACHE_DIR"
    rsync -a --delete --exclude '.git' "$SOURCE_DIR/" "$SOURCE_CACHE_DIR/"
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
# Automatic menus on SSH login are intentionally disabled to protect admin shells.
if d.get('auto_menu') is not False:
    d['auto_menu'] = False
    changed = True
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

dnstt_redirect_is_enabled() {
  # Updates must not resurrect this service when an admin intentionally
  # disabled/removed it because it can break ip6tables on some machines.
  local unit="sshpanel-dnstt-redirect.service"

  if "$SYSTEMCTL_BIN" is-enabled --quiet "$unit" 2>/dev/null; then
    return 0
  fi

  return 1
}

write_sshpanel_systemd_override() {
  local include_dnstt_redirect="${1:-false}"

  mkdir -p /etc/systemd/system/sshpanel.service.d
  {
    echo "[Unit]"
    if [[ "$include_dnstt_redirect" == "true" ]]; then
      echo "Wants=sshpanel-dnstt-redirect.service"
      echo "After=local-fs.target sshpanel-dnstt-redirect.service"
    else
      echo "After=local-fs.target"
    fi
    echo
    echo "[Service]"
    echo "Environment=PANEL_LOG_FILE=${INSTALL_DIR}/logs/panel.log"
    echo "Environment=PANEL_LOG_MAX_BYTES=${PANEL_LOG_MAX_BYTES}"
    echo "LimitNOFILE=1048576"
    echo "ExecStartPre="
    echo "ExecStartPre=${MKDIR_BIN} -p ${INSTALL_DIR}/logs"
    echo "ExecStartPre=${SH_BIN} -c '${MOUNTPOINT_BIN} -q ${INSTALL_DIR}/logs || ${MOUNT_BIN} -t tmpfs -o size=${LOG_TMPFS_SIZE},mode=0755 tmpfs ${INSTALL_DIR}/logs || true'"
    echo "ExecStartPre=${SH_BIN} -c '${TOUCH_BIN} ${INSTALL_DIR}/logs/panel.log && ${CHMOD_BIN} 0644 ${INSTALL_DIR}/logs/panel.log || true'"
    echo "StandardOutput=journal"
    echo "StandardError=journal"
  } > /etc/systemd/system/sshpanel.service.d/override.conf
}

ensure_dnstt_redirect() {
  if ! dnstt_redirect_is_enabled; then
    warn "  sshpanel-dnstt-redirect is disabled or removed; update will not recreate or enable it."
    write_sshpanel_systemd_override false
    "$SYSTEMCTL_BIN" daemon-reload
    return 0
  fi

  info "  Ensuring DNSTT DNS redirect service exists..."
  cat > /usr/local/sbin/sshpanel-dnstt-redirect.sh <<'EOS'
#!/bin/bash
set -euo pipefail
DNS_UPSTREAM="${DNS_UPSTREAM:-1.1.1.1}"
DNSTT_PORT="${DNSTT_PORT:-5300}"

if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now systemd-resolved.service >/dev/null 2>&1 || true
fi
rm -f /etc/resolv.conf
printf 'nameserver %s\n' "$DNS_UPSTREAM" > /etc/resolv.conf

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
if ! command -v iptables >/dev/null 2>&1 && command -v nft >/dev/null 2>&1; then
  nft add table inet sshpanel_nat 2>/dev/null || true
  nft 'add chain inet sshpanel_nat prerouting { type nat hook prerouting priority dstnat; policy accept; }' 2>/dev/null || true
  nft list chain inet sshpanel_nat prerouting 2>/dev/null | grep -q "udp dport 53 redirect to :$DNSTT_PORT" \
    || nft add rule inet sshpanel_nat prerouting udp dport 53 redirect to :"$DNSTT_PORT"
fi
EOS
  chmod +x /usr/local/sbin/sshpanel-dnstt-redirect.sh

  cat > /etc/systemd/system/sshpanel-dnstt-redirect.service <<'EOF2'
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
EOF2

  write_sshpanel_systemd_override true

  "$SYSTEMCTL_BIN" daemon-reload
  "$SYSTEMCTL_BIN" enable --now sshpanel-dnstt-redirect.service || warn "DNSTT redirect service failed. Check: journalctl -u sshpanel-dnstt-redirect -e"
}

restart_service() {
  info "[7/7] Restarting service..."
  ensure_dnstt_redirect

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
detect_pkg_manager
set_update_deps
ensure_update_dependencies
[[ -d "$INSTALL_DIR" ]] || error "Install dir $INSTALL_DIR not found. Run install.sh first."
[[ -f "$INSTALL_DIR/.env" ]] || error "$INSTALL_DIR/.env not found. Run install.sh first."
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
