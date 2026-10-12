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
MANIFEST_VERSION=3
INSTALL_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
STATE_DIR="/var/lib/conecta-ssh-pro"
TXN_MANIFEST="$STATE_DIR/manifest"
RESOURCE_LEDGER="$STATE_DIR/resources.tsv"
INSTALL_DIR_CREATED=0
DB_CREATED_BY_CONECTA=0
DB_ROLE_CREATED_BY_CONECTA=0
OWNED_UNIT_ONLINE_BRIDGE=0
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
  local port ssh_port=""
  ssh_port="$(detect_active_ssh_port)" || error "No se pudo detectar el puerto SSH activo. Se aborta por seguridad."
  for port in "${REQUIRED_TCP_PORTS[@]}"; do
    if [[ "$port" == "$ssh_port" ]]; then
      error "Conflicto crítico: SSH utiliza TCP ${ssh_port}, que también requiere Conecta. No se instalará para evitar cortar el acceso remoto."
    fi
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

write_transaction_manifest() {
  local state="$1" tmp="$STATE_DIR/manifest.tmp"
  install -d -m 0700 "$STATE_DIR"
  cat > "$tmp" <<EOF
PRODUCT=ConectaSSH-PRO
MANIFEST_VERSION=3
INSTALL_ID=$INSTALL_ID
STATE=$state
INSTALL_DIR=/opt/sshpanel
ROLLBACK_DIR=$ROLLBACK_DIR
INSTALL_DIR_CREATED=$INSTALL_DIR_CREATED
DB_NAME=sshpanel
DB_USER=sshpanel
DB_CREATED_BY_CONECTA=$DB_CREATED_BY_CONECTA
DB_ROLE_CREATED_BY_CONECTA=$DB_ROLE_CREATED_BY_CONECTA
OWNED_UNIT_SSH_PANEL=1
OWNED_UNIT_ONLINE_BRIDGE=${OWNED_UNIT_ONLINE_BRIDGE:-0}
OWNED_UNIT_DNSTT_REDIRECT=0
OWNED_PATH_INSTALL_DIR=1
OWNED_PATH_LOG_TMPFS=1
OWNED_PATH_CLI_CONECTA=1
OWNED_PATH_CLI_CONECTASSH=1
FIREWALL_RULES_CREATED=0
NETWORK_CONFIGURATION_CHANGED=0
EOF
  chmod 0600 "$tmp"
  mv -f -- "$tmp" "$TXN_MANIFEST"
}
register_resource() {
  local kind="$1" path="$2" target="${3:-}"
  printf '%s\t%s\t%s\n' "$kind" "$path" "$target" >> "$RESOURCE_LEDGER"
  chmod 0600 "$RESOURCE_LEDGER"
}
resource_path_is_allowed() {
  case "$1" in
    /opt/sshpanel|/etc/systemd/system/sshpanel.service|/etc/systemd/system/conecta-online-bridge.service|/etc/systemd/system/multi-user.target.wants/sshpanel.service|/usr/local/bin/conecta|/usr/local/bin/conectassh|sshpanel) return 0 ;;
    *) return 1 ;;
  esac
}
rollback_transaction_resources() {
  [[ -f "$TXN_MANIFEST" ]] || return 0
  local product state kind path target install_id
  product="$(awk -F= '$1=="PRODUCT"{print substr($0,index($0,"=")+1);exit}' "$TXN_MANIFEST")"
  install_id="$(awk -F= '$1=="INSTALL_ID"{print $2;exit}' "$TXN_MANIFEST")"
  [[ -n "$install_id" ]] || install_id="unknown"
  [[ "$product" == "ConectaSSH-PRO" ]] || { warn "Manifiesto transaccional ajeno; se conserva."; return 1; }
  state="$(awk -F= '$1=="STATE"{print $2;exit}' "$TXN_MANIFEST")"
  [[ "$state" == "installing" || "$state" == "rollback_pending" ]] || return 0
  write_transaction_manifest rollback_pending
  if [[ -f "$RESOURCE_LEDGER" ]]; then
    while IFS=$'\t' read -r kind path target; do
      [[ -n "$path" ]] || continue
      resource_path_is_allowed "$path" || { warn "Ruta fuera de allowlist en ledger: $path; rollback pendiente."; return 1; }
      case "$kind" in
        unit)
          local unit_name=""
          if [[ "$path" == "/etc/systemd/system/sshpanel.service" && -f "$path" && ! -L "$path" ]] &&
             grep -q 'WorkingDirectory=/opt/sshpanel' "$path" 2>/dev/null &&
             grep -q 'ExecStart=/opt/sshpanel/sshpanel' "$path" 2>/dev/null; then
            unit_name="sshpanel.service"
          elif [[ "$path" == "/etc/systemd/system/conecta-online-bridge.service" && -f "$path" && ! -L "$path" ]] &&
               grep -q 'ExecStart=/opt/sshpanel/online-bridge/conecta-online-bridge' "$path" 2>/dev/null; then
            unit_name="conecta-online-bridge.service"
          elif [[ -e "$path" || -L "$path" ]]; then
            warn "Unidad conservada; propiedad no demostrada: $path; rollback pendiente."
            return 1
          fi
          if [[ -n "$unit_name" ]]; then
            systemctl disable --now "$unit_name" >/dev/null 2>&1 || { warn "No se pudo detener $unit_name; rollback pendiente y datos conservados."; return 1; }
            rm -f -- "$path" || { warn "No se pudo retirar la unidad propia; rollback pendiente."; return 1; }
          fi ;;
        symlink)
          if [[ -L "$path" && "$(readlink "$path" 2>/dev/null || true)" == "$target" ]]; then
            rm -f -- "$path" || { warn "No se pudo retirar el enlace propio: $path"; return 1; }
          elif [[ -e "$path" || -L "$path" ]]; then warn "Enlace conservado; propiedad no demostrada: $path; rollback pendiente."; return 1; fi ;;
        directory)
          if [[ "$path" == "/opt/sshpanel" && "$INSTALL_DIR_CREATED" == "1" && -d "$path" && ! -L "$path" ]]; then
            python3 - "$path" <<'PY' || { warn "No se pudo retirar el directorio propio; rollback pendiente."; return 1; }
from pathlib import Path
import shutil,sys
p=Path(sys.argv[1])
if str(p)=="/opt/sshpanel" and not p.is_symlink(): shutil.rmtree(p)
PY
          elif [[ -e "$path" || -L "$path" ]]; then warn "Ruta de instalación no coincide con el directorio propio; se conserva."; return 1; fi ;;
        postgres_database)
          if [[ "$DB_CREATED_BY_CONECTA" == "1" ]] && command -v psql >/dev/null 2>&1 && id postgres >/dev/null 2>&1; then
            comment="$(su - postgres -c "psql -tAc \"SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname='sshpanel'\"" 2>/dev/null | tr -d '\r' || true)"
            if [[ "$comment" == "conecta-ssh-pro:$install_id" ]]; then su - postgres -c "dropdb --if-exists sshpanel" >/dev/null 2>&1 || { warn "No se pudo revertir la base de datos propia; rollback pendiente."; return 1; }; else warn "Base de datos conservada: propiedad no demostrada por comentario."; fi
          fi ;;
        postgres_role)
          if [[ "$DB_ROLE_CREATED_BY_CONECTA" == "1" ]] && command -v psql >/dev/null 2>&1 && id postgres >/dev/null 2>&1; then
            comment="$(su - postgres -c "psql -tAc \"SELECT shobj_description(oid, 'pg_authid') FROM pg_authid WHERE rolname='sshpanel'\"" 2>/dev/null | tr -d '\r' || true)"
            if [[ "$comment" == "conecta-ssh-pro:$install_id" ]]; then su - postgres -c "dropuser --if-exists sshpanel" >/dev/null 2>&1 || { warn "No se pudo revertir el rol propio; rollback pendiente."; return 1; }; else warn "Rol PostgreSQL conservado: propiedad no demostrada por comentario."; fi
          fi ;;
      esac
    done < <(tac "$RESOURCE_LEDGER")
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
  write_transaction_manifest rolled_back
  rm -f -- "$RESOURCE_LEDGER"
}
recover_previous_transaction() {
  [[ -f "$TXN_MANIFEST" && ! -L "$TXN_MANIFEST" ]] || return 0
  [[ "$(stat -c '%u' "$TXN_MANIFEST" 2>/dev/null || true)" == "0" ]] || { warn "Manifiesto transaccional no pertenece a root; se conserva."; return 0; }
  local manifest_mode
  manifest_mode="$(stat -c '%a' "$TXN_MANIFEST" 2>/dev/null || echo 777)"
  (( (8#$manifest_mode & 077) == 0 )) || { warn "Permisos inseguros en manifiesto transaccional; se conserva."; return 0; }
  if [[ -e "$RESOURCE_LEDGER" || -L "$RESOURCE_LEDGER" ]]; then
    [[ -f "$RESOURCE_LEDGER" && ! -L "$RESOURCE_LEDGER" && "$(stat -c '%u' "$RESOURCE_LEDGER" 2>/dev/null || true)" == "0" ]] || { warn "Ledger de recursos no verificable; se conserva."; return 0; }
    local ledger_mode
    ledger_mode="$(stat -c '%a' "$RESOURCE_LEDGER" 2>/dev/null || echo 777)"
    (( (8#$ledger_mode & 077) == 0 )) || { warn "Permisos inseguros en ledger; se conserva."; return 0; }
  fi
  local product state
  product="$(awk -F= '$1=="PRODUCT"{print substr($0,index($0,"=")+1);exit}' "$TXN_MANIFEST")"
  state="$(awk -F= '$1=="STATE"{print $2;exit}' "$TXN_MANIFEST")"
  [[ "$product" == "ConectaSSH-PRO" ]] || { warn "Manifiesto previo no reconocido; no se modifica."; return 0; }
  case "$state" in
    installing|rollback_pending)
      INSTALL_ID="$(awk -F= '$1=="INSTALL_ID"{print $2;exit}' "$TXN_MANIFEST")"
      [[ "$INSTALL_ID" =~ ^[A-Za-z0-9._-]+$ ]] || { warn "INSTALL_ID inválido; no se modifica el estado anterior."; return 0; }
      ROLLBACK_DIR="$(awk -F= '$1=="ROLLBACK_DIR"{print $2;exit}' "$TXN_MANIFEST")"
      if [[ -n "$ROLLBACK_DIR" && "$ROLLBACK_DIR" != /var/tmp/sshpanel-rollback.* ]]; then warn "Ruta de snapshot inválida; no se restaura ni elimina."; ROLLBACK_DIR=""; fi
      INSTALL_DIR_CREATED="$(awk -F= '$1=="INSTALL_DIR_CREATED"{print $2;exit}' "$TXN_MANIFEST")"
      [[ "$INSTALL_DIR_CREATED" == "1" ]] || INSTALL_DIR_CREATED=0
      DB_CREATED_BY_CONECTA="$(awk -F= '$1=="DB_CREATED_BY_CONECTA"{print $2;exit}' "$TXN_MANIFEST")"
      [[ "$DB_CREATED_BY_CONECTA" == "1" ]] || DB_CREATED_BY_CONECTA=0
      DB_ROLE_CREATED_BY_CONECTA="$(awk -F= '$1=="DB_ROLE_CREATED_BY_CONECTA"{print $2;exit}' "$TXN_MANIFEST")"
      [[ "$DB_ROLE_CREATED_BY_CONECTA" == "1" ]] || DB_ROLE_CREATED_BY_CONECTA=0
      warn "Se detectó una instalación interrumpida ($state). Recuperando únicamente recursos registrados..."
      rollback_transaction_resources || error "No se pudo recuperar el estado previo de forma segura."
      restore_rollback_snapshot
      if [[ -n "$ROLLBACK_DIR" && -d "$ROLLBACK_DIR" ]]; then rm -rf -- "$ROLLBACK_DIR"; fi
      ROLLBACK_DIR=""
      INSTALL_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
      INSTALL_DIR_CREATED=0
      DB_CREATED_BY_CONECTA=0
      DB_ROLE_CREATED_BY_CONECTA=0 ;;
    rolled_back|installed|uninstalled|preserved) ;;
    *) warn "Estado transaccional desconocido ($state); se conserva para revisión." ;;
  esac
}

recover_corrupt_install() {
  [[ -e "$INSTALL_DIR" || -L "$INSTALL_DIR" ]] || return 0
  [[ -d "$INSTALL_DIR" && ! -L "$INSTALL_DIR" ]] || return 0
  local marker_owned=false unit_path="/etc/systemd/system/sshpanel.service"
  if [[ -f "$INSTALL_DIR/.conecta-install-manifest" && ! -L "$INSTALL_DIR/.conecta-install-manifest" ]] &&
     [[ "$(stat -c '%u' "$INSTALL_DIR/.conecta-install-manifest" 2>/dev/null || true)" == "0" ]] &&
     (( (8#$(stat -c '%a' "$INSTALL_DIR/.conecta-install-manifest" 2>/dev/null || echo 777) & 077) == 0 )) &&
     grep -qx 'PRODUCT=ConectaSSH-PRO' "$INSTALL_DIR/.conecta-install-manifest"; then
    marker_owned=true
  elif [[ -f "$TXN_MANIFEST" && ! -L "$TXN_MANIFEST" && -f "$RESOURCE_LEDGER" && ! -L "$RESOURCE_LEDGER" ]] &&
       [[ "$(stat -c '%u' "$TXN_MANIFEST" 2>/dev/null || true)" == "0" ]] &&
       [[ "$(stat -c '%u' "$RESOURCE_LEDGER" 2>/dev/null || true)" == "0" ]] &&
       grep -qx 'PRODUCT=ConectaSSH-PRO' "$TXN_MANIFEST" &&
       grep -qx $'directory\t/opt/sshpanel\t' "$RESOURCE_LEDGER" &&
       grep -qx 'STATE=installed' "$TXN_MANIFEST"; then
    marker_owned=true
  fi
  $marker_owned || return 0

  if [[ -x "$INSTALL_DIR/sshpanel" && -f "$unit_path" && ! -L "$unit_path" ]] &&
     grep -q 'WorkingDirectory=/opt/sshpanel' "$unit_path" &&
     grep -q 'ExecStart=/opt/sshpanel/sshpanel' "$unit_path"; then
    return 0
  fi

  if [[ -e "$unit_path" || -L "$unit_path" ]]; then
    [[ -f "$unit_path" && ! -L "$unit_path" ]] &&
      grep -q 'WorkingDirectory=/opt/sshpanel' "$unit_path" &&
      grep -q 'ExecStart=/opt/sshpanel/sshpanel' "$unit_path" ||
      error "Instalación corrupta, pero la unidad sshpanel.service no tiene propiedad demostrable; se conserva todo."
    systemctl disable --now sshpanel.service >/dev/null 2>&1 ||
      error "No se pudo detener la unidad propia; se conserva la instalación para recuperación."
    rm -f -- "$unit_path"
  elif systemctl is-active --quiet sshpanel.service 2>/dev/null; then
    error "sshpanel.service está activo sin una unidad propia verificable; no se altera."
  fi

  for cli_path in /usr/local/bin/conecta /usr/local/bin/conectassh; do
    if [[ -L "$cli_path" && "$(readlink -f "$cli_path" 2>/dev/null || true)" == "$INSTALL_DIR/conectassh_cli.py" ]]; then
      rm -f -- "$cli_path"
    elif [[ -e "$cli_path" || -L "$cli_path" ]]; then
      error "Instalación corrupta; se conserva todo porque $cli_path no coincide con el enlace propio."
    fi
  done

  local recovery="/opt/sshpanel.recovery.$(date -u +%Y%m%dT%H%M%SZ)"
  [[ ! -e "$recovery" && ! -L "$recovery" ]] || error "Destino de recuperación existente: $recovery"
  mv -- "$INSTALL_DIR" "$recovery"
  if [[ -f "$TXN_MANIFEST" && "$(stat -c '%u' "$TXN_MANIFEST" 2>/dev/null || true)" == "0" ]]; then
    local tmp="$TXN_MANIFEST.tmp"
    sed -e 's/^STATE=.*/STATE=preserved/' -e 's/^INSTALL_DIR_CREATED=.*/INSTALL_DIR_CREATED=0/' "$TXN_MANIFEST" > "$tmp"
    chmod 0600 "$tmp"
    mv -f -- "$tmp" "$TXN_MANIFEST"
  fi
  rm -f -- "$RESOURCE_LEDGER"
  systemctl daemon-reload >/dev/null 2>&1 || true
  warn "Instalación corrupta recuperada sin purgar datos. Configuración y credenciales preservadas en $recovery"
  warn "La base de datos PostgreSQL se conserva; no se eliminan usuarios ni datos existentes."
}

preflight_checks() {
  info "[PRECHECK] Validando entorno..."
  [[ "$EUID" -eq 0 ]] || error "El instalador debe ejecutarse como root."
  require_systemd
  command -v ss >/dev/null 2>&1 || error "El comando ss es obligatorio para proteger SSH."
  ssh_safety_preflight
  recover_previous_transaction
  recover_corrupt_install
  case "$(uname -m)" in x86_64|aarch64) ;; *) error "Arquitectura no soportada: $(uname -m)." ;; esac
  if [[ -e "$INSTALL_DIR" || -L "$INSTALL_DIR" ]]; then
    if [[ -d "$INSTALL_DIR" && ! -L "$INSTALL_DIR" && -f "$INSTALL_DIR/.conecta-install-manifest" && ! -L "$INSTALL_DIR/.conecta-install-manifest" ]] &&
       [[ "$(stat -c '%u' "$INSTALL_DIR/.conecta-install-manifest" 2>/dev/null || true)" == "0" ]] &&
       (( (8#$(stat -c '%a' "$INSTALL_DIR/.conecta-install-manifest" 2>/dev/null || echo 777) & 077) == 0 )) &&
       grep -qx 'PRODUCT=ConectaSSH-PRO' "$INSTALL_DIR/.conecta-install-manifest" &&
       grep -qx 'STATE=installed' "$INSTALL_DIR/.conecta-install-manifest" &&
       [[ -x "$INSTALL_DIR/sshpanel" && -f "/etc/systemd/system/${SERVICE_NAME}.service" ]] &&
       grep -q 'WorkingDirectory=/opt/sshpanel' "/etc/systemd/system/${SERVICE_NAME}.service" &&
       grep -q 'ExecStart=/opt/sshpanel/sshpanel' "/etc/systemd/system/${SERVICE_NAME}.service"; then
      info "Instalación válida detectada: se ejecutará el actualizador idempotente en lugar de abortar o recrear PostgreSQL."
      [[ -f "$SCRIPT_DIR/update.sh" ]] || error "No existe update.sh junto al instalador; no se modificó la instalación."
      exec env UPDATE_SOURCE=local bash "$SCRIPT_DIR/update.sh"
    fi
    error "Existe $INSTALL_DIR pero no se puede demostrar que sea una instalación válida. Se conserva íntegramente para recuperación manual; no se sobrescribe ni se elimina."
  fi
  [[ ! -e "/etc/systemd/system/${SERVICE_NAME}.service" && ! -L "/etc/systemd/system/${SERVICE_NAME}.service" ]] || error "La unidad sshpanel.service existe sin instalación verificada; se conserva."
  [[ ! -e "/etc/systemd/system/conecta-online-bridge.service" && ! -L "/etc/systemd/system/conecta-online-bridge.service" ]] || error "La unidad conecta-online-bridge.service ya existe; no se sobrescribirá."
  [[ ! -e /etc/systemd/system/multi-user.target.wants/sshpanel.service && ! -L /etc/systemd/system/multi-user.target.wants/sshpanel.service ]] || error "Existe un enlace systemd sshpanel previo; se conserva."
  if "$SYSTEMCTL_BIN" cat sshpanel.service >/dev/null 2>&1; then error "systemd ya conoce sshpanel.service fuera del manifiesto; se conserva y se aborta."; fi
  if "$SYSTEMCTL_BIN" cat conecta-online-bridge.service >/dev/null 2>&1; then error "systemd ya conoce conecta-online-bridge.service; se conserva y se aborta."; fi
  [[ ! -e /usr/local/bin/conecta && ! -L /usr/local/bin/conecta ]] || error "Existe /usr/local/bin/conecta; se conserva y se aborta antes de modificar el sistema."
  [[ ! -e /usr/local/bin/conectassh && ! -L /usr/local/bin/conectassh ]] || error "Existe /usr/local/bin/conectassh; se conserva y se aborta antes de modificar el sistema."
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
        chown postgres:postgres "$data_dir"
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
    if "$SYSTEMCTL_BIN" is-active --quiet "$svc" 2>/dev/null; then
      started=true
      break
    fi
    if "$SYSTEMCTL_BIN" start "$svc" >/dev/null 2>&1; then
      # Start only when required; preserve the administrator's enable/disable policy.
      started=true
      break
    fi
  done
  if ! $started && command -v service >/dev/null 2>&1; then
    service postgresql start >/dev/null 2>&1 && started=true || true
  fi
  $started || warn "  Could not start PostgreSQL automatically; continuing in case it is already running."
}


echo -e "\n${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}   SSH Panel + Xray-core  ·  Installer     ${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}\n"

create_rollback_snapshot() {
  ROLLBACK_DIR="$(mktemp -d /var/tmp/sshpanel-rollback.XXXXXX)"
  mkdir -p "$ROLLBACK_DIR/files"
  : > "$ROLLBACK_DIR/manifest"
  local path key
  for path in /etc/systemd/system/sshpanel.service /etc/systemd/system/conecta-online-bridge.service /usr/local/bin/conecta /usr/local/bin/conectassh; do
    key="$(printf '%s' "$path" | sed 's#^/##; s#[/]#_#g')"
    if [[ -e "$path" || -L "$path" ]]; then
      printf 'EXISTS\t%s\t%s\n' "$path" "$key" >> "$ROLLBACK_DIR/manifest"
      tar -C / -czf "$ROLLBACK_DIR/files/${key}.tar.gz" "${path#/}"
    else printf 'ABSENT\t%s\t%s\n' "$path" "$key" >> "$ROLLBACK_DIR/manifest"; fi
  done
  info "  Snapshot de rollback creado: $ROLLBACK_DIR"
}
restore_rollback_snapshot() {
  [[ -n "$ROLLBACK_DIR" && -f "$ROLLBACK_DIR/manifest" ]] || return 0
  warn "Verificando snapshot sin sobrescribir recursos ajenos..."
  local state path key target
  while IFS=$'\t' read -r state path key; do
    [[ -n "$path" ]] || continue
    case "$path" in
      /etc/systemd/system/sshpanel.service|/etc/systemd/system/conecta-online-bridge.service|/usr/local/bin/conecta|/usr/local/bin/conectassh) ;;
      *) warn "Ruta no permitida en snapshot: $path; se conserva."; continue ;;
    esac
    if [[ "$state" == "EXISTS" ]]; then
      # Preflight should have refused these resources. Never overwrite a path
      # that existed before the transaction; keep it for an administrator.
      warn "Se conserva el recurso preexistente capturado en snapshot: $path"
      continue
    fi
    case "$path" in
      /etc/systemd/system/sshpanel.service)
        if [[ -f "$path" && ! -L "$path" ]] && grep -q 'WorkingDirectory=/opt/sshpanel' "$path" 2>/dev/null && grep -q 'ExecStart=/opt/sshpanel/sshpanel' "$path" 2>/dev/null; then rm -f -- "$path"; elif [[ -e "$path" || -L "$path" ]]; then warn "Unidad no reconocida conservada: $path"; fi ;;
      /etc/systemd/system/conecta-online-bridge.service)
        if [[ -f "$path" && ! -L "$path" ]] && grep -q 'conecta-online-bridge' "$path" 2>/dev/null; then rm -f -- "$path"; elif [[ -e "$path" || -L "$path" ]]; then warn "Unidad no reconocida conservada: $path"; fi ;;
      /usr/local/bin/conecta|/usr/local/bin/conectassh)
        if [[ -L "$path" && "$(readlink "$path" 2>/dev/null || true)" == "/opt/sshpanel/conectassh_cli.py" ]]; then rm -f -- "$path"; elif [[ -e "$path" || -L "$path" ]]; then warn "Enlace no reconocido conservado: $path"; fi ;;
    esac
  done < "$ROLLBACK_DIR/manifest"
  systemctl daemon-reload >/dev/null 2>&1 || true
}
cleanup() {
  local rc="${1:-0}" rollback_ok=true
  [[ "$CLEANUP_RUNNING" == "true" ]] && return 0
  CLEANUP_RUNNING=true
  if [[ "$INSTALL_SUCCESS" != "true" && "$INSTALL_STARTED" == "true" ]]; then
    warn "Instalación fallida. Ejecutando rollback transaccional..."
    write_transaction_manifest rollback_pending || warn "No se pudo actualizar el estado del manifiesto; se intentará rollback con el último registro durable."
    if rollback_transaction_resources; then
      restore_rollback_snapshot
    else
      warn "Rollback incompleto: se conservan el ledger y el snapshot para recuperación posterior."
      rollback_ok=false
    fi
  fi
  rm -f /tmp/go.tar.gz
  if [[ "$rollback_ok" == "true" && -n "$ROLLBACK_DIR" && -d "$ROLLBACK_DIR" ]]; then rm -rf -- "$ROLLBACK_DIR"; fi
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
INSTALL_STARTED=true
install -d -m 0700 "$STATE_DIR"
: > "$RESOURCE_LEDGER"
chmod 0600 "$RESOURCE_LEDGER"
INSTALL_DIR_CREATED=1
write_transaction_manifest installing
register_resource directory "$INSTALL_DIR"
create_rollback_snapshot
write_transaction_manifest installing
mkdir -p "$INSTALL_DIR"
cat > "$INSTALL_DIR/.conecta-install-manifest" <<EOF
PRODUCT=ConectaSSH-PRO
MANIFEST_VERSION=3
INSTALL_ID=$INSTALL_ID
STATE=installing
INSTALL_DIR=/opt/sshpanel
INSTALL_DIR_CREATED=1
DB_NAME=sshpanel
DB_USER=sshpanel
DB_CREATED_BY_CONECTA=0
DB_ROLE_CREATED_BY_CONECTA=0
OWNED_UNIT_SSH_PANEL=1
OWNED_UNIT_ONLINE_BRIDGE=0
OWNED_UNIT_DNSTT_REDIRECT=0
OWNED_PATH_INSTALL_DIR=1
OWNED_PATH_LOG_TMPFS=1
OWNED_PATH_CLI_CONECTA=1
OWNED_PATH_CLI_CONECTASSH=1
FIREWALL_RULES_CREATED=0
NETWORK_CONFIGURATION_CHANGED=0
EOF
chmod 0600 "$INSTALL_DIR/.conecta-install-manifest"

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
  GO_TOOLCHAIN_DIR="$ROLLBACK_DIR/go-toolchain"
  mkdir -p "$GO_TOOLCHAIN_DIR"
  tar -C "$GO_TOOLCHAIN_DIR" --strip-components=1 -xzf /tmp/go.tar.gz
  rm -f /tmp/go.tar.gz
  # Go is added to PATH for this installer process only; do not leave a global profile file behind.
fi

if [[ -x "${GO_TOOLCHAIN_DIR:-}/bin/go" ]]; then export PATH="${GO_TOOLCHAIN_DIR}/bin:$PATH"; elif [[ -x /usr/local/go/bin/go ]]; then export PATH="/usr/local/go/bin:$PATH"; fi
go version

# ── 4. Directory layout ──────────────────────────────────────────────────────
info "[4/10] Setting up ${INSTALL_DIR}…"
mkdir -p "$INSTALL_DIR/keys" "$INSTALL_DIR/logs"

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
if [[ ( -e /usr/local/bin/conectassh || -L /usr/local/bin/conectassh ) && "$(readlink -f /usr/local/bin/conectassh 2>/dev/null || true)" != "$INSTALL_DIR/conectassh_cli.py" ]]; then error "Existe /usr/local/bin/conectassh ajeno; no se sobrescribe."; fi
register_resource symlink /usr/local/bin/conectassh "$INSTALL_DIR/conectassh_cli.py"
ln -sfn "$INSTALL_DIR/conectassh_cli.py" /usr/local/bin/conectassh
register_resource symlink /usr/local/bin/conecta "$INSTALL_DIR/conectassh_cli.py"
ln -sfn "$INSTALL_DIR/conectassh_cli.py" /usr/local/bin/conecta
# CRITICAL SSH SAFETY: never install a login-shell hook automatically.
# The CLI is launched explicitly with `conecta`; login must stay independent.
# Never modify /etc/profile.d, sshd, the SSH port, or existing sessions here.
info "  ConectaSSH-PRO CLI installed: conecta (also conectassh); SSH login untouched."
mkdir -p "$INSTALL_DIR/source"
rsync -a --delete --exclude '.git' --exclude 'source/' --exclude '__pycache__/' "$SCRIPT_DIR/" "$INSTALL_DIR/source/"


install_online_web_pro_module() {
  local module_dir="$INSTALL_DIR/online-bridge"
  local source_dir="$SCRIPT_DIR/cmd/conecta-online-bridge"
  local tmp_bin="$module_dir/conecta-online-bridge.tmp"

  [[ -f "$source_dir/main.go" ]] || error "MODULO ONLINE WEB PRO source is missing."
  [[ -f "$source_dir/conecta-online-bridge.service" ]] || error "MODULO ONLINE WEB PRO service template is missing."

  # Record ownership durably before creating the unit so rollback/uninstall can
  # remove only this exact service and never mistake it for an unrelated unit.
  register_resource unit /etc/systemd/system/conecta-online-bridge.service
  OWNED_UNIT_ONLINE_BRIDGE=1
  write_transaction_manifest installing
  sed -i 's/^OWNED_UNIT_ONLINE_BRIDGE=.*/OWNED_UNIT_ONLINE_BRIDGE=1/' "$INSTALL_DIR/.conecta-install-manifest"

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

ROLE_EXISTS="$(su - postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='sshpanel'\"" 2>/dev/null | tr -d '[:space:]' || true)"
DB_EXISTS="$(su - postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='sshpanel'\"" 2>/dev/null | tr -d '[:space:]' || true)"
if [[ "$ROLE_EXISTS" != "1" ]]; then
  DB_ROLE_CREATED_BY_CONECTA=1
  register_resource postgres_role sshpanel
  write_transaction_manifest installing
  sed -i 's/^DB_ROLE_CREATED_BY_CONECTA=.*/DB_ROLE_CREATED_BY_CONECTA=1/' "$INSTALL_DIR/.conecta-install-manifest"
fi
if [[ "$DB_EXISTS" != "1" ]]; then
  DB_CREATED_BY_CONECTA=1
  register_resource postgres_database sshpanel
  write_transaction_manifest installing
  sed -i 's/^DB_CREATED_BY_CONECTA=.*/DB_CREATED_BY_CONECTA=1/' "$INSTALL_DIR/.conecta-install-manifest"
fi

su -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'\" | grep -q 1 || \
       psql -c \"CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';\"" postgres
# Reinstall-safe: if the role already existed, make the new .env password valid.
if [[ "$DB_ROLE_CREATED_BY_CONECTA" == "1" ]]; then
  su - postgres -c "psql -c \"COMMENT ON ROLE sshpanel IS 'conecta-ssh-pro:$INSTALL_ID';\""
fi
su -c "psql -c \"ALTER USER ${DB_USER} WITH PASSWORD '${DB_PASS}';\"" postgres

su -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'\" | grep -q 1 || \
       psql -c \"CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};\"" postgres
# Reinstall-safe: if the database already existed, make sshpanel its owner.
if [[ "$DB_CREATED_BY_CONECTA" == "1" ]]; then
  su - postgres -c "psql -c \"COMMENT ON DATABASE sshpanel IS 'conecta-ssh-pro:$INSTALL_ID';\""
fi
su -c "psql -c \"ALTER DATABASE ${DB_NAME} OWNER TO ${DB_USER};\"" postgres

# Verify the same TCP/password path the application uses before changing schema.
# This prevents a superficially successful install with unusable PostgreSQL credentials.
command -v psql >/dev/null 2>&1 || error "psql no está disponible tras instalar PostgreSQL."
if ! PGPASSWORD="$DB_PASS" psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -tAc 'SELECT 1' >/dev/null 2>&1; then
  error "No se pudo autenticar contra PostgreSQL usando las credenciales que utilizará CONECTA. Se inicia rollback y se conserva toda base de datos preexistente."
fi

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
  "listen": "disabled",
  "extra_listen": [],
  "local_ssh_listen": "127.0.0.1:2222",
  "host_key_file": "${INSTALL_DIR}/ssh_host_rsa_key",
  "quiet": false,
  "pam_auth_enabled": true,
  "banner_file": "${INSTALL_DIR}/banner.txt",
  "xray": {
    "enabled": false,
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

# ── 9. Optional protocols stay disabled by default ──────────────────────────
# Do not take over system DNS, alter /etc/resolv.conf, add firewall rules,
# install NAT redirects, or enable protocol listeners during a fresh install.
# DNSTT and other protocols can be configured explicitly from the CLI later.
info "[9/10] Public protocols remain disabled until explicitly configured."

# ── 10. Systemd service ──────────────────────────────────────────────────────
info "[10/10] Creating systemd service '${SERVICE_NAME}'…"
register_resource unit "/etc/systemd/system/${SERVICE_NAME}.service"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=SSH Panel + Xray-core Server
After=local-fs.target network.target postgresql.service
Wants=postgresql.service

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
register_resource symlink /etc/systemd/system/multi-user.target.wants/sshpanel.service ../sshpanel.service
"$SYSTEMCTL_BIN" enable  "$SERVICE_NAME"
"$SYSTEMCTL_BIN" restart "$SERVICE_NAME"

sleep 2
echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}   Installation complete!                  ${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo -e "  Server IP    : ${YELLOW}${SERVER_IP}${NC}"
echo -e "  Public protocols : disabled by default"
echo -e "  Internal SSH     : 127.0.0.1:2222  (loopback only)"
echo -e "  Xray/DNSTT       : not activated automatically"
echo -e "  Configure ports  : run conecta → AUTO CONFIGURAR / MODO DE CONEXIÓN"
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
echo -e "${YELLOW}View/rotate the API password later with: sudo conectassh api-password show|change${NC}"
echo ""
"$SYSTEMCTL_BIN" status "$SERVICE_NAME" --no-pager -l || true

cat > "$INSTALL_DIR/.conecta-install-manifest" <<EOF
PRODUCT=ConectaSSH-PRO
MANIFEST_VERSION=3
INSTALL_ID=$INSTALL_ID
STATE=installed
INSTALL_DIR=/opt/sshpanel
INSTALL_DIR_CREATED=1
DB_NAME=sshpanel
DB_USER=sshpanel
DB_CREATED_BY_CONECTA=$DB_CREATED_BY_CONECTA
DB_ROLE_CREATED_BY_CONECTA=$DB_ROLE_CREATED_BY_CONECTA
OWNED_UNIT_SSH_PANEL=1
OWNED_UNIT_ONLINE_BRIDGE=${OWNED_UNIT_ONLINE_BRIDGE:-0}
OWNED_UNIT_DNSTT_REDIRECT=0
OWNED_PATH_INSTALL_DIR=1
OWNED_PATH_LOG_TMPFS=1
OWNED_PATH_CLI_CONECTA=1
OWNED_PATH_CLI_CONECTASSH=1
FIREWALL_RULES_CREATED=0
NETWORK_CONFIGURATION_CHANGED=0
EOF
chmod 0600 "$INSTALL_DIR/.conecta-install-manifest"
write_transaction_manifest installed
INSTALL_SUCCESS=true
info "Manifiesto transaccional confirmado: $TXN_MANIFEST"
