#!/bin/bash
# Safe ConectaSSH-PRO removal. Data is preserved by default; --purge is destructive.
set -euo pipefail

INSTALL_DIR="/opt/sshpanel"
MARKER="$INSTALL_DIR/.conecta-install-manifest"
SERVICE="sshpanel.service"
BRIDGE_SERVICE="conecta-online-bridge.service"
DNS_SERVICE="sshpanel-dnstt-redirect.service"
STATE_DIR="/var/lib/conecta-ssh-pro"
TXN_MANIFEST="$STATE_DIR/manifest"
CLI="$INSTALL_DIR/conectassh_cli.py"
PURGE=false

fail(){ echo "[x] $*" >&2; exit 1; }
info(){ echo "[+] $*"; }
warn(){ echo "[!] $*" >&2; }

for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=true ;;
    --help|-h) echo "Uso: $0 [--purge]"; echo "Por defecto preserva /opt/sshpanel (configuración, credenciales, certificados, llaves y logs). --purge elimina los datos locales del producto."; exit 0 ;;
    *) fail "Opción desconocida: $arg" ;;
  esac
done

[[ $EUID -eq 0 ]] || fail "La desinstalación requiere root."
[[ -d "$INSTALL_DIR" && ! -L "$INSTALL_DIR" ]] || fail "No existe un directorio de instalación seguro en $INSTALL_DIR."
[[ -f "$MARKER" && ! -L "$MARKER" ]] || fail "No existe el manifiesto de propiedad; no se eliminará nada."
[[ "$(stat -c '%u' "$MARKER" 2>/dev/null)" == "0" ]] || fail "El manifiesto no pertenece a root."
mode="$(stat -c '%a' "$MARKER" 2>/dev/null || echo 777)"
(( (8#$mode & 077) == 0 )) || fail "Permisos inseguros en el manifiesto."
# The marker is root-owned and mode 600. Only accept fixed product/path values.
source "$MARKER"
[[ "${PRODUCT:-}" == "ConectaSSH-PRO" && "${INSTALL_DIR:-}" == "/opt/sshpanel" ]] || fail "Manifiesto no reconocido."
[[ "${MANIFEST_VERSION:-1}" =~ ^[0-9]+$ ]] || fail "Versión de manifiesto inválida."
STATE="${STATE:-installed}"
[[ "$STATE" == "installed" || "$STATE" == "installing" || "$STATE" == "rollback_pending" ]] || fail "Estado no desinstalable: $STATE."
OWNED_UNIT_SSH_PANEL="${OWNED_UNIT_SSH_PANEL:-1}"
OWNED_UNIT_ONLINE_BRIDGE="${OWNED_UNIT_ONLINE_BRIDGE:-0}"
OWNED_UNIT_DNSTT_REDIRECT="${OWNED_UNIT_DNSTT_REDIRECT:-0}"
OWNED_PATH_CLI_CONECTA="${OWNED_PATH_CLI_CONECTA:-0}"
OWNED_PATH_CLI_CONECTASSH="${OWNED_PATH_CLI_CONECTASSH:-0}"
DB_NAME="${DB_NAME:-sshpanel}"
DB_USER="${DB_USER:-sshpanel}"
DB_CREATED_BY_CONECTA="${DB_CREATED_BY_CONECTA:-0}"
DB_ROLE_CREATED_BY_CONECTA="${DB_ROLE_CREATED_BY_CONECTA:-0}"

if [[ "${CONFIRM:-}" != "YES" ]]; then
  echo "Desinstalación segura de CONECTA SSH PRO"
  if $PURGE; then
    echo "ATENCIÓN: --purge eliminará los datos locales del producto."
    read -r -p "Escribí PURGAR para confirmar el borrado: " answer
    [[ "$answer" == "PURGAR" ]] || { echo "Cancelado."; exit 0; }
  else
    echo "Se preservarán configuración, credenciales, certificados, llaves, logs y archivos de datos."
    read -r -p "Escribí DESINSTALAR para continuar: " answer
    [[ "$answer" == "DESINSTALAR" ]] || { echo "Cancelado."; exit 0; }
  fi
fi

# Global /etc/profile.d hooks are not in the ownership manifest; preserve them.
# Preflight every unit before changing anything. If a unit is ambiguous, abort
# before moving/removing the payload so no unknown service is left broken.
owned_unit_file() {
  local unit="$1" flag="$2" path="/etc/systemd/system/$1"
  [[ "$flag" == "1" && -f "$path" && ! -L "$path" ]] || return 1
  case "$unit" in
    "$SERVICE") grep -q 'WorkingDirectory=/opt/sshpanel' "$path" && grep -q 'ExecStart=/opt/sshpanel/sshpanel' "$path" ;;
    "$BRIDGE_SERVICE") grep -q 'conecta-online-bridge' "$path" ;;
    "$DNS_SERVICE") grep -q 'sshpanel-dnstt-redirect.sh' "$path" ;;
    *) return 1 ;;
  esac
}
for unit in "$SERVICE" "$BRIDGE_SERVICE" "$DNS_SERVICE"; do
  unit_path="/etc/systemd/system/$unit"
  [[ -e "$unit_path" || -L "$unit_path" ]] || continue
  flag=0
  case "$unit" in
    "$SERVICE") flag="$OWNED_UNIT_SSH_PANEL" ;;
    "$BRIDGE_SERVICE") flag="$OWNED_UNIT_ONLINE_BRIDGE" ;;
    "$DNS_SERVICE") flag="$OWNED_UNIT_DNSTT_REDIRECT" ;;
  esac
  if ! owned_unit_file "$unit" "$flag"; then
    fail "Se conserva todo: no se pudo demostrar propiedad exclusiva de $unit_path."
  fi
done
if ! owned_unit_file "$SERVICE" "$OWNED_UNIT_SSH_PANEL" && systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
  fail "sshpanel.service está activo pero su unidad no está demostrablemente bajo propiedad de este manifiesto; no se mueve el directorio."
fi

# Stop only the product's verified units; never ssh/sshd or any SSH user/session.
for unit in "$SERVICE" "$BRIDGE_SERVICE" "$DNS_SERVICE"; do
  unit_path="/etc/systemd/system/$unit"
  [[ -e "$unit_path" || -L "$unit_path" ]] || continue
  flag=0
  case "$unit" in
    "$SERVICE") flag="$OWNED_UNIT_SSH_PANEL" ;;
    "$BRIDGE_SERVICE") flag="$OWNED_UNIT_ONLINE_BRIDGE" ;;
    "$DNS_SERVICE") flag="$OWNED_UNIT_DNSTT_REDIRECT" ;;
  esac
  if owned_unit_file "$unit" "$flag"; then
    systemctl disable --now "$unit" >/dev/null 2>&1 || fail "No se pudo detener de forma segura $unit; se aborta."
  fi
done

# Logs may live on a tmpfs mounted by the product unit. Copy them off the
# mount before unmounting so default uninstall truly preserves the log files.
LOG_STAGE=""
if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$INSTALL_DIR/logs"; then
  if ! $PURGE; then
    LOG_STAGE="$(mktemp -d /var/tmp/conecta-ssh-pro-logs.XXXXXX)"
    cp -a "$INSTALL_DIR/logs/." "$LOG_STAGE/" || fail "No se pudieron preservar los logs; se aborta."
  fi
  umount "$INSTALL_DIR/logs" || fail "No se pudo desmontar el tmpfs de logs; se aborta sin borrar los datos."
  if ! $PURGE; then
    mkdir -p "$INSTALL_DIR/logs"
    cp -a "$LOG_STAGE/." "$INSTALL_DIR/logs/"
    rm -rf -- "$LOG_STAGE"
  fi
fi

for unit in "$SERVICE" "$BRIDGE_SERVICE" "$DNS_SERVICE"; do
  unit_path="/etc/systemd/system/$unit"
  [[ -e "$unit_path" || -L "$unit_path" ]] || continue
  flag=0
  case "$unit" in
    "$SERVICE") flag="$OWNED_UNIT_SSH_PANEL" ;;
    "$BRIDGE_SERVICE") flag="$OWNED_UNIT_ONLINE_BRIDGE" ;;
    "$DNS_SERVICE") flag="$OWNED_UNIT_DNSTT_REDIRECT" ;;
  esac
  if owned_unit_file "$unit" "$flag"; then
    rm -f -- "$unit_path"
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  fi
done
systemctl daemon-reload >/dev/null 2>&1 || true
for unit in "$SERVICE" "$BRIDGE_SERVICE" "$DNS_SERVICE"; do
  unit_path="/etc/systemd/system/$unit"
  if [[ -e "$unit_path" || -L "$unit_path" ]]; then
    fail "Quedó una unidad residual: $unit_path"
  fi
done

# Remove only the exact CLI symlinks declared in the manifest.
if [[ "$OWNED_PATH_CLI_CONECTA" == "1" && -L /usr/local/bin/conecta && "$(readlink -f /usr/local/bin/conecta 2>/dev/null || true)" == "$CLI" ]]; then
  rm -f -- /usr/local/bin/conecta
elif [[ -e /usr/local/bin/conecta || -L /usr/local/bin/conecta ]]; then
  info "Se conserva /usr/local/bin/conecta: no coincide con el enlace propio."
fi
if [[ "$OWNED_PATH_CLI_CONECTASSH" == "1" && -L /usr/local/bin/conectassh && "$(readlink -f /usr/local/bin/conectassh 2>/dev/null || true)" == "$CLI" ]]; then
  rm -f -- /usr/local/bin/conectassh
elif [[ -e /usr/local/bin/conectassh || -L /usr/local/bin/conectassh ]]; then
  info "Se conserva /usr/local/bin/conectassh: no coincide con el enlace propio."
fi

# A database is purged only when manifest flags AND PostgreSQL comments prove
# that both objects were created by this exact installation transaction.
if $PURGE && [[ "$DB_CREATED_BY_CONECTA" == "1" && "$DB_ROLE_CREATED_BY_CONECTA" == "1" && -n "${INSTALL_ID:-}" ]] && command -v psql >/dev/null 2>&1 && id postgres >/dev/null 2>&1; then
  db_comment="$(su - postgres -c "psql -tAc \"SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname='sshpanel'\"" 2>/dev/null | tr -d '\r' || true)"
  role_comment="$(su - postgres -c "psql -tAc \"SELECT shobj_description(oid, 'pg_authid') FROM pg_authid WHERE rolname='sshpanel'\"" 2>/dev/null | tr -d '\r' || true)"
  if [[ "$db_comment" == "conecta-ssh-pro:$INSTALL_ID" && "$role_comment" == "conecta-ssh-pro:$INSTALL_ID" ]]; then
    su - postgres -c "dropdb --if-exists '$DB_NAME'" >/dev/null 2>&1 || fail "No se pudo eliminar la base de datos propia; se conservan los datos restantes."
    su - postgres -c "dropuser --if-exists '$DB_USER'" >/dev/null 2>&1 || fail "No se pudo eliminar el rol propio de PostgreSQL."
  else
    info "PostgreSQL se conserva: los comentarios de propiedad no coinciden con esta instalación."
  fi
elif $PURGE; then
  info "PostgreSQL se conserva: el manifiesto no demuestra propiedad exclusiva de la base y del rol."
fi

FINAL_STATE=uninstalled
if $PURGE; then
  python3 - "$INSTALL_DIR" <<'PY'
from pathlib import Path
import shutil,sys
p=Path(sys.argv[1])
if str(p)!="/opt/sshpanel" or p.is_symlink() or not p.is_dir():
    raise SystemExit("Ruta insegura; no se elimina el directorio")
m=p/".conecta-install-manifest"
if not m.is_file() or "PRODUCT=ConectaSSH-PRO" not in m.read_text(errors="replace").splitlines():
    raise SystemExit("Manifiesto de propiedad no válido; no se elimina el directorio")
shutil.rmtree(p)
PY
  info "Datos locales del producto eliminados por solicitud explícita (--purge)."
else
  preserved="/opt/sshpanel.preserved.$(date -u +%Y%m%dT%H%M%SZ)"
  [[ ! -e "$preserved" && ! -L "$preserved" ]] || fail "Destino de preservación ya existe: $preserved"
  mv -- "$INSTALL_DIR" "$preserved"
  FINAL_STATE=preserved
  info "Configuración, credenciales, certificados, llaves, logs y datos preservados en: $preserved"
  info "La base de datos PostgreSQL se conserva."
fi

if [[ -f "$TXN_MANIFEST" && "$(stat -c '%u' "$TXN_MANIFEST" 2>/dev/null || true)" == "0" ]]; then
  tmp="$TXN_MANIFEST.tmp"
  sed -e "s/^STATE=.*/STATE=$FINAL_STATE/" -e 's/^INSTALL_DIR_CREATED=.*/INSTALL_DIR_CREATED=0/' "$TXN_MANIFEST" > "$tmp"
  chmod 0600 "$tmp"
  mv -f -- "$tmp" "$TXN_MANIFEST"
  [[ -f "$STATE_DIR/resources.tsv" && ! -L "$STATE_DIR/resources.tsv" ]] && rm -f -- "$STATE_DIR/resources.tsv"
fi
info "ConectaSSH-PRO desinstalado. No se modificaron OpenSSH, sshd_config, puerto 22 ni usuarios SSH."
