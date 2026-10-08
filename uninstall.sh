#!/bin/bash
set -euo pipefail
INSTALL_DIR="/opt/sshpanel"
MARKER="$INSTALL_DIR/.conecta-install-manifest"
SERVICE="sshpanel.service"
BRIDGE_SERVICE="conecta-online-bridge.service"
DNS_SERVICE="sshpanel-dnstt-redirect.service"
CLI="$INSTALL_DIR/conectassh_cli.py"

fail(){ echo "[x] $*" >&2; exit 1; }
info(){ echo "[+] $*"; }
[[ $EUID -eq 0 ]] || fail "La desinstalación requiere root."
[[ -f "$MARKER" ]] || fail "No existe el manifiesto de instalación de ConectaSSH-PRO. Operación abortada por seguridad."
source "$MARKER"
[[ "$PRODUCT" == "ConectaSSH-PRO" && "$INSTALL_DIR" == "/opt/sshpanel" ]] || fail "Manifiesto no reconocido."

if [[ "$CONFIRM" != "YES" ]]; then
  echo "DESINSTALACIÓN SEGURA — CONECTASSH-PRO"
  echo "Solo se eliminarán componentes identificados como propios de ConectaSSH-PRO."
  echo "SSHPlus/Horizon, sshd, usuarios SSH y paquetes compartidos NO se eliminan."
  read -r -p "Escribí DESINSTALAR para continuar: " answer
  [[ "$answer" == "DESINSTALAR" ]] || { echo "Cancelado."; exit 0; }
fi

systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
systemctl disable --now "$BRIDGE_SERVICE" >/dev/null 2>&1 || true
systemctl disable --now "$DNS_SERVICE" >/dev/null 2>&1 || true

for unit in "$SERVICE" "$BRIDGE_SERVICE" "$DNS_SERVICE"; do
  [[ -f "/etc/systemd/system/$unit" ]] && rm -f "/etc/systemd/system/$unit"
done
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl reset-failed "$SERVICE" "$BRIDGE_SERVICE" "$DNS_SERVICE" >/dev/null 2>&1 || true

remove_redirect_rule(){
  local bin="$1"
  command -v "$bin" >/dev/null 2>&1 || return 0
  while "$bin" -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null; do
    "$bin" -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 >/dev/null 2>&1 || break
  done
}
remove_redirect_rule iptables
remove_redirect_rule ip6tables
if command -v nft >/dev/null 2>&1 && nft list table inet sshpanel_nat >/dev/null 2>&1; then
  nft delete table inet sshpanel_nat >/dev/null 2>&1 || true
fi

if [[ "$UFW_53_ADDED" == "1" ]] && command -v ufw >/dev/null 2>&1; then ufw delete allow 53/udp >/dev/null 2>&1 || true; fi
if [[ "$FIREWALLD_53_ADDED" == "1" ]] && command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --permanent --remove-port=53/udp >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
fi

if [[ "$RESOLVED_WAS_ACTIVE" == "1" ]]; then systemctl enable --now systemd-resolved.service >/dev/null 2>&1 || true; fi
if [[ -n "$RESOLV_LINK_TARGET" && -e "$RESOLV_LINK_TARGET" ]]; then
  rm -f /etc/resolv.conf; ln -s "$RESOLV_LINK_TARGET" /etc/resolv.conf
elif [[ -f "$RESOLV_BACKUP" ]]; then
  rm -f /etc/resolv.conf; cp -a "$RESOLV_BACKUP" /etc/resolv.conf
fi

if [[ "$FSTAB_TMPFS_ADDED" == "1" && -f /etc/fstab ]]; then
  python3 - <<'PY'
from pathlib import Path
p=Path("/etc/fstab")
lines=p.read_text().splitlines()
lines=[x for x in lines if x.split()[:2] != ["tmpfs","/opt/sshpanel/logs"]]
p.write_text("\n".join(lines)+("\n" if lines else ""))
PY
fi

for link in /usr/local/bin/conecta /usr/local/bin/conectassh; do
  if [[ -L "$link" && "$(readlink -f "$link" 2>/dev/null || true)" == "$CLI" ]]; then rm -f "$link"; fi
done
if [[ -n "$CONECTA_BACKUP" && -e "$CONECTA_BACKUP" ]]; then mv "$CONECTA_BACKUP" /usr/local/bin/conecta; fi
if [[ -f /etc/profile.d/conecta-auto-menu.sh ]] && grep -q '/usr/local/bin/conecta' /etc/profile.d/conecta-auto-menu.sh 2>/dev/null; then
  rm -f /etc/profile.d/conecta-auto-menu.sh
fi

if [[ "$DB_CREATED_BY_CONECTA" == "1" && "$DB_ROLE_CREATED_BY_CONECTA" == "1" ]] && command -v psql >/dev/null 2>&1 && id postgres >/dev/null 2>&1; then
  su - postgres -c "psql -c \"REVOKE CONNECT ON DATABASE $DB_NAME FROM public; SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$DB_NAME' AND pid <> pg_backend_pid();\"" >/dev/null 2>&1 || true
  su - postgres -c "dropdb --if-exists '$DB_NAME'" >/dev/null 2>&1 || true
  su - postgres -c "dropuser --if-exists '$DB_USER'" >/dev/null 2>&1 || true
fi

python3 - "$INSTALL_DIR" <<'PY'
from pathlib import Path
import shutil,sys
root=Path(sys.argv[1]).resolve()
if str(root)!="/opt/sshpanel": raise SystemExit("Unsafe path")
if root.exists(): shutil.rmtree(root)
PY

[[ -n "$AUTO_MENU_BACKUP" && -f "$AUTO_MENU_BACKUP" ]] && rm -f "$AUTO_MENU_BACKUP" || true
[[ -n "$RESOLV_BACKUP" && -f "$RESOLV_BACKUP" ]] && rm -f "$RESOLV_BACKUP" || true
systemctl daemon-reload >/dev/null 2>&1 || true
info "ConectaSSH-PRO desinstalado. Componentes externos y paquetes compartidos conservados."
