#!/bin/sh
# ConectaSSH-PRO: optional automatic admin menu for root interactive shells.
# Disabled by default; controlled by auto_menu in /opt/sshpanel/config.json.
case "$-" in *i*) ;; *) return 0 2>/dev/null || exit 0 ;; esac
[ "$(id -u 2>/dev/null)" = "0" ] || return 0 2>/dev/null || exit 0
[ "${CONECTA_AUTO_MENU_RUNNING:-0}" = "1" ] && return 0 2>/dev/null || exit 0
CONFIG=/opt/sshpanel/config.json
[ -r "$CONFIG" ] || return 0 2>/dev/null || exit 0
AUTO_MENU=$(python3 - "$CONFIG" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        print("1" if bool(json.load(f).get("auto_menu", False)) else "0")
except Exception:
    print("0")
PY
)
[ "$AUTO_MENU" = "1" ] || return 0 2>/dev/null || exit 0
export CONECTA_AUTO_MENU_RUNNING=1
/usr/local/bin/conecta
unset CONECTA_AUTO_MENU_RUNNING
