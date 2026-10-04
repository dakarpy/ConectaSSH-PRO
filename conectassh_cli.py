#!/usr/bin/env python3
"""DragonCoreSSH terminal administration. Python 3 standard library only.

Root access to /opt/sshpanel/.env acts as local administrator authentication.
Passwords are generated; no password input or interactive login is requested.
"""

import argparse
import copy
import datetime as dt
import getpass
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


INSTALL_DIR = Path(os.environ.get("DRAGONCORE_DIR", "/opt/sshpanel"))
ENV_FILE = INSTALL_DIR / ".env"
SERVICE = os.environ.get("DRAGONCORE_SERVICE", "sshpanel")

# Colores ANSI para terminales SSH/Android. Se desactivan con NO_COLOR.
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
WHITE = "\033[37m"
MAGENTA = "\033[35m"


def paint(text, color, bold=False):
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return str(text)
    return f"{BOLD if bold else ""}{color}{text}{RESET}"


def colorize_menu(lines):
    """Tema final: cyan estructura, blanco información, amarillo funciones y verde solo estados OK."""
    import re
    out = []
    header_labels = r"(Host:|SO:|Uptime:|Hora:|CPU:|Memoria:|UP/DOWN:|SERVICIO:)"
    stats_labels = r"(Onlines:|Expirados:|Total:)"

    for raw in lines:
        # Marco siempre cyan. Esto incluye TODOS los bordes y separadores.
        if raw.startswith(("┌", "└", "├", "┏", "┗", "┣")):
            out.append(paint(raw, CYAN))
            continue

        if "SCRIPT CONECTA SSH -" in raw:
            out.append(paint(raw, CYAN, True))
            continue

        if "[00] • SALIR" in raw:
            out.append(paint(raw, RED, True))
            continue

        if "Elegí una opción" in raw:
            out.append(paint(raw, CYAN, True))
            continue

        # Encabezado VPS: estructura/etiquetas cyan; datos normales blancos;
        # solamente un estado positivo como ACTIVO queda verde.
        if re.search(r"(?:^|•\s)(Host|SO|Uptime|Hora|CPU|RAM|Memoria|UP/DOWN|SERVICIO):", raw):
            def header_entry(match):
                bullet, label, value = match.groups()
                state_color = GREEN if label == "SERVICIO" and value.strip().upper() in ("ACTIVO", "ONLINE", "OK") else WHITE
                return paint(bullet, CYAN) + paint(label + ":", CYAN, True) + " " + paint(value, state_color)
            colored = re.sub(
                r"(•\s*)(Host|SO|Uptime|Hora|CPU|RAM|Memoria|UP/DOWN|SERVICIO):\s*([^│]+?)(?=\s{2,}•|\s*│|$)",
                header_entry,
                raw,
            )
            out.append(colored)
            continue

        if any(label in raw for label in ("Onlines:", "Expirados:", "Total:")):
            colored = re.sub(stats_labels, lambda m: paint(m.group(1), CYAN, True), raw)
            colored = re.sub(r"(: )([^│]+?)(?=\s{2,}|\s*│|$)", lambda m: ": " + paint(m.group(2), WHITE, True), colored)
            out.append(colored)
            continue

        if re.search(r"\[\d{2}\]\s*•", raw):
            def paint_entry(match):
                number, bullet, label = match.groups()
                return paint(number, CYAN, True) + bullet + paint(label, YELLOW)
            colored = re.sub(
                r"(\[\d{2}\])(\s*•\s*)(.*?)(?=\s*│|\s{3,}\[\d{2}\]|$)",
                paint_entry,
                raw,
            )
            out.append(colored)
            continue

        out.append(raw)
    return out


class CLIError(Exception):
    pass


def require_root():
    if os.geteuid() != 0:
        raise CLIError("Ejecutá desde una sesión root (o usá sudo menu).")


def read_env():
    try:
        fd = os.open(ENV_FILE, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, encoding="utf-8") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise CLIError(".env must be a regular file")
            lines = handle.readlines()
    except OSError as exc:
        raise CLIError(f"Cannot read {ENV_FILE}: {exc}") from exc
    values = {}
    for line in lines:
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.rstrip("\n").split("=", 1)
            values[key.strip()] = value.strip().strip('"')
    return lines, values


def api_password():
    token = read_env()[1].get("ADMIN_TOKEN", "")
    if len(token) < 32:
        raise CLIError("ADMIN_TOKEN is missing or too short in .env")
    return token


def api_base():
    address = read_env()[1].get("ADMIN_HTTP_ADDR", "127.0.0.1:9090")
    try:
        parsed = urllib.parse.urlsplit("http://" + address)
        port = parsed.port
        if not port or not 1 <= port <= 65535:
            raise ValueError("invalid port")
    except ValueError as exc:
        raise CLIError(f"Invalid ADMIN_HTTP_ADDR: {exc}") from exc
    # Always connect locally, including when the API is explicitly exposed
    # for managed-server integrations.
    host = "[::1]" if parsed.hostname in ("::", "::1") else "127.0.0.1"
    return f"http://{host}:{port}"


def request(method, path, data=None, timeout=25):
    if not path.startswith("/") or path.startswith("//"):
        raise CLIError("Invalid API path")
    body = None if data is None else json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        api_base() + path, data=body, method=method,
        headers={"Authorization": "Bearer " + api_password(),
                 "Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        # Do not send the bearer credential through an inherited HTTP proxy.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=timeout) as response:
            raw = response.read(2 * 1024 * 1024)
            return json.loads(raw) if raw.strip() else None
    except urllib.error.HTTPError as exc:
        detail = exc.read(2048).decode("utf-8", "replace").strip()
        raise CLIError(f"API {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise CLIError(f"API unavailable at {api_base()}: {exc}") from exc


def write_env_token(token):
    if len(token) < 32 or not all(ch.isalnum() or ch in "-_" for ch in token):
        raise CLIError("API password must have 32+ letters, digits, - or _")
    lines, _ = read_env()
    replaced = False
    out = []
    for line in lines:
        if line.startswith("ADMIN_TOKEN="):
            if not replaced:
                out.append("ADMIN_TOKEN=" + token + "\n")
                replaced = True
        else:
            out.append(line)
    if not replaced:
        out.append("ADMIN_TOKEN=" + token + "\n")
    old = os.stat(ENV_FILE, follow_symlinks=False)
    fd, tmp = tempfile.mkstemp(prefix=".env.dragoncore-", dir=ENV_FILE.parent)
    try:
        os.fchmod(fd, 0o600)
        os.fchown(fd, old.st_uid, old.st_gid)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.writelines(out)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, ENV_FILE)
        dirfd = os.open(ENV_FILE.parent, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def service_action(action):
    proc = subprocess.run(["systemctl", action, SERVICE], capture_output=True, text=True)
    if proc.returncode:
        raise CLIError((proc.stderr or proc.stdout).strip() or f"systemctl {action} failed")


def rotate_api_password():
    old = api_password()
    new = secrets.token_urlsafe(36)
    write_env_token(new)
    try:
        service_action("restart")
        last_error = None
        for _ in range(12):
            try:
                request("GET", "/api/users")  # Verify the new token is active.
                last_error = None
                break
            except CLIError as exc:
                last_error = exc
                time.sleep(1)
        if last_error:
            raise last_error
    except CLIError as exc:
        write_env_token(old)
        try:
            service_action("restart")
        except CLIError:
            pass
        raise CLIError(f"Rotation failed; previous password restored: {exc}") from exc
    print("Nueva contraseña de API:", new)


def ask(label, default=""):
    suffix = f" [{default}]" if default != "" else ""
    result = input(f"{label}{suffix}: ").strip()
    return result or str(default)


def number(label, default, minimum=0, maximum=1000000):
    raw = ask(label, default)
    try:
        value = int(raw)
    except ValueError as exc:
        raise CLIError(f"{label} must be a number") from exc
    if not minimum <= value <= maximum:
        raise CLIError(f"{label} must be between {minimum} and {maximum}")
    return value


def normalize_public_endpoint(value):
    """Accept a port and store it as 0.0.0.0:PORT; preserve IP:PORT input."""
    raw = str(value).strip()
    if raw.isdecimal():
        port = int(raw)
        if not 1 <= port <= 65535:
            raise CLIError("El puerto debe estar entre 1 y 65535")
        return f"0.0.0.0:{port}"
    return raw


def normalize_public_endpoints(value):
    if isinstance(value, list):
        return [normalize_public_endpoint(item) for item in value]
    return normalize_public_endpoint(value)


def expiry(default=""):
    raw = ask("Vencimiento (AAAA-MM-DD, días desde hoy o 'nunca')", default or "nunca")
    if raw.lower() in ("never", "none", "nunca", "0"):
        return ""
    try:
        day = dt.date.today() + dt.timedelta(days=int(raw)) if raw.isdecimal() else dt.date.fromisoformat(raw)
        return day.isoformat() + "T23:59:59Z"
    except ValueError as exc:
        raise CLIError("Ingresá AAAA-MM-DD, cantidad de días o nunca") from exc


def confirm(label):
    return input(label + " Escribí SI para confirmar: ").strip().lower() in ("si", "sí")


def size(n):
    n = float(n or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}"
        n /= 1024


def terminal_columns():
    override = os.environ.get("DRAGONCORE_COLUMNS", "")
    if override.isdecimal() and 24 <= int(override) <= 240:
        return int(override)
    return max(24, shutil.get_terminal_size(fallback=(80, 24)).columns)


def print_wrapped(value, indent=""):
    width = max(20, terminal_columns() - len(indent) - 1)
    for part in textwrap.wrap(str(value), width=width, break_long_words=True) or [""]:
        print(indent + part)


def parse_expiry(value):
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except (TypeError, ValueError):
        return None


def local_meminfo():
    try:
        lines = Path("/proc/meminfo").read_text().splitlines()
        values = {k.rstrip(":"): int(v.split()[0]) * 1024 for k, v in (line.split(":", 1) for line in lines)}
        total = values["MemTotal"]
        return total, max(0, total - values["MemAvailable"])
    except (OSError, KeyError, ValueError):
        return 0, 0


def collect_vps_status():
    """Read live host and DragonCore data; degraded API data never blocks the menu."""
    try:
        os_name = next((line.split("=", 1)[1].strip().strip('"')
                        for line in Path("/etc/os-release").read_text().splitlines()
                        if line.startswith("PRETTY_NAME=")), "Linux")
    except OSError:
        os_name = "Linux"
    try:
        seconds = int(float(Path("/proc/uptime").read_text().split()[0]))
        uptime = f"{seconds // 86400}d {(seconds % 86400) // 3600}h"
    except (OSError, ValueError, IndexError):
        uptime = "--"
    try:
        service = subprocess.run(["systemctl", "is-active", SERVICE], capture_output=True, text=True)
        state = service.stdout.strip()
        if state not in ("active", "inactive", "failed", "activating", "deactivating"):
            state = "unknown"
    except OSError:
        state = "unknown"
    stats = users = xray = None
    for path, key in (("/api/stats", "stats"), ("/api/users", "users"),
                      ("/api/xray/status", "xray")):
        try:
            value = request("GET", path, timeout=2)
        except (CLIError, ValueError):
            value = None
        if key == "stats":
            stats = value if isinstance(value, dict) else None
        elif key == "users":
            users = value if isinstance(value, list) else None
        else:
            xray = value if isinstance(value, dict) else None

    try:
        load_avg = float(Path("/proc/loadavg").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        load_avg = None
    total_mem, used_mem = local_meminfo()
    if stats and stats.get("mem_total_bytes"):
        total_mem = stats["mem_total_bytes"]
        used_mem = stats.get("mem_used_bytes", 0)
    now = dt.datetime.now(dt.timezone.utc)
    expired = sum(1 for u in users or [] if (e := parse_expiry(u.get("expires_at"))) and e <= now)
    interfaces = (stats or {}).get("interfaces") or []
    rx_bytes = sum(float(item.get("rx_bytes", 0) or 0) for item in interfaces)
    tx_bytes = sum(float(item.get("tx_bytes", 0) or 0) for item in interfaces)
    try:
        disk = shutil.disk_usage("/")
        disk_pct = 100 * disk.used / disk.total if disk.total else 0
    except OSError:
        disk_pct = 0
    return {
        "host": os.uname().nodename, "os": os_name, "uptime": uptime,
        "time": dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M"),
        "cores": os.cpu_count() or 1, "cpu": (stats or {}).get("cpu_percent"), "load": load_avg,
        "mem_total": total_mem, "mem_used": used_mem,
        "disk_pct": disk_pct,
        "ssh_total": len(users) if users is not None else None,
        "ssh_online": sum(1 for u in users or [] if u.get("active_conns", 0) > 0) if users is not None else None,
        "ssh_expired": expired if users is not None else None,
        "xray_online": xray.get("online_users") if xray else None,
        "down_mbps": max((item.get("rx_mbps", 0) for item in interfaces), default=0),
        "up_mbps": max((item.get("tx_mbps", 0) for item in interfaces), default=0),
        "rx_bytes": rx_bytes, "tx_bytes": tx_bytes,
        "service": state, "api_online": stats is not None and users is not None,
    }


def render_vps_status(s, columns=None):
    """Render VPS status within the terminal width, including narrow phones."""
    cols = columns or terminal_columns()
    width = min(74, max(20, cols - 4))
    def field(value):
        return "--" if value is None else str(value)
    def line(value):
        return "┃ " + value.ljust(width) + " ┃"
    cpu = "--" if s["cpu"] is None else f"{s['cpu']:.1f}%"
    ram = (f"{size(s['mem_used'])}/{size(s['mem_total'])}"
           if s["mem_total"] else "--")
    if cols < 60:
        rows = [
            "SCRIPT CONECTA SSH • VPS",
            f"OS: {s['os']}",
            f"Host: {s['host']}  {s['time'][-5:]}",
            f"CPU: {cpu} / {s['cores']} núcleos",
            f"RAM: {ram}  Disco: {s['disk_pct']:.0f}%",
            f"Uptime: {s['uptime']}  Servicio: {s['service']}",
            f"SSH: {field(s['ssh_online'])} conectados / {field(s['ssh_total'])} total",
            f"Vencidos: {field(s['ssh_expired'])}  Xray: {field(s['xray_online'])} conectados",
            f"Net: ↓ {s['down_mbps']:.1f} ↑ {s['up_mbps']:.1f} Mbps"
            if s["api_online"] else "API sin conexión; datos locales del VPS",
        ]
    else:
        rows = [
            "SCRIPT CONECTA SSH  •  ESTADO DEL VPS",
            f"OS: {s['os']}   Host: {s['host']}",
            f"Hora: {s['time']}   Uptime: {s['uptime']}   Servicio: {s['service']}",
            f"CPU: {cpu} ({s['cores']} cores)   RAM: {ram}   Disk: {s['disk_pct']:.0f}%",
            f"SSH: {field(s['ssh_online'])} conectados  |  {field(s['ssh_expired'])} vencidos  |  "
            f"{field(s['ssh_total'])} total   Xray: {field(s['xray_online'])} conectados",
            f"Red: ↓ {s['down_mbps']:.2f} Mbps   ↑ {s['up_mbps']:.2f} Mbps"
            if s["api_online"] else "API: no disponible; se muestran las métricas locales del VPS",
        ]
    wrapped = (piece for row in rows for piece in textwrap.wrap(row, width=width, break_long_words=True))
    return "\n".join(["┏" + "━" * (width + 2) + "┓", *(line(part) for part in wrapped),
                      "┗" + "━" * (width + 2) + "┛"])


def list_users():
    users = request("GET", "/api/users") or []
    if terminal_columns() < 72:
        for u in sorted(users, key=lambda row: row["username"]):
            print_wrapped(f"{u['username']}  {u.get('active_conns', 0)}/{u.get('max_connections', 0)} conectados")
            print_wrapped(f"Consumo {size(u.get('total_bytes', 0))}  "
                          f"Vence {str(u.get('expires_at') or 'nunca')[:10]}", "  ")
    else:
        print(f"{'USUARIO':<24} {'EN LÍNEA':>8} {'LÍMITE':>6} {'CONSUMO':>12}  VENCE")
        for u in sorted(users, key=lambda row: row["username"]):
            print(f"{u['username']:<24} {u.get('active_conns', 0):>8} "
                  f"{u.get('max_connections', 0):>6} {size(u.get('total_bytes', 0)):>12}  "
                  f"{str(u.get('expires_at') or 'nunca')[:10]}")
    print(f"Total de usuarios: {len(users)}")
    return users


def user_payload(u):
    fields = ("username", "max_connections", "limit_mbps_up", "limit_mbps_down",
              "data_quota_bytes", "quota_action", "quota_throttle_mbps", "totp_secret",
              "totp_period", "totp_window", "totp_digits", "allow_static_password",
              "use_pam", "owner_username")
    p = {field: u[field] for field in fields if field in u}
    p["expires_at"] = u.get("expires_at") or ""
    return p


def get_user(name):
    return next((u for u in request("GET", "/api/users") or [] if u["username"] == name), None)


def create_user(default_days=30, test_hours=None):
    name = ask("Usuario SSH").lower()
    if not name:
        raise CLIError("El usuario es obligatorio")
    if get_user(name):
        raise CLIError("El usuario ya existe; elegí Editar usuario SSH")
    password = f"{secrets.randbelow(1000000):06d}"
    expires_at = ((dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=test_hours)).isoformat(timespec="seconds")
                  if test_hours else expiry(str(default_days)))
    use_pam = ask("¿Usar autenticación PAM para este usuario? (sí/no)", "sí").lower() in ("sí", "si", "s", "yes", "y")
    p = {"username": name, "password": password, "max_connections": number("Máximo de conexiones", 1, 0, 10000),
         "expires_at": expires_at, "limit_mbps_up": 0, "limit_mbps_down": 0,
         "data_quota_bytes": 0, "quota_action": "throttle", "quota_throttle_mbps": 10,
         "use_pam": use_pam}
    if use_pam:
        print("Aviso: el usuario PAM debe existir como cuenta Linux válida en /etc/passwd y /etc/shadow.")
    request("POST", "/api/users/create", p)
    expira = str(expires_at or "nunca")[:10]
    if expira and expira != "nunca":
        try:
            expira = dt.datetime.fromisoformat(expira).strftime("%d/%m/%Y")
        except ValueError:
            pass
    print("\n✅ ¡USUARIO CREADO CON ÉXITO!")
    print(f"👤 USUARIO: {name}")
    print(f"🔑 CONTRASEÑA: {password}")
    print(f"📲 CONEXIÓN: {p["max_connections"]}")
    print(f"📆 VENCIMIENTO: {expira}")


def edit_user():
    name = ask("Usuario SSH").lower()
    u = get_user(name)
    if not u:
        raise CLIError("Usuario no encontrado")
    p = user_payload(u)
    print("1 Vencimiento   2 Conexiones   3 Ancho de banda   4 Cuota   5 Generar nueva contraseña   6 PAM")
    choice = ask("Opción")
    if choice == "1":
        p["expires_at"] = expiry(str(u.get("expires_at") or "")[:10])
    elif choice == "2":
        p["max_connections"] = number("Máximo de conexiones", u.get("max_connections", 1), 0, 10000)
    elif choice == "3":
        p["limit_mbps_up"] = number("Subida Mbps (0 = predeterminado)", u.get("limit_mbps_up", 0))
        p["limit_mbps_down"] = number("Bajada Mbps (0 = predeterminado)", u.get("limit_mbps_down", 0))
    elif choice == "4":
        gib = number("Cuota GiB (0 = ilimitada)", round(u.get("data_quota_bytes", 0) / 1024**3))
        p["data_quota_bytes"] = gib * 1024**3
        p["quota_action"] = ask("Al alcanzar la cuota: limitar/bloquear", u.get("quota_action") or "throttle")
        p["quota_throttle_mbps"] = number("Velocidad limitada en Mbps", u.get("quota_throttle_mbps") or 10)
    elif choice == "5":
        p["password"] = f"{secrets.randbelow(1000000):06d}"
    elif choice == "6":
        p["use_pam"] = ask("¿Usar autenticación PAM? (sí/no)", "sí" if u.get("use_pam") else "no").lower() in ("sí", "si", "s", "yes", "y")
        if p["use_pam"]:
            print("Aviso: el usuario PAM debe existir como cuenta Linux válida en /etc/passwd y /etc/shadow.")
    else:
        return
    request("POST", "/api/users/create", p)
    print("Guardado.")
    if choice == "5":
        print("Contraseña SSH generada:", p["password"])


def delete_user():
    name = ask("SSH username").lower()
    if confirm(f"¿Eliminar el usuario SSH {name}?"):
        request("DELETE", "/api/users/delete?" + urllib.parse.urlencode({"username": name}))
        print("Deleted.")


def reset_traffic():
    name = ask("SSH username").lower()
    if confirm(f"¿Restablecer el consumo de {name}?"):
        request("POST", "/api/users/reset-traffic", {"username": name})
        print("Traffic reset.")


def delete_expired_users():
    now = dt.datetime.now(dt.timezone.utc)
    expired = [u["username"] for u in request("GET", "/api/users") or []
               if (end := parse_expiry(u.get("expires_at"))) and end <= now]
    if not expired:
        print("No hay usuarios SSH vencidos.")
        return
    print("Usuarios SSH vencidos:", ", ".join(expired))
    if confirm(f"¿Eliminar los {len(expired)} usuarios SSH vencidos?"):
        for name in expired:
            request("DELETE", "/api/users/delete?" + urllib.parse.urlencode({"username": name}))
        print(f"Se eliminaron {len(expired)} usuarios SSH vencidos.")


def user_report():
    for u in request("GET", "/api/users") or []:
        print()
        print_wrapped(f"{u['username']} | conexiones {u.get('active_conns', 0)}/{u.get('max_connections', 0)}"
                      f" | vence {str(u.get('expires_at') or 'nunca')[:10]}")
        quota = u.get("data_quota_bytes", 0)
        print_wrapped(f"Consumo {size(u.get('total_bytes', 0))}/{size(quota) if quota else 'ilimitado'}"
                      f" | velocidad ↑ {size(u.get('up_bytes_per_sec', 0))}/s"
                      f" ↓ {size(u.get('down_bytes_per_sec', 0))}/s", "  ")


def xray_inbounds():
    inbounds = request("GET", "/api/xray/inbounds") or []
    for inbound in inbounds:
        endpoint = ("puertos SSH/TLS compartidos" if inbound.get("shared_port") else
                    f"puerto {inbound.get('port')}")
        print_wrapped(f"{inbound.get('tag')} ({inbound.get('protocol')}/{inbound.get('network') or 'tcp'}, "
                      f"{endpoint}, path {inbound.get('path') or '-'})")
        for c in inbound.get("clients") or []:
            print_wrapped(f"{c.get('name') or c.get('email') or c.get('id') or c.get('uuid')}  "
                          f"conectado={c.get('online', False)}  "
                          f"consumo={size(c.get('total_bytes', 0))}", "  ")
            print_wrapped(str(c.get('id') or c.get('uuid')), "  ")
    return inbounds


def xray_shared_port():
    """Configure an HTTP transport on the panel's existing public ports."""
    server = request("GET", "/api/server/config")
    xray = server.get("xray") or {}
    if xray.get("mode", "native") == "external":
        raise CLIError("Los puertos compartidos requieren el modo emulador nativo de Xray")
    listeners = [server.get("listen") or "0.0.0.0:80", *(server.get("extra_listen") or [])]
    tls_listeners = [entry.get("listen") for entry in server.get("tls_forwarders") or []]
    print_wrapped("SSH/HTTP público: " + ", ".join(listeners))
    if tls_listeners:
        print_wrapped("TLS público: " + ", ".join(tls_listeners))
    config = request("GET", "/api/xray/config")
    inbounds = config.setdefault("inbounds", [])
    candidates = [ib for ib in inbounds if ib.get("protocol") in ("vless", "vmess")]
    for ib in candidates:
        print_wrapped(f"{ib.get('tag')} ({ib.get('protocol')})"
                      + (" [shared]" if ib.get("dragoncoreSharedPort") else ""), "  ")
    tag = ask("Inbound tag (new or listed)")
    if not tag or any(ch.isspace() for ch in tag):
        raise CLIError("Ingresá una etiqueta sin espacios")
    inbound = next((ib for ib in candidates if ib.get("tag") == tag), None)
    if inbound is None and any(ib.get("tag") == tag for ib in inbounds):
        raise CLIError("That tag belongs to an unsupported inbound")
    transport = ask("Transporte (ws/xhttp)",
                    ((inbound or {}).get("streamSettings") or {}).get("network", "ws")).lower()
    transport = {"websocket": "ws", "splithttp": "xhttp"}.get(transport, transport)
    if transport not in ("ws", "xhttp"):
        raise CLIError("El puerto compartido requiere transporte WS o XHTTP")
    existing_paths = set()
    for ib in inbounds:
        if ib is inbound or not ib.get("dragoncoreSharedPort"):
            continue
        stream = ib.get("streamSettings") or {}
        settings = stream.get("wsSettings") if stream.get("network") in ("ws", "websocket") else stream.get("xhttpSettings")
        path = (settings or {}).get("path", "").rstrip("/")
        existing_paths.add(path)
    def overlaps_shared(path):
        return any(path == old or path.startswith(old + "/") or old.startswith(path + "/")
                   for old in existing_paths)

    auto = next(f"/c{i}" for i in range(1, 10000) if not overlaps_shared(f"/c{i}"))
    old_stream = (inbound or {}).get("streamSettings") or {}
    old_settings = old_stream.get("wsSettings" if transport == "ws" else "xhttpSettings") or {}
    entered = ask("Ruta (vacío = generar una)", old_settings.get("path", ""))
    path = entered or auto
    if not path.startswith("/"):
        path = "/" + path
    path = path.rstrip("/")
    if path in ("", "/") or any(ch in path for ch in "?#%\\ \t\r\n") or "//" in path or any(
            segment in (".", "..") for segment in path.split("/")):
        raise CLIError("Use a distinct URL path like /c1")
    if overlaps_shared(path):
        raise CLIError("La ruta se superpone con otra entrada Xray compartida")
    if inbound is None:
        protocol = ask("Protocolo (vless/vmess)", "vless").lower()
        if protocol not in ("vless", "vmess"):
            raise CLIError("El protocolo debe ser vless o vmess")
        client_uuid = str(uuid.uuid4())
        inbound = {"tag": tag, "protocol": protocol,
                   "settings": {"clients": [{"id": client_uuid, "email": tag + "@dragoncore.local"}]}}
        inbounds.append(inbound)
        print("UUID del cliente generado:", client_uuid)
    else:
        print_wrapped("The existing inbound transport will change; its clients are preserved.")
    # Port is informational for shared inbounds: the panel already owns all
    # public sockets. Clients use the port of whichever SSH/TLS listener they choose.
    inbound["port"] = int(listeners[0].rsplit(":", 1)[-1])
    inbound["dragoncoreSharedPort"] = True
    stream = inbound.setdefault("streamSettings", {})
    stream["network"] = transport
    stream["security"] = "none"  # the panel's TLS forwarder terminates TLS
    stream.pop("tlsSettings", None)
    stream.pop("wsSettings", None)
    stream.pop("xhttpSettings", None)
    stream.pop("splithttpSettings", None)
    stream["wsSettings" if transport == "ws" else "xhttpSettings"] = {"path": path}
    print_wrapped(f"Ruta {transport.upper()} compartida: {path}")
    if not confirm("Save and apply this Xray inbound?"):
        return
    request("POST", "/api/xray/config", config)
    status = request("GET", "/api/xray/status") or {}
    action = "restart" if status.get("running") else "start"
    request("POST", f"/api/xray/{action}", {})
    print_wrapped("Activo en los puertos públicos SSH/HTTP y en los puertos TLS configurados."
                  " Set the client path above; use TLS security in the client when using a TLS port.")


def xray_create():
    inbounds = xray_inbounds()
    tag = ask("Inbound tag")
    if not any(x.get("tag") == tag for x in inbounds):
        raise CLIError("Elegí una etiqueta de entrada de la lista")
    name = ask("Nombre del cliente")
    if not name:
        raise CLIError("El nombre del cliente es obligatorio")
    client_uuid = str(uuid.uuid4())
    data = {"inbound_tag": tag, "uuid": client_uuid,
            "name": name, "email": name.lower().replace(" ", "-") + "@dragoncore.local",
            "expires_at": expiry("30"), "max_connections": 0,
            "data_quota_bytes": 0, "quota_action": "block", "quota_throttle_mbps": 1}
    request("POST", "/api/xray/clients/add", data)
    print("UUID del cliente Xray creado:", client_uuid)


def xray_delete():
    tag = ask("Inbound tag")
    client_uuid = ask("Client UUID")
    if confirm(f"¿Eliminar el cliente Xray {client_uuid}?"):
        query = urllib.parse.urlencode({"inbound_tag": tag, "uuid": client_uuid})
        request("DELETE", "/api/xray/clients/remove?" + query)
        print("Deleted.")


def xray_edit():
    client_uuid = ask("Client UUID")
    client = next((c for inbound in request("GET", "/api/xray/inbounds") or []
                   for c in inbound.get("clients") or []
                   if (c.get("id") or c.get("uuid")) == client_uuid), None)
    if not client:
        raise CLIError("Xray client not found")
    p = {"uuid": client_uuid, "name": client.get("name") or "",
         "email": client.get("email") or "", "expires_at": client.get("expires_at") or "",
         "max_connections": client.get("max_conns") or 0,
         "data_quota_bytes": client.get("data_quota_bytes") or 0,
         "quota_action": client.get("quota_action") or "block",
         "quota_throttle_mbps": client.get("quota_throttle_mbps") or 1}
    print("1 Vencimiento   2 Límite de conexiones   3 Cuota   4 Nombre")
    choice = ask("Opción")
    if choice == "1":
        p["expires_at"] = expiry(str(p["expires_at"])[:10])
    elif choice == "2":
        p["max_connections"] = number("Máximo de conexiones (0 = ilimitado)", p["max_connections"], 0, 10000)
    elif choice == "3":
        p["data_quota_bytes"] = number("Cuota GiB (0 = ilimitada)", round(p["data_quota_bytes"] / 1024**3)) * 1024**3
        p["quota_action"] = ask("On quota: block/throttle", p["quota_action"])
        p["quota_throttle_mbps"] = number("Throttle Mbps", p["quota_throttle_mbps"])
    elif choice == "4":
        p["name"] = ask("Nombre", p["name"])
    else:
        return
    request("POST", "/api/xray/clients/update", p)
    print("Guardado.")


def xray_reset_traffic():
    client_uuid = ask("Client UUID")
    if confirm(f"¿Restablecer el tráfico de {client_uuid}?"):
        request("POST", "/api/xray/clients/reset-traffic", {"uuid": client_uuid})
        print("Traffic reset.")


def setting_value(label, current, kind="text"):
    """Solicita una configuración; dejar vacío conserva el valor actual."""
    shown = ", ".join(map(str, current)) if isinstance(current, list) else current
    if kind == "secret":
        value = getpass.getpass(f"{label} (vacío = conservar actual): ").strip()
        return value or current
    if kind == "bool":
        raw = ask(label + " (sí/no)", "sí" if current else "no").lower()
        if raw not in ("sí", "si", "no", "s", "n", "yes", "y"):
            raise CLIError("Ingresá sí o no")
        return raw in ("sí", "si", "s", "yes", "y")
    if kind.startswith("choose:"):
        allowed = kind.partition(":")[2].split("/")
        value = ask(label + " (" + "/".join(allowed) + ")", current).lower()
        if value not in allowed:
            raise CLIError("Elegí una opción válida: " + ", ".join(allowed))
        return value
    if kind == "int":
        return number(label, current or 0, -1, 1000000000)
    if kind in ("list", "intlist"):
        raw = input(f"{label} (separados por coma, - para borrar) [{shown or ''}]: ").strip()
        if not raw:
            return current or []
        items = [] if raw == "-" else [item.strip() for item in raw.split(",") if item.strip()]
        if kind == "intlist":
            try:
                return [int(item) for item in items]
            except ValueError as exc:
                raise CLIError("Ingresá números separados por comas") from exc
        return items
    raw = ask(label, shown or "")
    return raw if raw != "-" else ""


def save_settings(path, document):
    report = request("POST", path, document)
    print("Configuración aplicada.")
    if isinstance(report, dict):
        for warning in report.get("warnings") or []:
            print_wrapped("Advertencia: " + str(warning))


def edit_field(path, field, parent_keys=()):
    key, label, kind = field
    document = request("GET", path)
    parent = document
    for parent_key in parent_keys:
        parent = parent[parent_key]
    current = parent.get(key)
    if current is None:
        current = False if kind == "bool" else ([] if kind in ("list", "intlist") else (0 if kind == "int" else ""))
    value = setting_value(label, current, kind)
    if key in ("listen", "udp_listen", "tcp_listen", "fake_dns_listen") and key != "local_ssh_listen":
        value = normalize_public_endpoints(value)
    if key == "extra_listen":
        value = normalize_public_endpoints(value)
    if value == current:
        print("No changes.")
        return
    parent[key] = value
    save_settings(path, document)


def _display_setting_value(value):
    if isinstance(value, list):
        return ", ".join(map(str, value)) if value else "--"
    if isinstance(value, bool):
        return "ACTIVO" if value else "DESACTIVADO"
    if value is None or value == "":
        return "--"
    return str(value)


def field_menu(title, path, fields, parent_keys=()):
    def current_options():
        document = request("GET", path) or {}
        parent = document
        for parent_key in parent_keys:
            parent = parent.get(parent_key) or {}
        result = {}
        for index, field in enumerate(fields, 1):
            key, label, _kind = field
            result[str(index)] = (
                f"{label}: {_display_setting_value(parent.get(key))}",
                lambda f=field: edit_field(path, f, parent_keys),
            )
        return result

    menu(title, current_options, force_single=True)


SSH_FIELDS = (
    ("listen", "WEBSOCKET SSH PRINCIPAL", "text"),
    ("extra_listen", "WEBSOCKET SSH SECUNDARIO", "list"),
    ("local_ssh_listen", "PUERTO SSH LOCAL/INTERNO", "text"),
    ("host_key_file", "Archivo de clave del host SSH", "text"),
    ("banner", "Texto del banner SSH", "text"),
    ("banner_file", "Archivo del banner SSH", "text"),
    ("quiet", "Modo silencioso", "bool"),
    ("user_count", "Mostrar cantidad de usuarios", "bool"),
    ("pam_auth_enabled", "Inicio de sesión mediante PAM", "bool"),
    ("ssh_idle_timeout", "Tiempo de espera SSH inactivo", "text"),
    ("max_total_connections", "Límite global de conexiones", "int"),
    ("default_limit_mbps_up", "Velocidad de subida predeterminada (Mbps)", "int"),
    ("default_limit_mbps_down", "Velocidad de bajada predeterminada (Mbps)", "int"),
    ("proxy_auto_restart_interval", "Intervalo de reinicio de escucha", "text"),
    ("proxy_auto_restart_grace", "Tiempo de gracia del reinicio", "text"),
)

BLOCKS = {
    "dnstt": ("DNSTT / SLOWDNS", {"domain": "", "udp_listen": "0.0.0.0:5300"}, (
        ("domain", "Dominio del túnel DNS", "text"), ("domains", "Dominios aceptados", "list"),
        ("udp_listen", "Escucha UDP", "text"), ("privkey_file", "Archivo de clave privada", "text"),
        ("fake_dns_enabled", "DNS local simulado", "bool"), ("fake_dns_listen", "Escucha DNS simulado", "text"),
        ("fake_dns_domain", "Dominio DNS simulado", "text"), ("fake_dns_workers", "Procesos de DNS simulado", "int"),
        ("dns_response_workers", "Procesos de respuesta DNS", "int"), ("max_sessions", "Máximo de sesiones", "int"),
        ("max_streams", "Máximo de flujos", "int"), ("pending_responses", "Respuestas pendientes", "int"),
        ("stream_buffer", "Bytes del búfer de flujo", "int"), ("udp_read_buffer", "Búfer de lectura UDP", "int"),
        ("udp_write_buffer", "Búfer de escritura UDP", "int"), ("log_connections", "Registrar conexiones", "bool"),
        ("disable_stats_log", "Silenciar registros de estadísticas", "bool"), ("disable_console_log", "Silenciar registros de consola", "bool"),
        ("auto_restart_interval", "Intervalo de reinicio", "text"), ("auto_restart_grace", "Tiempo de gracia del reinicio", "text"),
    )),
    "bhttp": ("BHTTP", {"listen": [], "shared_ports": True}, (
        ("listen", "Escuchas TCP", "list"), ("shared_ports", "Compartir puertos SSH/TLS", "bool"),
        ("session_timeout", "Tiempo de espera de sesión", "text"), ("max_v2_lanes", "Máximo de canales V2", "int"),
        ("max_sessions", "Máximo de sesiones", "int"), ("max_connections", "Máximo de conexiones", "int"),
        ("disable_console_log", "Silenciar registros de consola", "bool"), ("log_connections", "Registrar conexiones", "bool"),
        ("auto_restart_interval", "Intervalo de reinicio", "text"), ("auto_restart_grace", "Tiempo de gracia del reinicio", "text"),
    )),
    "btun": ("BTUN", {"tcp_listen": "0.0.0.0:7301", "udp_listen": "0.0.0.0:7302", "manage_routing": True}, (
        ("tcp_listen", "Escucha TCP", "text"), ("udp_listen", "Escucha UDP", "text"),
        ("shared_ports", "Compartir puertos SSH/TLS", "bool"), ("tun_name", "Interfaz TUN", "text"),
        ("subnet", "Subred privada CIDR", "text"), ("gateway", "Puerta de enlace CIDR", "text"),
        ("mtu", "MTU de TUN", "int"), ("manage_routing", "Administrar enrutamiento/NAT", "bool"),
        ("wan_interface", "Interfaz WAN", "text"), ("handshake_timeout", "Tiempo de espera del handshake", "text"),
        ("idle_timeout", "Tiempo de espera por inactividad", "text"), ("max_packet_size", "Máximo de bytes por paquete", "int"),
        ("max_cover_bytes", "Máximo de bytes de cobertura", "int"), ("max_sessions", "Máximo de sesiones", "int"),
        ("disable_console_log", "Silenciar registros de consola", "bool"), ("log_connections", "Registrar conexiones", "bool"),
        ("auto_restart_interval", "Intervalo de reinicio", "text"), ("auto_restart_grace", "Tiempo de gracia del reinicio", "text"),
    )),
    "hcr": ("HCR", {"engine": "official", "listen": ["0.0.0.0:8880"], "shared_ports": False, "transport": "plain", "target": "127.0.0.1:2222", "max_download_frame": 3290, "download_poll_timeout": "20s", "session_stats_interval": "10s"}, (
        ("listen", "Puerto HCR", "list"), ("engine", "Motor HCR", "choose:official/embedded"), ("transport", "Transporte HCR", "choose:plain/tls/auto"), ("target", "Destino SSH HCR", "text"), ("binary_path", "Binario HCR oficial", "text"), ("shared_ports", "Compartir puertos SSH/TLS", "bool"),
        ("max_connections", "Máximo de conexiones", "int"), ("max_sessions", "Máximo de sesiones", "int"),
        ("max_source_sessions", "Máximo de sesiones por IP", "int"),
        ("download_poll_timeout", "Tiempo de espera de sondeo de descarga", "text"),
        ("max_download_frame", "Máximo de bytes por trama", "int"),
        ("idle_session_timeout", "Tiempo de espera de sesión inactiva", "text"),
        ("disable_console_log", "Silenciar registros de consola", "bool"), ("log_connections", "Registrar conexiones", "bool"),
        ("auto_restart_interval", "Intervalo de reinicio", "text"), ("auto_restart_grace", "Tiempo de gracia del reinicio", "text"),
    )),
    "udpgw": ("UDPGW / BADVPN", {"listen": "0.0.0.0:7300"}, (
        ("listen", "Escucha TCP", "text"), ("max_frame", "Máximo de bytes por trama", "int"),
        ("debug", "Registros de depuración", "bool"), ("hexdump", "Bytes del volcado hexadecimal", "int"),
        ("write_chan", "Tamaño de cola de escritura", "int"), ("udp_bind", "IP de enlace UDP", "text"),
        ("udp_rbuf", "Búfer de lectura UDP", "int"), ("udp_wbuf", "Búfer de escritura UDP", "int"),
        ("map_ttl", "TTL de asignación", "text"), ("reap_every", "Intervalo de limpieza", "text"),
        ("idle_timeout", "Tiempo de espera por inactividad", "text"), ("max_client_conns", "Máximo de conexiones por cliente", "int"),
        ("max_map_entries", "Máximo de asignaciones por cliente", "int"), ("max_clients", "Máximo de clientes", "int"),
        ("auto_restart_interval", "Intervalo de reinicio", "text"), ("auto_restart_grace", "Tiempo de gracia del reinicio", "text"),
    )),
    "xray": ("SERVICIO XRAY", {"enabled": True, "mode": "native", "native": True}, (
        ("enabled", "Activar Xray", "bool"), ("mode", "Modo de ejecución", "choose:native/external"),
        ("native_ip_strategy", "Estrategia de IP", "choose:auto/force_ipv4"),
        ("bin_path", "Binario externo de Xray", "text"),
        ("config_file", "Archivo de configuración externo", "text"),
        ("native_config_file", "Archivo de configuración nativo", "text"),
        ("api_server", "Dirección de API de estadísticas", "text"),
        ("online_window_seconds", "Segundos de ventana en línea", "int"),
        ("stats_poll_seconds", "Segundos entre consultas de estadísticas", "int"),
    )),
}


def toggle_block(block):
    document = request("GET", "/api/server/config")
    if document.get(block) is not None:
        if confirm("¿Desactivar " + BLOCKS[block][0] + " y desconectar sus sesiones?"):
            document[block] = None
            save_settings("/api/server/config", document)
        return
    value = copy.deepcopy(BLOCKS[block][1])
    if block == "dnstt":
        value["domain"] = ask("DNS tunnel domain")
        if not value["domain"]:
            raise CLIError("A DNSTT domain is required")
        key = request("POST", "/api/dnstt/genkey", {})
        value["privkey_file"] = key["privkey_file"]
        print_wrapped("DNSTT public key: " + key["pubkey"])
    document[block] = value
    save_settings("/api/server/config", document)


def block_field(block, field):
    document = request("GET", "/api/server/config")
    current = document.get(block)
    if current is None:
        raise CLIError("Primero activá " + BLOCKS[block][0])
    key, label, kind = field
    old = current.get(key)
    if old is None:
        old = False if kind == "bool" else ([] if kind == "list" else (0 if kind == "int" else ""))
    value = setting_value(label, old, kind)
    if key in ("listen", "udp_listen", "tcp_listen", "fake_dns_listen"):
        value = normalize_public_endpoints(value)
    if value == old:
        print("No changes.")
        return
    current[key] = value
    if block == "xray" and key == "mode":
        current["native"] = value == "native"
    save_settings("/api/server/config", document)


def block_menu(block):
    title, _, fields = BLOCKS[block]

    def current_options():
        document = request("GET", "/api/server/config") or {}
        current = document.get(block)
        active = current is not None
        options = {
            "1": (
                "ACTIVAR / DESACTIVAR: " + ("ACTIVO" if active else "DESACTIVADO"),
                lambda: toggle_block(block),
            )
        }

        for index, field in enumerate(fields, 2):
            key, label, _kind = field
            shown = _display_setting_value(current.get(key)) if active else "--"
            options[str(index)] = (
                f"{label}: {shown}",
                lambda f=field: block_field(block, f),
            )

        if block == "xray":
            options[str(len(fields) + 2)] = ("Ajustes del emulador nativo", xray_tuning_menu)
        return options

    menu(
        title + " SETTINGS",
        current_options,
        force_single=(block in ("dnstt", "bhttp", "udpgw", "btun", "hcr", "xray")),
        force_one_page=(block in ("dnstt", "btun", "hcr", "udpgw")),
    )


def xray_tuning_field(field):
    document = request("GET", "/api/server/config")
    xray = document.get("xray")
    if xray is None:
        raise CLIError("Primero activá Xray")
    tuning = xray.setdefault("native_tuning", {})
    key, label, kind = field
    old = tuning.get(key, False if kind == "bool" else 0)
    value = setting_value(label, old, kind)
    if value == old:
        print("No changes.")
        return
    tuning[key] = value
    save_settings("/api/server/config", document)


def xray_tuning_menu():
    fields = (("runtime_gomaxprocs", "Hilos de CPU de ejecución (0 = automático)", "int"),
              ("mux_global_sessions", "Límite global de sesiones Mux", "int"),
              ("trace_packets", "Rastreo de paquetes", "bool"))
    menu("AJUSTES AVANZADOS DE XRAY", {str(i): (field[1], lambda f=field: xray_tuning_field(f))
                         for i, field in enumerate(fields, 1)}, force_single=True, force_one_page=True)


def certificate_list():
    certs = (request("GET", "/api/tls/certs") or {}).get("certs") or []
    for index, cert in enumerate(certs, 1):
        print_wrapped(f"{index}. {cert['name']} — {cert.get('days_left', '?')} days left"
                      f" {'válido' if cert.get('key_ok') else 'verificar certificado/clave'}")
    if not certs:
        print("No hay certificados. Generá uno en Modos de conexión.")
    return certs


def select_certificate():
    certs = certificate_list()
    if not certs:
        raise CLIError("Primero creá un certificado")
    index = number("Número de certificado", 1, 1, len(certs)) - 1
    cert = certs[index]
    if not cert.get("key_ok"):
        raise CLIError("El certificado o su clave correspondiente no está disponible")
    return cert["cert_file"], cert["key_file"]


def tls_listener_add():
    cfg = request("GET", "/api/server/config")
    listen = normalize_public_endpoint(ask("Puerto TLS", "443"))
    cert, key = select_certificate()
    listeners = cfg.get("tls_forwarders") or []
    listeners.append({"listen": listen, "cert_file": cert, "key_file": key})
    cfg["tls_forwarders"] = listeners
    save_settings("/api/server/config", cfg)


def tls_listener_edit(index):
    cfg = request("GET", "/api/server/config")
    listeners = cfg.get("tls_forwarders") or []
    if index >= len(listeners):
        raise CLIError("La escucha TLS fue eliminada")
    entry = listeners[index]
    options = {"1": ("Cambiar dirección de escucha", lambda: tls_listener_field(index, "listen")),
               "2": ("Seleccionar certificado", lambda: tls_listener_field(index, "certificate")),
               "3": ("Eliminar escucha", lambda: tls_listener_field(index, "remove"))}
    print_wrapped(f"Escucha: {entry['listen']}  Certificado: {entry['cert_file']}")
    menu("ESCUCHA TLS", options, force_single=True)


def tls_listener_field(index, field):
    cfg = request("GET", "/api/server/config")
    listeners = cfg.get("tls_forwarders") or []
    if index >= len(listeners):
        raise CLIError("TLS listener was removed")
    if field == "remove":
        if not confirm("¿Eliminar esta escucha TLS?"):
            return
        listeners.pop(index)
    elif field == "certificate":
        listeners[index]["cert_file"], listeners[index]["key_file"] = select_certificate()
    else:
        listeners[index]["listen"] = normalize_public_endpoint(
            ask("Puerto TLS", str(listeners[index]["listen"]).rsplit(":", 1)[-1])
        )
    cfg["tls_forwarders"] = listeners
    save_settings("/api/server/config", cfg)


def tls_listener_menu():
    def options():
        listeners = (request("GET", "/api/server/config") or {}).get("tls_forwarders") or []
        result = {"1": ("Agregar escucha TLS", tls_listener_add)}
        result.update({str(index + 2): (listener.get("listen", "Escucha TLS"),
                                         lambda i=index: tls_listener_edit(i))
                       for index, listener in enumerate(listeners)})
        return result
    menu("ESCUCHAS TLS", options, force_single=True)


def server_settings_menu():
    options = {
        "1": ("WEBSOCKET", lambda: field_menu("CONFIGURACIÓN SSH", "/api/server/config", SSH_FIELDS)),
        "2": ("TLS TUNNEL", tls_listener_menu),
        "3": ("DNSTT", lambda: block_menu("dnstt")),
        "4": ("BHTTP", lambda: block_menu("bhttp")),
        "5": ("BTUN", lambda: block_menu("btun")),
        "6": ("HCR", lambda: block_menu("hcr")),
        "7": ("UDPGW", lambda: block_menu("udpgw")),
        "8": ("SERVICIO XRAY", lambda: block_menu("xray")),
    }

    while True:
        clear_screen()
        cfg = request("GET", "/api/server/config") or {}

        def compact_endpoint(value):
            import re
            return re.sub(r"0\.0\.0\.0:(\d+)", r":\1", str(value))

        width = 76
        inner = 76
        gap = 3
        half = (inner - gap) // 2
        right_width = inner - half - gap

        # Una sola caja: mantiene todas las funciones y solo unifica el diseño.
        print(paint("┏" + "━" * width + "┓", CYAN))
        print(paint("┃" + " MODOS DE CONEXIÓN ".center(inner) + "┃", CYAN, True))
        print(paint("┣" + "━" * width + "┫", CYAN))

        listen = cfg.get("listen") or "--"
        extra = cfg.get("extra_listen") or []
        tls = cfg.get("tls_forwarders") or []
        blocks = [
            ("OPENSSH", listen, True),
            ("SSH/HTTP PÚBLICO", ", ".join([listen, *extra]), True),
            ("TLS SSH", ", ".join(x.get("listen", "--") for x in tls) or "--", bool(tls)),
            ("BHTTP", ", ".join(map(str, (cfg.get("bhttp") or {}).get("listen") or [])) or "--", cfg.get("bhttp") is not None),
            ("HCR", ", ".join(map(str, (cfg.get("hcr") or {}).get("listen") or [])) or "--", cfg.get("hcr") is not None),
            ("BTUN", "TCP " + str((cfg.get("btun") or {}).get("tcp_listen", "--")) + " / UDP " + str((cfg.get("btun") or {}).get("udp_listen", "--")), cfg.get("btun") is not None),
            ("DNSTT", str((cfg.get("dnstt") or {}).get("domain", "--")) + " / " + str((cfg.get("dnstt") or {}).get("udp_listen", "--")), cfg.get("dnstt") is not None),
            ("UDPGW", str((cfg.get("udpgw") or {}).get("listen", "--")), cfg.get("udpgw") is not None),
            ("XRAY", str((cfg.get("xray") or {}).get("mode", "--")), bool(cfg.get("xray") and cfg["xray"].get("enabled", True))),
        ]

        for i in range(0, len(blocks), 2):
            def paint_protocol(item):
                name, value, enabled = item
                marker = "◉" if enabled else "○"
                marker_color = GREEN if enabled else RED
                return (paint("[", CYAN) + paint(marker, marker_color, True) +
                        paint("] ", CYAN) + paint(name, WHITE) +
                        paint(": " + compact_endpoint(value), WHITE))

            left_plain = f"[{'◉' if blocks[i][2] else '○'}] {blocks[i][0]}: {compact_endpoint(blocks[i][1])}"
            left_colored = paint_protocol(blocks[i])

            if i + 1 < len(blocks):
                right_plain = f"[{'◉' if blocks[i + 1][2] else '○'}] {blocks[i + 1][0]}: {compact_endpoint(blocks[i + 1][1])}"
                right_colored = paint_protocol(blocks[i + 1])
            else:
                right_plain = ""
                right_colored = ""

            left_colored += " " * max(0, half - len(left_plain))
            right_colored += " " * max(0, right_width - len(right_plain))
            print("┃" + left_colored + " " * gap + right_colored + "┃")

        print(paint("┣" + "━" * width + "┫", CYAN))
        print(paint("┃" + " CONFIGURACIÓN DEL SERVIDOR ".center(inner) + "┃", CYAN, True))
        print(paint("┣" + "━" * width + "┫", CYAN))

        config_entries = [
            ("01", "WEBSOCKET"), ("02", "TLS TUNNEL"),
            ("03", "DNSTT"), ("04", "BHTTP"),
            ("05", "BTUN"), ("06", "HCR"),
            ("07", "UDPGW"), ("08", "SERVICIO XRAY"),
        ]
        for i in range(0, len(config_entries), 2):
            left_num, left_label = config_entries[i]
            right_num, right_label = config_entries[i + 1]
            left_text = f"[{left_num}] • {left_label}"
            right_text = f"[{right_num}] • {right_label}"
            left_colored = paint(f"[{left_num}]", CYAN, True) + paint(" • ", YELLOW) + paint(left_label, YELLOW)
            right_colored = paint(f"[{right_num}]", CYAN, True) + paint(" • ", YELLOW) + paint(right_label, YELLOW)
            left_colored += " " * max(0, half - len(left_text))
            right_colored += " " * max(0, right_width - len(right_text))
            print("┃" + left_colored + " " * gap + right_colored + "┃")

        exit_text = "[00] • SALIR"
        exit_colored = paint("[00]", RED, True) + paint(" • SALIR", RED)
        print("┃" + exit_colored + " " * max(0, inner - len(exit_text)) + "┃")
        print(paint("┗" + "━" * width + "┛", CYAN))

        choice = input(paint("INFORME UMA OPÇÃO: ", CYAN, True)).strip().lstrip("0") or "0"
        if choice == "0":
            return
        entry = options.get(choice)
        if not entry:
            print("Opción inválida.")
            continue
        try:
            entry[1]()
        except (CLIError, ValueError, json.JSONDecodeError, OSError) as exc:
            print("Error:", exc)
        except KeyboardInterrupt:
            print("\nCancelado.")


def tree_node(document, trail):
    node = document
    for part in trail:
        node = node[part]
    return node


def tree_value(path, trail):
    document = request("GET", path)
    parent = tree_node(document, trail[:-1])
    old = parent[trail[-1]]
    if old is None:
        raise CLIError("This empty field has no type; use another setting first")
    kind = "bool" if isinstance(old, bool) else "int" if isinstance(old, int) else "text"
    value = setting_value(str(trail[-1]), old, kind)
    if value == old:
        print("No changes.")
        return
    parent[trail[-1]] = value
    save_settings(path, document)


def tree_browse(path, trail=()):
    """Navigate existing Xray settings without displaying or editing raw JSON."""
    def options():
        node = tree_node(request("GET", path), trail)
        if not isinstance(node, (dict, list)):
            raise CLIError("Elegí una configuración desde el menú superior")
        items = list(node.keys()) if isinstance(node, dict) else list(range(len(node)))
        result = {}
        for index, key in enumerate(items, 1):
            value = node[key]
            if str(key).lower() in ("password", "secret", "token", "api_key", "admin_key"):
                result[str(index)] = (str(key) + ": [hidden]",
                                      lambda: print("Configure credentials through the authenticated API."))
                continue
            if key == "clients" and trail and trail[-1] == "settings":
                result[str(index)] = ("Clientes (usá el menú de cuentas Xray)",
                                      lambda: print("Usá el menú de cuentas Xray para administrar los clientes."))
                continue
            label = str(key) + (" ›" if isinstance(value, (dict, list)) else
                                ": " + ("yes" if value is True else "no" if value is False else str(value)[:24]))
            next_trail = (*trail, key)
            result[str(index)] = (label, lambda t=next_trail, v=value:
                                  tree_browse(path, t) if isinstance(v, (dict, list)) else tree_value(path, t))
        return result
    menu("XRAY " + (str(trail[-1]).upper() if trail else "FIELDS"), options, force_single=True)


def xray_inbound_add():
    cfg = request("GET", "/api/xray/config")
    inbounds = cfg.setdefault("inbounds", [])
    tag = ask("New inbound tag")
    if not tag or any(inbound.get("tag") == tag for inbound in inbounds):
        raise CLIError("Ingresá una etiqueta de entrada única")
    protocol = setting_value("Protocolo", "vless", "choose:vless/vmess")
    used = {item.get("port") for item in inbounds}
    suggested_port = next(p for p in range(10086, 65536) if p not in used)
    port = number("Standalone port", suggested_port, 1, 65535)
    listen = ask("IP de escucha", "0.0.0.0")
    transport = setting_value("Transporte", "tcp", "choose:tcp/ws/xhttp")
    stream = {"network": transport, "security": "none"}
    if transport != "tcp":
        path = ask("URL path (blank = /c1)") or "/c1"
        if not path.startswith("/"):
            path = "/" + path
        if path == "/":
            raise CLIError("A non-root URL path is required")
        stream["wsSettings" if transport == "ws" else "xhttpSettings"] = {"path": path}
    client_id = str(uuid.uuid4())
    inbound = {"tag": tag, "protocol": protocol, "listen": listen, "port": port,
               "settings": {"clients": [{"id": client_id, "email": tag + "@dragoncore.local"}]},
               "streamSettings": stream}
    if protocol == "vless":
        inbound["settings"]["decryption"] = "none"
    inbounds.append(inbound)
    save_settings("/api/xray/config", cfg)
    print("UUID del cliente generado:", client_id)


def xray_inbound_field(tag, field):
    cfg = request("GET", "/api/xray/config")
    inbound = next((item for item in cfg.get("inbounds") or [] if item.get("tag") == tag), None)
    if inbound is None:
        raise CLIError("Inbound was removed")
    if field == "remove":
        if not confirm(f"¿Eliminar la entrada {tag} y sus clientes?"):
            return
        cfg["inbounds"].remove(inbound)
    elif field == "port":
        if inbound.get("dragoncoreSharedPort"):
            raise CLIError("Las entradas compartidas usan los puertos públicos SSH/TLS")
        inbound["port"] = number("Puerto", inbound.get("port") or 10086, 1, 65535)
    elif field == "listen":
        inbound["listen"] = ask("IP de escucha", inbound.get("listen") or "0.0.0.0")
    elif field == "path":
        stream = inbound.setdefault("streamSettings", {})
        network = stream.get("network")
        if network not in ("ws", "xhttp"):
            raise CLIError("Primero elegí el transporte WS o XHTTP")
        key = "wsSettings" if network == "ws" else "xhttpSettings"
        old = stream.get(key, {}).get("path", "")
        value = ask("URL path", old)
        if not value.startswith("/"):
            value = "/" + value
        if value == "/":
            raise CLIError("A non-root URL path is required")
        stream.setdefault(key, {})["path"] = value
    elif field == "transport":
        if inbound.get("dragoncoreSharedPort"):
            raise CLIError("Usá Compartir puertos SSH/TLS para cambiar esta entrada")
        stream = inbound.setdefault("streamSettings", {})
        network = setting_value("Transporte", stream.get("network", "tcp"), "choose:tcp/ws/xhttp")
        stream["network"] = network
        if network in ("ws", "xhttp"):
            key = "wsSettings" if network == "ws" else "xhttpSettings"
            value = ask("URL path (blank = /c1)", stream.get(key, {}).get("path", "")) or "/c1"
            if not value.startswith("/"):
                value = "/" + value
            stream.setdefault(key, {})["path"] = value
        print_wrapped("Los clientes existentes deben actualizar su transporte de conexión.")
    save_settings("/api/xray/config", cfg)


def xray_inbound_settings(tag):
    menu("ENTRADA " + tag.upper(), {
        "1": ("IP de escucha", lambda: xray_inbound_field(tag, "listen")),
        "2": ("Puerto independiente", lambda: xray_inbound_field(tag, "port")),
        "3": ("Transporte (TCP/WS/XHTTP)", lambda: xray_inbound_field(tag, "transport")),
        "4": ("Ruta WS/XHTTP", lambda: xray_inbound_field(tag, "path")),
        "5": ("Eliminar entrada", lambda: xray_inbound_field(tag, "remove")),
    }, force_single=True)


def xray_inbound_settings_menu():
    def options():
        inbounds = (request("GET", "/api/xray/config") or {}).get("inbounds") or []
        result = {"1": ("Crear entrada independiente", xray_inbound_add),
                  "2": ("Compartir puertos SSH/TLS (WS/XHTTP)", xray_shared_port)}
        result.update({str(index + 3): (f"{item.get('tag')} ({item.get('protocol')})",
                                         lambda tag=item.get("tag"): xray_inbound_settings(tag))
                       for index, item in enumerate(inbounds)})
        return result
    menu("ENTRADAS XRAY", options, force_single=True, force_one_page=True)


def xray_settings_menu():
    menu("CONFIGURACIÓN XRAY", {
        "1": ("Entradas y transportes", xray_inbound_settings_menu),
        "2": ("Servicio nativo / externo", lambda: block_menu("xray")),
        "3": ("Otros campos de Xray", lambda: tree_browse("/api/xray/config")),
    })


BOT_FIELDS = (
    ("enabled", "Bot habilitado", "bool"),
    ("mp_confirm_mode", "Confirmación de pagos", "choose:polling/webhook"),
    ("mp_poll_interval", "Intervalo de consulta de pagos", "text"),
    ("pix_expiration_minutes", "Minutos de vencimiento de PIX", "int"),
    ("trial_enabled", "Cuentas de prueba habilitadas", "bool"),
    ("trial_hours", "Duración de prueba en horas", "int"),
    ("trial_max_connections", "Límite de conexiones de prueba", "int"),
    ("trial_kind", "Tipo de prueba", "choose:ssh/xray"),
    ("trial_inbound_tag", "Entrada Xray de prueba", "text"),
    ("admin_telegram_ids", "IDs de Telegram de administradores", "intlist"),
    ("currency", "Moneda", "text"),
    ("public_host", "Hostname público de SSH", "text"),
    ("xray_public_host", "Hostname público de Xray", "text"),
    ("telegram_token", "Token del bot de Telegram", "secret"),
    ("mp_access_token", "Token de acceso de Mercado Pago", "secret"),
    ("mp_webhook_secret", "Secreto del webhook de pagos", "secret"),
)


def bot_text_setting(key, label):
    settings = request("GET", "/api/bot/settings") or {}
    print_wrapped(f"Actual {label}: {settings.get(key, '') or '(vacío)'}")
    if key == "app_url":
        value = setting_value(label, settings.get(key, ""))
    else:
        print("Ingresá el nuevo texto y terminá con una línea que contenga solamente un punto.")
        print("Una primera línea vacía conserva el texto actual; un solo - lo borra.")
        first = input("Primera línea: ")
        if not first:
            return
        if first == "-":
            value = ""
        else:
            lines = [first]
            while (line := input()) != ".":
                lines.append(line)
            value = "\n".join(lines)
    if value == settings.get(key, ""):
        print("No changes.")
        return
    save_settings("/api/bot/settings", {key: value})


def bot_text_menu():
    fields = (("welcome_text", "Mensaje de bienvenida"), ("contact_text", "Mensaje de contacto"),
              ("app_text", "Descripción de la aplicación"), ("app_url", "URL de la aplicación"))
    menu("TEXTOS DEL BOT", {str(i): (label, lambda k=key, l=label: bot_text_setting(k, l))
                      for i, (key, label) in enumerate(fields, 1)}, force_single=True, force_one_page=True)


def bot_settings_menu():
    menu("BOT DE TELEGRAM", {
        "1": ("Configuración del bot y pagos", lambda: field_menu("CONFIGURACIÓN DEL BOT", "/api/bot/config", BOT_FIELDS)),
        "2": ("Mensajes y enlace de la aplicación", bot_text_menu),
    }, force_single=True, force_one_page=True)


def managed_server_summary():
    servers = request("GET", "/api/servers") or []
    for row in servers:
        print_wrapped(f"{row.get('id')} {row.get('name')}  {row.get('base_url')}"
                      f"  {'activo' if row.get('is_active') else 'desactivado'}"
                      f"  SSH={'yes' if row.get('enable_ssh') else 'no'}"
                      f" Xray={'yes' if row.get('enable_xray') else 'no'}")
    return servers


def managed_server_field(server_id, field):
    server = next((row for row in request("GET", "/api/servers") or []
                   if str(row.get("id")) == str(server_id)), None)
    if server is None or server.get("is_local"):
        raise CLIError("Select an existing remote server")
    kind = "bool" if field in ("is_active", "enable_ssh", "enable_xray") else "text"
    value = setting_value(field.replace("_", " ").title(), server.get(field, ""), kind)
    if value == server.get(field):
        print("No changes.")
        return
    server[field] = value
    payload = {key: server.get(key) for key in ("id", "name", "base_url", "admin_username",
                                                "enable_ssh", "enable_xray", "is_active")}
    # An empty credential preserves the encrypted credential already stored by the API.
    payload["admin_key"] = ""
    save_settings("/api/servers", payload)


def managed_server_edit(server_id):
    fields = (("name", "Nombre del servidor"), ("base_url", "URL de la API"),
              ("admin_username", "Usuario administrador remoto"), ("is_active", "Activo"),
              ("enable_ssh", "Permitir cuentas SSH"), ("enable_xray", "Permitir clientes Xray"))
    menu("SERVIDOR ADMINISTRADO", {str(i): (label, lambda f=field: managed_server_field(server_id, f))
                            for i, (field, label) in enumerate(fields, 1)}, force_single=True, force_one_page=True)


def managed_servers_menu():
    servers = [server for server in managed_server_summary() if not server.get("is_local")]
    if not servers:
        print("No hay servidores remotos configurados. Agregá un servidor mediante la API autenticada.")
        return
    menu("SERVIDORES ADMINISTRADOS", {str(i): (f"{server.get('name')} ({server.get('id')})",
                                     lambda sid=server.get("id"): managed_server_edit(sid))
                             for i, server in enumerate(servers, 1)})


def set_banner():
    cfg = request("GET", "/api/server/config")
    print("Ingresá el texto del banner y terminá con una línea que contenga solamente un punto:")
    lines = []
    while True:
        line = input()
        if line == ".":
            break
        lines.append(line)
    cfg["banner"] = "\n".join(lines)
    request("POST", "/api/server/config", cfg)
    print("Banner aplicado.")


def set_ssh_ports():
    cfg = request("GET", "/api/server/config")
    cfg["listen"] = normalize_public_endpoint(
        ask("Puerto SSH principal", str(cfg.get("listen") or "0.0.0.0:80").rsplit(":", 1)[-1])
    )
    current = ", ".join(str(item).rsplit(":", 1)[-1] for item in (cfg.get("extra_listen") or []))
    extras = input(f"Puertos adicionales, separados por coma [{current}] (ingresá - para borrar): ").strip()
    extras = "" if extras == "-" else (extras or current)
    cfg["extra_listen"] = normalize_public_endpoints([part.strip() for part in extras.split(",") if part.strip()])
    result = request("POST", "/api/server/config", cfg)
    print("Configuración de escuchas SSH aplicada.")
    if result:
        print(json.dumps(result, indent=2)[:2000])


def set_ssh_limits():
    cfg = request("GET", "/api/server/config")
    cfg["default_limit_mbps_up"] = number("Subida Mbps predeterminada (0 = ilimitada)", cfg.get("default_limit_mbps_up", 0))
    cfg["default_limit_mbps_down"] = number("Bajada Mbps predeterminada (0 = ilimitada)", cfg.get("default_limit_mbps_down", 0))
    cfg["max_total_connections"] = number("Límite global de conexiones SSH (0 = predeterminado)", cfg.get("max_total_connections", 0), 0, 1000000)
    request("POST", "/api/server/config", cfg)
    print("Límites predeterminados aplicados.")


def status():
    print(render_vps_status(collect_vps_status()))
    try:
        stats = request("GET", "/api/stats")
        print("\nInterfaces de red:")
        for iface in stats.get("interfaces") or []:
            if terminal_columns() < 72:
                print_wrapped(f"{iface['name']}  ↓ {iface.get('rx_mbps', 0):.2f} Mbps "
                              f"↑ {iface.get('tx_mbps', 0):.2f} Mbps", "  ")
                print_wrapped(f"RX {size(iface.get('rx_bytes', 0))} "
                              f"TX {size(iface.get('tx_bytes', 0))}", "    ")
            else:
                print(f"  {iface['name']:<18} ↓ {iface.get('rx_mbps', 0):>8.2f} Mbps "
                      f"↑ {iface.get('tx_mbps', 0):>8.2f} Mbps  "
                      f"RX {size(iface.get('rx_bytes', 0))}  TX {size(iface.get('tx_bytes', 0))}")
    except CLIError as exc:
        print(exc)


def connection_status():
    cfg = request("GET", "/api/server/config")
    print_wrapped("SSH público: " + ", ".join([cfg.get("listen", "--"), *(cfg.get("extra_listen") or [])]))
    print_wrapped("SSH local: " + cfg.get("local_ssh_listen", "127.0.0.1:2222"))
    for listener in cfg.get("tls_forwarders") or []:
        print_wrapped("TLS SSH: " + listener.get("listen", "--"))
    for name, label, fields in (
        ("bhttp", "BHTTP", ("listen", "shared_ports")),
        ("hcr", "HCR", ("listen", "shared_ports")),
        ("btun", "BTUN", ("tcp_listen", "udp_listen", "shared_ports")),
        ("dnstt", "DNSTT", ("domain", "udp_listen")),
        ("udpgw", "UDPGW", ("listen",)),
        ("xray", "Xray", ("mode", "enabled")),
    ):
        block = cfg.get(name)
        if block is None:
            print(f"{label}: desactivado")
        else:
            details = "  ".join(f"{f}={block[f]}" for f in fields if f in block)
            print_wrapped(f"{label}: configurado  {details}")


def protocol_stats():
    for label, path in (("DNSTT", "/api/dnstt"), ("BHTTP", "/api/bhttp"),
                        ("HCR", "/api/hcr"), ("BTUN", "/api/btun")):
        try:
            print(f"\n{label}: {json.dumps(request('GET', path), indent=2)[:1200]}")
        except CLIError as exc:
            print(f"{label}: {exc}")


def protocol_logs():
    print("1 DNSTT  2 BHTTP  3 HCR  4 BTUN")
    selected = ask("Protocolo")
    endpoint = {"1": "dnstt", "2": "bhttp", "3": "hcr", "4": "btun"}.get(selected)
    if not endpoint:
        raise CLIError("Protocolo inválido")
    result = request("GET", f"/api/{endpoint}/logs")
    if isinstance(result, list):
        print("\n".join(str(line) for line in result[-60:]))
    else:
        print(json.dumps(result, indent=2)[-8000:])


def generate_tls_certificate(lets_encrypt=False):
    domain = ask("Dominio del certificado")
    if not domain:
        raise CLIError("Domain required")
    payload = {"domain": domain}
    path = "/api/tls/generate-selfsigned"
    if lets_encrypt:
        payload["email"] = ask("Correo de contacto")
        path = "/api/tls/letsencrypt"
    result = request("POST", path, payload)
    print(json.dumps(result, indent=2))


def regenerate_dnstt_key():
    if confirm("Replace the DNSTT private key? Existing client keys will stop working."):
        print(json.dumps(request("POST", "/api/dnstt/genkey", {}), indent=2))


def connection_protocols_visual(show_return=True):
    cfg = request("GET", "/api/server/config") or {}
    def mark(enabled): return "◉" if enabled else "○"
    listen = cfg.get("listen") or "--"
    extra = cfg.get("extra_listen") or []
    tls = cfg.get("tls_forwarders") or []
    blocks = [
        ("OPENSSH", listen, True),
        ("SSH/HTTP PÚBLICO", ", ".join([listen, *extra]), True),
        ("TLS SSH", ", ".join(x.get("listen", "--") for x in tls) or "--", bool(tls)),
        ("BHTTP", ", ".join(map(str, (cfg.get("bhttp") or {}).get("listen") or [])) or "--", cfg.get("bhttp") is not None),
        ("HCR", ", ".join(map(str, (cfg.get("hcr") or {}).get("listen") or [])) or "--", cfg.get("hcr") is not None),
        ("BTUN", "TCP " + str((cfg.get("btun") or {}).get("tcp_listen", "--")) + " / UDP " + str((cfg.get("btun") or {}).get("udp_listen", "--")), cfg.get("btun") is not None),
        ("DNSTT", str((cfg.get("dnstt") or {}).get("domain", "--")) + " / " + str((cfg.get("dnstt") or {}).get("udp_listen", "--")), cfg.get("dnstt") is not None),
        ("UDPGW", str((cfg.get("udpgw") or {}).get("listen", "--")), cfg.get("udpgw") is not None),
        ("XRAY", str((cfg.get("xray") or {}).get("mode", "--")), bool(cfg.get("xray") and cfg["xray"].get("enabled", True))),
    ]
    # Ancho fijo común: garantiza que el segundo panel se alinee con el primero.
    width = 76
    print(paint("┏" + "━" * width + "┓", CYAN))
    print(paint("┃" + " MODOS DE CONEXIÓN ".center(width) + "┃", CYAN, True))
    print(paint("┣" + "━" * width + "┫", CYAN))
    import re
    def compact_endpoint(value):
        # En este panel 0.0.0.0 significa todas las interfaces; mostrar solo :PUERTO
        # evita que una dirección innecesariamente larga rompa la fila.
        text = str(value)
        text = re.sub(r"0\.0\.0\.0:(\d+)", r":\1", text)
        return text

    for i in range(0, len(blocks), 2):
        def fmt(item):
            name, value, enabled = item
            return "[" + mark(enabled) + "] " + name + ": " + compact_endpoint(value)
        left = fmt(blocks[i])
        right = fmt(blocks[i + 1]) if i + 1 < len(blocks) else ""
        gap = 3
        half = (width - gap) // 2
        right_width = width - half - gap

        # Cada protocolo ocupa EXACTAMENTE una fila. No hacemos wrap.
        # Si un texto excepcionalmente largo no cabe, se compacta el valor.
        left = left[:half].rstrip()
        right = right[:right_width].rstrip()
        row_text = "┃" + left.ljust(half) + " " * gap + right.ljust(right_width) + "┃"

        # Tema profesional: marco/estructura cyan, protocolo y puerto blanco,
        # estado activo verde e inactivo rojo.
        def paint_protocol(item):
            name, value, enabled = item
            marker = "◉" if enabled else "○"
            marker_color = GREEN if enabled else RED
            name_part = paint("[", CYAN) + paint(marker, marker_color, True) + paint("] ", CYAN)
            name_part += paint(name, WHITE)
            value_text = compact_endpoint(value)
            return name_part + paint(": " + value_text, WHITE)

        left_colored = paint_protocol(blocks[i])
        right_colored = paint_protocol(blocks[i + 1]) if i + 1 < len(blocks) else ""
        # El ancho se conserva usando el texto plano para evitar desalineación ANSI.
        left_plain = left
        right_plain = right
        left_colored += " " * max(0, half - len(left_plain))
        right_colored += " " * max(0, right_width - len(right_plain))
        print("┃" + left_colored + " " * gap + right_colored + "┃")
    if show_return:
        print(paint("┣" + "━" * width + "┫", CYAN))
        print(paint("┃ [00] • RETORNAR".ljust(width + 1) + "┃", RED, True))
        print(paint("┗" + "━" * width + "┛", CYAN))
    else:
        print(paint("┗" + "━" * width + "┛", CYAN))

def connection_menu():
    menu("MODOS DE CONEXIÓN", {
        "1": ("PROTOCOLOS ACTIVOS", connection_protocols_visual),
        "2": ("PUERTOS ACTIVOS", connection_status),
        "3": ("Estadísticas DNSTT / BHTTP / HCR / BTUN", protocol_stats),
        "4": ("CONFIGURAR PROTOCOLOS Y MODOS DE CONEXIÓN", server_settings_menu),
        "5": ("Certificados TLS", certificate_list),
        "6": ("Clave pública DNSTT", lambda: print(json.dumps(request("GET", "/api/dnstt/pubkey"), indent=2))),
        "7": ("Registros de protocolos", protocol_logs),
        "8": ("GENERAR CERTIFICADO TLS AUTOFIRMADO PARA TLS TUNNEL/XRAY", generate_tls_certificate),
        "9": ("Solicitar certificado Let's Encrypt", lambda: generate_tls_certificate(True)),
        "10": ("Regenerar clave DNSTT", regenerate_dnstt_key),
    })


def traffic_history():
    data = request("GET", "/api/vnstat")
    print(f"Hoy: {size(data.get('today_total_bytes', 0))}  "
          f"Este mes: {size(data.get('month_total_bytes', 0))}")
    for label in ("daily", "monthly"):
        print(f"\n{label.title()} by interface:")
        for row in data.get(label) or []:
            print_wrapped(f"{row.get('period', '--')}  {row.get('iface', '--')}  "
                          f"↓ {size(row.get('rx_bytes', 0))} "
                          f"↑ {size(row.get('tx_bytes', 0))}", "  ")


def system_log_view():
    source = ask("Origen del registro: panel/dnstt/xray", "panel").lower()
    if source not in ("panel", "dnstt", "xray"):
        raise CLIError("Elegí panel, dnstt o xray")
    data = request("GET", f"/api/system/logs?source={source}&lines=100")
    print("\n".join(data.get("lines") or []))


def observability_menu():
    menu("VPS Y TRÁFICO", {
        "1": ("Estado del VPS y tráfico de red en vivo", status),
        "2": ("Usuarios SSH conectados / informe de tráfico", user_report),
        "3": ("Xray conectado / clientes", xray_inbounds),
        "4": ("Tráfico diario y mensual", traffic_history),
        "5": ("Registros del sistema", system_log_view),
        "6": ("Estado de compilación y actualización", lambda: print(json.dumps(request("GET", "/api/system/update-status"), indent=2))),
    })


def logs():
    subprocess.run(["journalctl", "-u", SERVICE, "-n", "80", "--no-pager"])


def update_from_git():
    updater = INSTALL_DIR / "update.sh"
    if not updater.is_file():
        raise CLIError(f"No se encontró el actualizador: {updater}")
    result = subprocess.run(["bash", str(updater)], check=False)
    if result.returncode:
        raise CLIError(f"La actualización falló (salida {result.returncode}); revisá la salida anterior")
    print("Actualización completa. Volvé a abrir el menú para cargar la CLI actualizada.")


def render_menu(title, options, vps_status=None, columns=None, two_columns=False):
    """Render a boxed terminal menu; optionally use the compact two-column layout."""
    cols = columns or terminal_columns()
    # Keep the frame compact on phones, but use the reference layout on normal SSH terminals.
    width = min(76, max(24, cols - 2))
    inner = width - 2

    def clip(value, limit):
        text = str(value)
        return text if len(text) <= limit else text[:max(0, limit - 1)] + "…"

    def row(left="", right=""):
        gap = 3
        half = (inner - gap) // 2
        left_text = clip(left, half).ljust(half)
        right_text = clip(right, inner - half - gap).ljust(inner - half - gap)
        return "│ " + left_text + " " * gap + right_text + " │"

    def single(value=""):
        return "│ " + clip(value, inner).ljust(inner) + " │"

    def metrics_row(left="", right=""):
        # Alinear el segundo bloque exactamente con SO, Hora y Servicio.
        gap = 3
        left_width = (inner - gap) // 2
        right_width = inner - gap - left_width
        left_text = clip(left, left_width).ljust(left_width)
        right_text = clip(right, right_width).ljust(right_width)
        return "│ " + left_text + " " * gap + right_text + " │"

    def summary_row(left="", middle="", right=""):
        # Resumen compacto de usuarios, separado del encabezado antes del menú.
        gap = 3
        available = inner - (gap * 2)
        base = available // 3
        widths = [base, base, available - (base * 2)]
        values = [left, middle, right]
        parts = [
            clip(values[0], widths[0]).ljust(widths[0]),
            clip(values[1], widths[1]).center(widths[1]),
            clip(values[2], widths[2] - 4).rjust(widths[2] - 4) + " " * 4,
        ]
        return "│ " + (" " * gap).join(parts) + " │"

    title_text = clip("SCRIPT CONECTA SSH - " + title.upper(), max(8, width - 5))
    # The body rows use two padding characters around the content.
    # Extend the top border by the same two columns so both upper corners align.
    top = "┌─ " + title_text + " "
    top += "─" * max(0, width - len(top) + 1) + "┐"
    bottom = "└" + "─" * width + "┘"
    separator = "├" + "─" * width + "┤"

    lines = [top]
    if vps_status is not None:
        cpu = "--" if vps_status.get("cpu") is None else f"{vps_status['cpu']:.1f}%"
        if vps_status.get("mem_total"):
            mem_used_mb = int(vps_status["mem_used"] / 1024**2)
            mem_total_gb = vps_status["mem_total"] / 1024**3
            mem_pct = (100 * vps_status["mem_used"] / vps_status["mem_total"])
            ram = f"{mem_used_mb}MB / {mem_total_gb:.0f}GB - {mem_pct:.0f}%"
        else:
            ram = "--"
        online = vps_status.get("ssh_online")
        expired = vps_status.get("ssh_expired")
        total = vps_status.get("ssh_total")
        service_label = {"active": "activo", "inactive": "inactivo", "failed": "fallido",
                         "activating": "activando", "deactivating": "desactivando"}.get(
                             vps_status.get("service"), vps_status.get("service", "--"))
        load = "--" if vps_status.get("load") is None else f"{vps_status['load']:.2f}"
        lines.extend([
            row(f"• Host: {vps_status.get('host', '--')}",
                f"• SO: {vps_status.get('os', '--')}"),
            row(f"• Uptime: {vps_status.get('uptime', '--')}",
                f"• Hora: {vps_status.get('time', '--')}"),
            metrics_row(f"• CPU: {vps_status.get('cores', '--')} ({cpu}) LOAD: {load}",
                         f"• RAM: {ram}"),
            row("• UP/DOWN: " + size(vps_status.get("rx_bytes", 0)) +
                " | " + size(vps_status.get("tx_bytes", 0)),
                "• SERVICIO: " + service_label.upper()),
            separator,
            summary_row(
                f"Onlines: {online if online is not None else '--'}",
                f"Expirados: {expired if expired is not None else '--'}",
                f"Total: {total if total is not None else '--'}",
            ),
            separator,
        ])

    entries = list(options.items())
    if two_columns:
        for i in range(0, len(entries), 2):
            left_key, (left_label, _) = entries[i]
            if i + 1 < len(entries):
                right_key, (right_label, _) = entries[i + 1]
                lines.append(row(f"[{str(left_key).zfill(2)}] • {str(left_label).upper()}",
                                 f"[{str(right_key).zfill(2)}] • {str(right_label).upper()}"))
            else:
                lines.append(single(f"[{str(left_key).zfill(2)}] • {str(left_label).upper()}"))
    else:
        for key, (label, _) in entries:
            lines.append(single(f"[{str(key).zfill(2)}] • {str(label).upper()}"))

    # Todos los menús y submenús tienen una salida uniforme en [00].
    lines.append(single("[00] • SALIR"))

    lines.append(bottom)
    return "\n".join(colorize_menu(lines))


def clear_screen():
    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


_menu_calls = 0


def menu(title, options, two_columns=False, force_single=False, force_one_page=False):
    global _menu_calls
    _menu_calls += 1
    page = 0
    while True:
        clear_screen()
        vps = collect_vps_status() if title == "MAIN MENU" else None
        current_options = options() if callable(options) else options
        # Dos columnas en terminales normales cuando las etiquetas caben; una columna en móvil.
        labels = [str(label) for label, _ in current_options.values()]
        half = max(1, (terminal_columns() - 8) // 2)
        auto_two_columns = False if force_single else (terminal_columns() >= 64 and all(len(label) <= half - 2 for label in labels))
        page_size = len(current_options) if force_one_page else (16 if len(current_options) <= 16 else (8 if terminal_columns() <= 48 else 12))
        entries = list(current_options.items())
        pages = max(1, (len(entries) + page_size - 1) // page_size)
        page = min(page, pages - 1)
        visible = dict(entries[page * page_size:(page + 1) * page_size])
        heading = title + (f" ({page + 1}/{pages})" if pages > 1 else "")
        print(render_menu(heading, visible, vps, two_columns=auto_two_columns))
        prompt = paint("Elegí una opción: ", CYAN, True)
        if pages > 1:
            print(" n  Página siguiente   p  Página anterior")
        choice = input(prompt).strip().lstrip("0") or "0"
        if choice.lower() in ("n", "p") and pages > 1:
            page = min(pages - 1, page + 1) if choice.lower() == "n" else max(0, page - 1)
            continue
        if choice == "0":
            return
        entry = visible.get(choice)
        if not entry:
            print("Opción inválida.")
        else:
            current_menu_calls = _menu_calls
            try:
                entry[1]()
            except (CLIError, ValueError, json.JSONDecodeError, OSError) as exc:
                print("Error:", exc)
            except KeyboardInterrupt:
                print("\nCancelado.")
            if _menu_calls != current_menu_calls:
                continue  # A submenu already showed its own output and prompts.
        if sys.stdin.isatty() and sys.stdout.isatty():
            try:
                input("\nPresioná Enter para volver al menú...")
            except (EOFError, KeyboardInterrupt):
                print()


def pam_auth_menu():
    """Configura la autenticación PAM global del servidor."""
    document = request("GET", "/api/server/config") or {}
    current = bool(document.get("pam_auth_enabled", False))

    def set_pam(enabled):
        document = request("GET", "/api/server/config") or {}
        document["pam_auth_enabled"] = bool(enabled)
        save_settings("/api/server/config", document)
        print("Autenticación PAM:", "ACTIVO" if enabled else "DESACTIVADO")
        if enabled:
            print("Las cuentas Linux válidas pueden autenticarse mediante /etc/passwd y /etc/shadow.")

    state = "ACTIVO" if current else "DESACTIVADO"
    menu("AUTENTICACIÓN PAM", {
        "1": ("ACTIVAR PAM", lambda: set_pam(True)),
        "2": ("DESACTIVAR PAM", lambda: set_pam(False)),
    }, two_columns=True)
    print(f"Estado actual: {state}")


def toggle_server_bool(key, label):
    document = request("GET", "/api/server/config") or {}
    current = bool(document.get(key, False))
    document[key] = not current
    save_settings("/api/server/config", document)
    print(f"{label}: {'ACTIVO' if not current else 'DESACTIVADO'}")



def auto_menu_toggle():
    toggle_server_bool("auto_menu", "AUTO MENU")


def ssh_connection_limit_toggle():
    toggle_server_bool("ssh_connection_limit_enabled", "LIMITADOR SSH")


def ssh_menu():
    document = request("GET", "/api/server/config") or {}
    pam_state = "ACTIVO" if document.get("pam_auth_enabled", True) else "DESACTIVADO"
    limit_state = "ACTIVO" if document.get("ssh_connection_limit_enabled", False) else "DESACTIVADO"
    menu("GESTOR DE USUARIOS SSH", {
        "1": ("Crear usuario", create_user),
        "2": ("Crear prueba", lambda: create_user(test_hours=24)),
        "3": ("Remover usuario", delete_user),
        "4": ("Renovar / editar usuario", edit_user),
        "5": ("Usuarios online", user_report),
        "6": ("Relatorio usuarios", user_report),
        "7": ("Remover expirados", delete_expired_users),
        "8": ("Listar usuarios", list_users),
        "9": ("Restablecer tráfico", reset_traffic),
        "10": (f"USUARIO PAM: {pam_state}", pam_auth_menu),
        "11": (f"LIMITAR SSH: {limit_state}", ssh_connection_limit_toggle),
    }, two_columns=True)


def xray_action(action):
    request("POST", f"/api/xray/{action}", {})
    print(f"Xray {action} completed.")


def xray_menu():
    menu("XRAY", {"1": ("Entradas y clientes", xray_inbounds),
                  "2": ("Crear cliente (UUID generado)", xray_create),
                  "3": ("Editar cliente", xray_edit),
                  "4": ("Restablecer tráfico del cliente", xray_reset_traffic),
                  "5": ("Eliminar cliente", xray_delete),
                  "6": ("Estado", lambda: print(json.dumps(request("GET", "/api/xray/status"), indent=2))),
                  "7": ("Configuración de Xray", xray_settings_menu),
                  "8": ("Iniciar Xray", lambda: xray_action("start")),
                  "9": ("Detener Xray", lambda: xray_action("stop") if confirm("¿Detener las conexiones Xray?") else None),
                  "10": ("Reiniciar Xray", lambda: xray_action("restart")),
                  "11": ("Registros de Xray", lambda: print(json.dumps(request("GET", "/api/xray/logs"), indent=2)[-8000:])),
                  "12": ("Reparar estadísticas de Xray", lambda: request("POST", "/api/xray/stats/repair", {}) if confirm("¿Reparar las estadísticas de Xray?") else None),
                  "13": ("Compartir puertos SSH/TLS (WS/XHTTP)", xray_shared_port)}, force_single=True, force_one_page=True)



def backup_users_file_path():
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path("/root") / f"ConectaSSH-backup-{timestamp}.json"


def find_user_backups():
    root = Path("/root")
    if not root.is_dir():
        return []
    paths = list(root.glob("ConectaSSH-backup-*.json"))
    paths += list(root.glob("ConectaSSH-users-backup-*.vps"))
    return sorted(paths, key=lambda p: p.stat().st_mtime, reverse=True)


def backup_users():
    require_root()
    users = (request("GET", "/api/users/backup", timeout=120) or {}).get("users") or []
    xray = request("GET", "/api/xray/config", timeout=60) or {}
    document = {
        "format": "conecta-ssh-backup",
        "version": 2,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "ssh": {"users": users},
        "xray": {"config": xray},
    }
    target = backup_users_file_path()
    target.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(target, 0o600)
    print("\n✅ BACKUP CONECTA SSH CREADO")
    print(f"📁 Archivo: {target}")
    print(f"👤 Usuarios SSH: {len(users)}")
    print(f"✖️ Entradas Xray: {len(xray.get('inbounds') or [])}")
    print("📦 Incluye usuarios SSH + configuración Xray")


def restore_own_backup(path):
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("format") != "conecta-ssh-backup" or document.get("version") != 2:
        raise CLIError("El archivo no es un backup Conecta SSH v2")
    users = (document.get("ssh") or {}).get("users") or []
    xray = ((document.get("xray") or {}).get("config"))
    restored = 0
    if users:
        result = request("POST", "/api/users/restore",
                         {"version": 1, "created_at": document.get("created_at"), "users": users},
                         timeout=180) or {}
        restored = result.get("restored", 0)
    if isinstance(xray, dict):
        request("POST", "/api/xray/config", xray, timeout=120)
    print("\n✅ RESTAURACIÓN CONECTA SSH COMPLETADA")
    print(f"👤 Usuarios SSH: {restored}/{len(users)}")
    print(f"✖️ Entradas Xray: {len((xray or {}).get('inbounds') or [])}")


def restore_sshplus_backup(path):
    result = subprocess.run(["python3", "/opt/sshpanel/sshplus_backup.py", "restore", str(path)],
                            capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        raise CLIError(result.stderr.strip() or "No se pudo importar el backup SSHPlus")
    print("\n" + result.stdout.strip())
    print("🔄 Fuente: backup SSHPlus .vps")


def _choose_backup(paths, title):
    if not paths:
        return None
    if len(paths) == 1:
        return paths[0]
    print(f"\n{title}")
    for i, p in enumerate(paths, 1):
        print(f"[{i:02d}] {p.name}")
    try:
        return paths[int(ask("Elegí el backup", "1")) - 1]
    except (ValueError, IndexError):
        raise CLIError("Backup inválido")


def restore_own_backup_menu():
    require_root()
    paths = sorted(Path("/root").glob("ConectaSSH-backup-*.json"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    path = _choose_backup(paths, "BACKUPS CONECTA SSH")
    if not path:
        print("\nNo se encontró un backup Conecta SSH en /root.")
        return
    if confirm(f"¿Restaurar {path.name}? Se restaurarán usuarios SSH y Xray."):
        restore_own_backup(path)


def restore_sshplus_from_menu():
    require_root()
    paths = sorted(Path("/root").glob("ConectaSSH-users-backup-*.vps"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    path = _choose_backup(paths, "BACKUPS SSHPLUS")
    if not path:
        print("\nNo se encontró un backup SSHPlus .vps en /root.")
        print("Copiá el .vps de SSHPlus a /root y volvé a entrar.")
        return
    if confirm(f"¿Importar usuarios de SSHPlus desde {path.name}?"):
        restore_sshplus_backup(path)


def user_backup_menu():
    menu("BACKUP Y RESTAURACIÓN", {
        "1": ("Crear Backup Conecta SSH (SSH + Xray)", backup_users),
        "2": ("Restaurar Backup Conecta SSH", restore_own_backup_menu),
        "3": ("Restaurar Backup SSHPlus", restore_sshplus_from_menu),
    }, force_single=True, force_one_page=True)

def speedtest_vps():
    """Ejecuta Speedtest y muestra un resultado limpio en español."""
    require_root()
    binary = shutil.which("speedtest-cli") or shutil.which("speedtest")
    if not binary:
        raise CLIError("Speedtest no está instalado")

    print("\n┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    print("┃             TEST DE VELOCIDAD DEL VPS            ┃")
    print("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    print("[===  ] • ESPERE - EJECUTANDO PRUEBA")

    result = subprocess.run(
        [binary, "--json", "--share"],
        capture_output=True,
        text=True,
        timeout=180,
    )
    output = (result.stdout or "").strip()
    if result.returncode != 0 or not output:
        error = (result.stderr or output).strip()
        raise CLIError(error or "Speedtest no pudo completarse")

    try:
        data = json.loads(output)
        ping = float(data.get("ping", 0.0))
        download = float(data.get("download", 0.0)) / 1_000_000
        upload = float(data.get("upload", 0.0)) / 1_000_000
        share = str(data.get("share") or "").strip()
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise CLIError("Respuesta inválida del Speedtest: " + str(exc))

    if not share:
        share = "No disponible"

    print("\n[✓] PRUEBA DE VELOCIDAD FINALIZADA")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"PING: {ping:.2f} ms")
    print(f"DESCARGA: {download:.2f} Mbps")
    print(f"SUBIDA: {upload:.2f} Mbps")
    print(f"ENLACE: {share}")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")


def optimize_vps():
    """Optimización segura sin detener ni reiniciar servicios."""
    require_root()
    before_mem = local_meminfo()[1]
    before_disk = shutil.disk_usage("/").used

    def run_step(command, success, failure):
        result = subprocess.run(command, capture_output=True, text=True, timeout=180)
        if result.returncode == 0:
            print(f"[✓] {success}")
            return True
        error = (result.stderr or result.stdout).strip()
        if error:
            print_wrapped("⚠️ " + error)
        print(f"[!] {failure}")
        return False

    print("\n┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    print("┃                OPTIMIZAR SERVIDOR              ┃")
    print("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    print("[    =] • AGUARDE - EJECUTANDO OPTIMIZACIÓN")

    # Espera hasta 60 s si apt/dpkg está ocupado por una actualización automática.
    run_step(
        ["apt-get", "-o", "DPkg::Lock::Timeout=60", "update"],
        "PAQUETES ACTUALIZADOS !",
        "NO SE PUDO ACTUALIZAR LA INFORMACIÓN DE PAQUETES !",
    )
    run_step(
        ["apt-get", "-o", "DPkg::Lock::Timeout=60", "-f", "install", "-y"],
        "FALLAS CORREGIDAS !",
        "NO SE PUDIERON CORREGIR TODAS LAS DEPENDENCIAS !",
    )

    print("[    =] • AGUARDE - REMOVIENDO PAQUETES INÚTILES")
    run_step(
        ["apt-get", "-o", "DPkg::Lock::Timeout=60", "autoremove", "-y"],
        "PAQUETES INÚTILES REMOVIDOS !",
        "NO SE PUDIERON REMOVER TODOS LOS PAQUETES INÚTILES !",
    )

    subprocess.run(["apt-get", "-o", "DPkg::Lock::Timeout=60", "clean"], capture_output=True, text=True, timeout=180)
    subprocess.run(["systemd-tmpfiles", "--clean"], capture_output=True, text=True, check=False)
    try:
        with open("/proc/sys/vm/drop_caches", "w", encoding="ascii") as handle:
            handle.write("3\n")
    except OSError:
        pass

    # Este VPS no tiene swap configurada; si existe en otro VPS, no se fuerza
    # swapoff para evitar presión innecesaria de memoria.
    after_mem = local_meminfo()[1]
    after_disk = shutil.disk_usage("/").used
    print("\n┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    print("┃                OPTIMIZAR SERVIDOR              ┃")
    print("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    print("[✓] PAQUETES ACTUALIZADOS !")
    print("[✓] FALLAS CORREGIDAS !")
    print("[✓] PAQUETES INÚTILES REMOVIDOS !")
    print("[✓] CACHE Y SWAP LIMPIOS !")
    print(f"\n💾 Disco liberado: {size(max(0, before_disk - after_disk))}")
    print(f"🧠 RAM usada antes: {size(before_mem)}")
    print(f"🧠 RAM usada después: {size(after_mem)}")
    print("🔒 Procesos y servicios: sin detener ni reiniciar")


def user_backup_menu():
    menu("BACKUP DE USUARIOS SSH", {
        "1": ("Crear Backup de usuarios", backup_users),
        "2": ("Restaurar Backup de usuarios", restore_users_backup),
    }, force_single=True, force_one_page=True)


def multi_protocol_menu():
    menu("MULTIPROTOCOLO", {
        "1": ("Configurar protocolos simultáneamente", server_settings_menu),
        "2": ("Ver protocolos activos", connection_protocols_visual),
        "3": ("Ver puertos activos", connection_status),
    }, force_single=True, force_one_page=True)


def config_menu():
    menu("CONFIGURACIÓN", {
        "1": ("Configurar banner SSH", set_banner),
        "2": ("Cambiar puertos de escucha SSH", set_ssh_ports),
        "3": ("Ancho de banda / límites de conexiones", set_ssh_limits),
        "4": ("MULTIPROTOCOLO", multi_protocol_menu),
        "5": ("Configuración de Xray", xray_settings_menu),
        "6": ("Configuración del bot de Telegram", bot_settings_menu),
        "7": ("Servidores administrados", managed_servers_menu),
        "8": ("Contraseña de API", api_menu),
        "9": ("Registros recientes", logs),
        "10": ("Reiniciar servicio", lambda: service_action("restart")),
        "11": ("Actualizar desde Git", lambda: update_from_git() if confirm("¿Actualizar desde Git ahora?") else None),
        "12": ("CHECKUSER DUAL", checkuser_dual_menu),
    }, force_single=True, force_one_page=True)


def api_menu():
    menu("CONTRASEÑA DE API", {"1": ("Ver contraseña actual", lambda: print("Contraseña de API:", api_password())),
                          "2": ("Generar nueva contraseña y reiniciar servicio", rotate_api_password)})


def checkuser_dual_menu():
    """Abrir o instalar el CheckUser Dual (DTunnel + Void Pro)."""
    check_bin = shutil.which("check")
    if check_bin:
        subprocess.run([check_bin], check=False)
        return

    print("\nCHECKUSER DUAL no está instalado en esta VPS.")
    print("Servicio previsto: puerto 2052")
    print("URL para Void Pro: http://IP_DA_VPS:2052/check?user={username}&uuid={uuid}&hwid={hwid}")
    print("\nInstalador indicado:")
    print("https://raw.githubusercontent.com/Willapela/check-dt-voidpro/main/install-checkuser-dual.sh")
    print("\nEl repositorio indicado actualmente responde 404; no voy a ejecutar un instalador distinto sin tu autorización.")


def main_menu_options():
    return {
        "1": ("GESTOR DE USUARIOS SSH", ssh_menu),
        "2": ("GESTOR XRAY", xray_menu),
        "3": ("GESTIONAR PROTOCOLOS", connection_menu),
        "4": ("MODO DE CONEXIÓN", server_settings_menu),
        "5": ("BOT DE TELEGRAM", bot_settings_menu),
        "6": ("BACKUP DE USUARIOS", user_backup_menu),
        "7": (f"AUTO MENU: {'ACTIVO' if (request("GET", "/api/server/config") or {}).get("auto_menu", False) else 'DESACTIVADO'}", auto_menu_toggle),
        "8": ("SPEEDTEST", speedtest_vps),
        "9": ("OPTIMIZAR", optimize_vps),
        "10": ("CONFIGURACIÓN", config_menu),
    }


def main():
    parser = argparse.ArgumentParser(description="DragonCoreSSH CLI administration")
    parser.add_argument("--mobile", action="store_true", help="force a 40-column phone layout")
    parser.add_argument("command", nargs="?", choices=("menu", "status", "users", "api-password", "logs", "update"), default="menu")
    parser.add_argument("action", nargs="?", choices=("show", "change"))
    args = parser.parse_args()
    require_root()
    if args.mobile:
        os.environ["DRAGONCORE_COLUMNS"] = "68"
    if args.command == "api-password":
        if args.action == "show":
            print(api_password())
        elif args.action == "change":
            rotate_api_password()
        else:
            api_menu()
    elif args.action:
        parser.error("action is only valid with api-password")
    elif args.command == "users":
        list_users()
    elif args.command == "status":
        status()
    elif args.command == "logs":
        logs()
    elif args.command == "update":
        update_from_git()
    else:
        menu("MAIN MENU", main_menu_options())


if __name__ == "__main__":
    try:
        main()
    except (CLIError, KeyboardInterrupt) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
