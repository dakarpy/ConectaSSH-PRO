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
        "cores": os.cpu_count() or 1, "cpu": (stats or {}).get("cpu_percent"),
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
    password = secrets.token_urlsafe(18)
    expires_at = ((dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=test_hours)).isoformat(timespec="seconds")
                  if test_hours else expiry(str(default_days)))
    use_pam = ask("¿Usar autenticación PAM para este usuario? (sí/no)", "no").lower() in ("sí", "si", "s", "yes", "y")
    p = {"username": name, "password": password, "max_connections": number("Máximo de conexiones", 1, 0, 10000),
         "expires_at": expires_at, "limit_mbps_up": 0, "limit_mbps_down": 0,
         "data_quota_bytes": 0, "quota_action": "throttle", "quota_throttle_mbps": 10,
         "use_pam": use_pam}
    if use_pam:
        print("Aviso: el usuario PAM debe existir como cuenta Linux válida en /etc/passwd y /etc/shadow.")
    request("POST", "/api/users/create", p)
    print(f"Usuario SSH: {name}\nContraseña SSH generada: {password}")


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
        p["password"] = secrets.token_urlsafe(18)
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
    if value == current:
        print("No changes.")
        return
    parent[key] = value
    save_settings(path, document)


def field_menu(title, path, fields, parent_keys=()):
    menu(title, {str(index): (label, lambda f=field: edit_field(path, f, parent_keys))
                 for index, field in enumerate(fields, 1) for label in (field[1],)})


SSH_FIELDS = (
    ("listen", "Escucha SSH/HTTP principal", "text"),
    ("extra_listen", "Escuchas públicas adicionales", "list"),
    ("local_ssh_listen", "Escucha SSH local", "text"),
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
    "dnstt": ("DNSTT", {"domain": "", "udp_listen": "0.0.0.0:5300"}, (
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
    "bhttp": ("BHTTP", {"listen": ["0.0.0.0:8880"], "shared_ports": False}, (
        ("listen", "Escuchas TCP", "list"), ("shared_ports", "Compartir puertos SSH/TLS", "bool"),
        ("session_timeout", "Tiempo de espera de sesión", "text"), ("max_v2_lanes", "Máximo de canales V2", "int"),
        ("max_sessions", "Máximo de sesiones", "int"), ("max_connections", "Máximo de conexiones", "int"),
        ("disable_console_log", "Silenciar registros de consola", "bool"), ("log_connections", "Registrar conexiones", "bool"),
        ("auto_restart_interval", "Intervalo de reinicio", "text"), ("auto_restart_grace", "Tiempo de gracia del reinicio", "text"),
    )),
    "btun": ("BTUN", {"tcp_listen": "0.0.0.0:7300", "udp_listen": "", "manage_routing": True}, (
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
    "hcr": ("HCR", {"listen": ["0.0.0.0:8181"], "shared_ports": False}, (
        ("listen", "Escuchas TCP", "list"), ("shared_ports", "Compartir puertos SSH/TLS", "bool"),
        ("max_connections", "Máximo de conexiones", "int"), ("max_sessions", "Máximo de sesiones", "int"),
        ("max_source_sessions", "Máximo de sesiones por IP", "int"),
        ("download_poll_timeout", "Tiempo de espera de sondeo de descarga", "text"),
        ("max_download_frame", "Máximo de bytes por trama", "int"),
        ("idle_session_timeout", "Tiempo de espera de sesión inactiva", "text"),
        ("disable_console_log", "Silenciar registros de consola", "bool"), ("log_connections", "Registrar conexiones", "bool"),
        ("auto_restart_interval", "Intervalo de reinicio", "text"), ("auto_restart_grace", "Tiempo de gracia del reinicio", "text"),
    )),
    "udpgw": ("UDPGW", {"listen": "0.0.0.0:7400"}, (
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
    if value == old:
        print("No changes.")
        return
    current[key] = value
    if block == "xray" and key == "mode":
        current["native"] = value == "native"
    save_settings("/api/server/config", document)


def block_menu(block):
    title, _, fields = BLOCKS[block]
    options = {"1": ("Activar / desactivar", lambda: toggle_block(block))}
    options.update({str(index): (label, lambda f=field: block_field(block, f))
                    for index, field in enumerate(fields, 2) for label in (field[1],)})
    if block == "xray":
        options[str(len(fields) + 2)] = ("Ajustes del emulador nativo", xray_tuning_menu)
    menu(title + " SETTINGS", options)


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
                         for i, field in enumerate(fields, 1)})


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
    listen = ask("TLS listener (IP:port)", "0.0.0.0:443")
    cert, key = select_certificate()
    cfg.setdefault("tls_forwarders", []).append({"listen": listen, "cert_file": cert, "key_file": key})
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
    menu("ESCUCHA TLS", options)


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
        listeners[index]["listen"] = ask("TLS listener (IP:port)", listeners[index]["listen"])
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
    menu("ESCUCHAS TLS", options)


def server_settings_menu():
    menu("CONFIGURACIÓN DEL SERVIDOR", {
        "1": ("SSH y escuchas públicas", lambda: field_menu("CONFIGURACIÓN SSH", "/api/server/config", SSH_FIELDS)),
        "2": ("Escuchas TLS", tls_listener_menu),
        "3": ("DNSTT", lambda: block_menu("dnstt")),
        "4": ("BHTTP", lambda: block_menu("bhttp")),
        "5": ("BTUN", lambda: block_menu("btun")),
        "6": ("HCR", lambda: block_menu("hcr")),
        "7": ("UDPGW", lambda: block_menu("udpgw")),
        "8": ("Servicio Xray", lambda: block_menu("xray")),
    })


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
    menu("XRAY " + (str(trail[-1]).upper() if trail else "FIELDS"), options)


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
    })


def xray_inbound_settings_menu():
    def options():
        inbounds = (request("GET", "/api/xray/config") or {}).get("inbounds") or []
        result = {"1": ("Crear entrada independiente", xray_inbound_add),
                  "2": ("Compartir puertos SSH/TLS (WS/XHTTP)", xray_shared_port)}
        result.update({str(index + 3): (f"{item.get('tag')} ({item.get('protocol')})",
                                         lambda tag=item.get("tag"): xray_inbound_settings(tag))
                       for index, item in enumerate(inbounds)})
        return result
    menu("ENTRADAS XRAY", options)


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
                      for i, (key, label) in enumerate(fields, 1)})


def bot_settings_menu():
    menu("BOT DE TELEGRAM", {
        "1": ("Configuración del bot y pagos", lambda: field_menu("CONFIGURACIÓN DEL BOT", "/api/bot/config", BOT_FIELDS)),
        "2": ("Mensajes y enlace de la aplicación", bot_text_menu),
    })


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
                            for i, (field, label) in enumerate(fields, 1)})


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
    cfg["listen"] = ask("Dirección SSH principal (IP:puerto)", cfg.get("listen") or "0.0.0.0:80")
    current = ", ".join(cfg.get("extra_listen") or [])
    extras = input(f"Direcciones adicionales, separadas por coma [{current}] (ingresá - para borrar): ").strip()
    extras = "" if extras == "-" else (extras or current)
    cfg["extra_listen"] = [part.strip() for part in extras.split(",") if part.strip()]
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


def connection_menu():
    menu("MODOS DE CONEXIÓN", {
        "1": ("Puertos y transportes", connection_status),
        "2": ("Estadísticas DNSTT / BHTTP / HCR / BTUN", protocol_stats),
        "3": ("Escuchas y configuración de protocolos", server_settings_menu),
        "4": ("Certificados TLS", certificate_list),
        "5": ("Clave pública DNSTT", lambda: print(json.dumps(request("GET", "/api/dnstt/pubkey"), indent=2))),
        "6": ("Registros de protocolos", protocol_logs),
        "7": ("Generar certificado TLS autofirmado", generate_tls_certificate),
        "8": ("Solicitar certificado Let's Encrypt", lambda: generate_tls_certificate(True)),
        "9": ("Regenerar clave DNSTT", regenerate_dnstt_key),
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


def render_menu(title, options, vps_status=None, columns=None):
    """Render a boxed SSHorizon-style terminal menu with two columns."""
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
        ram = (f"{size(vps_status['mem_used'])} / {size(vps_status['mem_total'])}"
               if vps_status.get("mem_total") else "--")
        online = vps_status.get("ssh_online")
        expired = vps_status.get("ssh_expired")
        total = vps_status.get("ssh_total")
        service_label = {"active": "activo", "inactive": "inactivo", "failed": "fallido",
                         "activating": "activando", "deactivating": "desactivando"}.get(
                             vps_status.get("service"), vps_status.get("service", "--"))
        lines.extend([
            row(f"• Host: {vps_status.get('host', '--')}",
                f"• SO: {vps_status.get('os', '--')}"),
            row(f"• Uptime: {vps_status.get('uptime', '--')}",
                f"• Hora: {vps_status.get('time', '--')}"),
            row(f"• CPU: {cpu} ({vps_status.get('cores', '--')} cores)",
                f"• Memoria: {ram}"),
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
            single("MENU"),
        ])

    # Una sola columna evita que las opciones largas se corten en terminales SSH,
    # especialmente en celulares. El ancho se adapta al terminal y cada opción ocupa
    # una línea completa del cuadro.
    for key, (label, _) in options.items():
        lines.append(single(f"[{str(key).zfill(2)}] • {label}"))

    # Todos los menús y submenús tienen una salida uniforme en [00].
    lines.append(single("[00] • SALIR"))

    lines.extend([
        separator,
        single("Elegí una opción y presioná Enter: _"),
        bottom,
    ])
    return "\n".join(lines)


def clear_screen():
    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


_menu_calls = 0


def menu(title, options):
    global _menu_calls
    _menu_calls += 1
    page = 0
    while True:
        clear_screen()
        vps = collect_vps_status() if title == "MAIN MENU" else None
        current_options = options() if callable(options) else options
        # Menú de una sola columna: menos ancho y más legible en móvil.
        page_size = 8 if terminal_columns() <= 48 else 12
        entries = list(current_options.items())
        pages = max(1, (len(entries) + page_size - 1) // page_size)
        page = min(page, pages - 1)
        visible = dict(entries[page * page_size:(page + 1) * page_size])
        heading = title + (f" ({page + 1}/{pages})" if pages > 1 else "")
        print(render_menu(heading, visible, vps))
        if pages > 1:
            print(" n  Página siguiente   p  Página anterior")
        choice = input("Elegí una opción: ").strip().lstrip("0") or "0"
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


def ssh_menu():
    menu("CUENTAS SSH", {"1": ("Listar / conexiones / consumo", list_users),
                          "2": ("Crear (contraseña generada)", create_user),
                          "3": ("Crear prueba (24 horas)", lambda: create_user(test_hours=24)),
                          "4": ("Editar / renovar / cambiar contraseña", edit_user),
                          "5": ("Informe detallado de cuenta", user_report),
                          "6": ("Restablecer tráfico", reset_traffic),
                          "7": ("Eliminar usuarios vencidos", delete_expired_users),
                          "8": ("Eliminar un usuario", delete_user)})


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
                  "13": ("Compartir puertos SSH/TLS (WS/XHTTP)", xray_shared_port)})


def config_menu():
    menu("CONFIGURACIÓN", {"1": ("Configurar banner SSH", set_banner),
                           "2": ("Cambiar puertos de escucha SSH", set_ssh_ports),
                           "3": ("Ancho de banda / límites de conexiones", set_ssh_limits),
                           "4": ("Todas las opciones del servidor y protocolos", server_settings_menu),
                           "5": ("Configuración de Xray", xray_settings_menu),
                           "6": ("Configuración del bot de Telegram", bot_settings_menu),
                           "7": ("Servidores administrados", managed_servers_menu)})


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
        "3": ("MODOS DE CONEXIÓN", connection_menu),
        "4": ("VPS Y TRÁFICO", observability_menu),
        "5": ("CONFIGURACIÓN", config_menu),
        "6": ("CONTRASEÑA DE API", api_menu),
        "7": ("REGISTROS RECIENTES", logs),
        "8": ("REINICIAR SERVICIO", lambda: service_action("restart")),
        "9": ("ACTUALIZAR DESDE GIT", lambda: update_from_git() if confirm("¿Actualizar desde Git ahora?") else None),
        "10": ("CHECKUSER DUAL", checkuser_dual_menu),
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
