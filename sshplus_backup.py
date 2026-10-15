#!/usr/bin/env python3
"""Safe SSHPlus .vps importer for ConectaSSH-PRO.

Never extracts archive members to disk and never writes /etc/passwd, /etc/shadow,
groups, root credentials, or Linux accounts. Only imports validated non-root
users through the panel API.
"""
import datetime as dt
import json
import os
import re
import secrets
import subprocess
import tarfile
from pathlib import Path
import urllib.request

BASE = Path('/opt/sshpanel')
ROOT = Path('/root')
VALID_USER = re.compile(r'^[A-Za-z0-9._-]{1,32}$')
# Limits protect against malformed/decompression-bomb archives, not user counts.
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 250000
MAX_MEMBER_BYTES = 32 * 1024 * 1024
RESTORE_BATCH_SIZE = 1000


def req(method, path, data=None, timeout=120):
    env = {}
    env_path = BASE / '.env'
    for line in env_path.read_text().splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            env[k.strip()] = v.strip().strip('"')
    addr = env.get('ADMIN_HTTP_ADDR', '127.0.0.1:9090').rsplit(':', 1)[-1]
    url = 'http://127.0.0.1:' + addr + path
    body = None
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer ' + env.get('ADMIN_TOKEN', '')}
    if data is not None:
        body = json.dumps(data).encode()
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def _archive_data(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError('El backup no es un archivo regular.')
    if path.stat().st_size <= 0 or path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError('Tamaño del backup fuera del rango permitido.')
    with tarfile.open(path, 'r:*') as archive:
        members = archive.getmembers()
        if len(members) > MAX_ARCHIVE_ENTRIES:
            raise ValueError('El backup supera el límite de seguridad de elementos del archivo.')
        files = {}
        for member in members:
            name = member.name.lstrip('./')
            parts = Path(name).parts
            if not name or name.startswith('/') or '..' in parts:
                raise ValueError('El backup contiene una ruta insegura.')
            if not (member.isfile() or member.isdir()):
                raise ValueError('El backup contiene enlaces u objetos especiales; se rechaza por seguridad.')
            if member.size > MAX_MEMBER_BYTES:
                raise ValueError('Un elemento del backup excede el tamaño permitido.')
            if member.isfile():
                if name in files:
                    raise ValueError('El backup contiene rutas duplicadas.')
                handle = archive.extractfile(member)
                if handle is None:
                    raise ValueError('No se pudo leer un elemento del backup.')
                files[name] = handle.read(MAX_MEMBER_BYTES + 1)
                if len(files[name]) > MAX_MEMBER_BYTES:
                    raise ValueError('Un elemento excede el tamaño permitido.')
    def text(name, required=False):
        value = files.get(name)
        if value is None:
            if required:
                raise ValueError('Falta el archivo requerido: ' + name)
            return ''
        return value.decode('utf-8', errors='replace')
    db = text('root/usuarios.db', required=True)
    passwd = text('etc/passwd', required=True)
    shadow = text('etc/shadow', required=True)
    pass_users = {line.split(':', 1)[0] for line in passwd.splitlines() if ':' in line}
    shadow_expiry = {}
    for line in shadow.splitlines():
        fields = line.split(':')
        if len(fields) >= 8 and fields[0] and fields[7].isdigit():
            try:
                day = int(fields[7])
                shadow_expiry[fields[0]] = (
                    dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
                    + dt.timedelta(days=day)).isoformat().replace('+00:00', 'Z')
            except (OverflowError, ValueError):
                pass
    rows, skipped = [], []
    seen = set()
    for line in db.splitlines():
        fields = line.split()
        if not fields:
            continue
        username = fields[0]
        if username.lower() == 'root':
            skipped.append('root')
            continue
        if not VALID_USER.fullmatch(username):
            skipped.append('invalid_username')
            continue
        if username in seen:
            raise ValueError('El backup repite el usuario ' + username)
        seen.add(username)
        if username not in pass_users:
            skipped.append('no_system_account')
            continue
        cred_path = 'etc/SSHPlus/senha/' + username
        raw_password = files.get(cred_path)
        if not raw_password:
            skipped.append('missing_password')
            continue
        password = raw_password.decode('utf-8', errors='replace').splitlines()
        if not password or not password[0]:
            skipped.append('empty_password')
            continue
        try:
            limit = int(fields[1]) if len(fields) > 1 else 1
        except ValueError:
            raise ValueError('Límite inválido para el usuario ' + username)
        if not 1 <= limit <= 100000:
            raise ValueError('Límite fuera de rango para el usuario ' + username)
        rows.append({
            'username': username,
            'password': password[0],
            'max_connections': limit,
            'expires_at': shadow_expiry.get(username, ''),
            'use_pam': False,
        })
    if not rows:
        raise ValueError('No se encontraron usuarios importables.')
    return rows, len(members), skipped


def inspect(path):
    users, entries, skipped = _archive_data(path)
    # Report only counts and usernames; never print passwords or password hashes.
    print(json.dumps({
        'ok': True, 'file': Path(path).name, 'archive_entries': entries,
        'users_found': len(users),
        'root_excluded': True, 'skipped_entries': len(skipped),
        'users': [{'username': u['username'], 'max_connections': u['max_connections'],
                   'expires_at': u['expires_at']} for u in users],
        'ready': len(users) > 0 and all(u['username'].lower() != 'root' for u in users),
    }, ensure_ascii=False))


def restore(path):
    users, entries, skipped = _archive_data(path)
    if not users:
        raise ValueError('No se encontraron usuarios válidos para restaurar.')
    if any(u['username'].lower() == 'root' for u in users):
        raise ValueError('Protección root: se canceló la restauración.')

    # Import in small idempotent batches so large backups do not create one huge
    # HTTP request. Upsert means a retry after an interruption is safe.
    restored_total = 0
    total_users = len(users)
    for offset in range(0, total_users, RESTORE_BATCH_SIZE):
        batch = users[offset:offset + RESTORE_BATCH_SIZE]
        result = req('POST', '/api/users/restore', {
            'version': 1,
            'created_at': dt.datetime.now(dt.timezone.utc).isoformat(),
            'users': batch,
            'defer_reload': offset + len(batch) < total_users,
        }, timeout=180)
        restored = int(result.get('restored', 0))
        total = int(result.get('total', -1))
        if restored != len(batch) or total != len(batch):
            raise RuntimeError(
                f'Respuesta API inesperada en lote {offset // RESTORE_BATCH_SIZE + 1}: '
                f'restored={restored}, total={total}, esperado={len(batch)}. '
                f'Progreso confirmado: {restored_total}/{total_users}. '
                'Podés volver a ejecutar la restauración; las cuentas se actualizan por nombre.'
            )
        restored_total += restored
        print(f'PROGRESO {restored_total}/{total_users}', flush=True)

    print('RESTORE_OK')
    print('USUARIOS_RESTAURADOS', restored_total)
    print('ELEMENTOS_BACKUP', entries)
    print('USUARIOS_OMITIDOS', len(skipped))
    print('ROOT_MODIFICADO', 'NO')
    print('ARCHIVOS_DE_CUENTAS_DEL_SISTEMA_MODIFICADOS', 'NO')
    print('BACKUP_ORIGEN', Path(path).name)

if __name__ == '__main__':
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == 'inspect':
        try:
            inspect(sys.argv[2])
        except Exception as exc:
            print(json.dumps({'ok': False, 'error': str(exc)}, ensure_ascii=False))
            raise SystemExit(2)
    elif len(sys.argv) == 3 and sys.argv[1] == 'restore':
        try:
            restore(sys.argv[2])
        except Exception as exc:
            print('ERROR:', str(exc), file=__import__('sys').stderr)
            raise SystemExit(2)
    else:
        raise SystemExit('Uso: sshplus_backup.py inspect|restore ARCHIVO.vps')
