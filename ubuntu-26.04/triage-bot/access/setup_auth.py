#!/usr/bin/env python3
"""Prepare an independent dashboard user, without displaying or saving plaintext password."""
import getpass
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent
AUTH = ROOT / 'auth.json'
UNIT = ROOT / 'triage-bridge.service'


def main():
    if not (PROJECT / '.env').exists():
        raise SystemExit('ERROR: install under ~/instalacion/security-triage-bot/access')
    if AUTH.exists():
        raise SystemExit('ERROR: auth.json already exists. Not overwriting credentials.')
    username = 'triage_admin'
    password = getpass.getpass('Contraseña NUEVA del panel (mínimo 12 caracteres): ')
    repeat = getpass.getpass('Repite la contraseña: ')
    if len(password) < 12 or password != repeat or ':' in username:
        raise SystemExit('ERROR: contraseñas distintas o menos de 12 caracteres.')
    rounds = 350000
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, rounds)
    data = {'username': username, 'salt': salt.hex(), 'rounds': rounds, 'digest': digest.hex()}
    fd = os.open(AUTH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f)
    os.chmod(AUTH, 0o600)
    user = getpass.getuser()
    content = f'''[Unit]
Description=Security Triage read-only dashboard bridge (lab)
After=network-online.target k3s.service docker.service
Wants=network-online.target

[Service]
Type=simple
User={user}
Group={user}
WorkingDirectory={PROJECT}
ExecStart=/usr/bin/python3 {ROOT / 'bridge.py'}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectControlGroups=true
PrivateTmp=true
PrivateDevices=true
RestrictAddressFamilies=AF_INET AF_UNIX
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
'''
    UNIT.write_text(content, encoding='utf-8')
    print('Cuenta del dashboard:', username)
    print('Credenciales generadas localmente; contraseña no mostrada ni guardada en claro.')
    print('Unidad systemd generada:', UNIT)


if __name__ == '__main__':
    main()
