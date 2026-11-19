#!/usr/bin/env python3
import argparse
import os
import re
import stat
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

PROFILE = {
    'sca': {'enabled': 'yes', 'interval': '12h'},
    'vulnerability-detection': {'enabled': 'yes'},
    'syscheck': {'disabled': 'no', 'frequency': '43200'},
}


def apply_profile(original):
    try:
        base = re.sub(r'<\?xml[^>]*\?>', '', original)
        source_root = ET.fromstring('<root>' + base + '</root>')
        if not source_root.findall('ossec_config'):
            raise ValueError('No existe ossec_config')
        for section in PROFILE:
            found = source_root.findall('.//' + section)
            if len(found) > 1:
                raise ValueError('Secciones duplicadas: ' + section)
            if found and not re.search(r'<'+re.escape(section)+r'\s*>', original):
                raise ValueError('Sección autocerrada no compatible: ' + section)
    except ET.ParseError as exc:
        raise ValueError('XML original inválido: ' + str(exc)) from exc
    text = original
    for section, settings in PROFILE.items():
        pattern = re.compile(r'<'+re.escape(section)+r'\s*>(.*?)</'+re.escape(section)+r'\s*>', re.S)
        matches = list(pattern.finditer(text))
        if len(matches) > 1:
            raise ValueError('Secciones duplicadas: ' + section)
        if not matches:
            closing = re.search(r'</ossec_config\s*>', text)
            if not closing:
                raise ValueError('No existe cierre ossec_config')
            block = '\n  <'+section+'>\n' + ''.join(
                '    <'+key+'>'+value+'</'+key+'>\n' for key,value in settings.items()
            ) + '  </'+section+'>\n'
            text = text[:closing.start()] + block + text[closing.start():]
            continue
        match = matches[0]
        body = match.group(1)
        for key, value in settings.items():
            child = re.compile(r'(<'+re.escape(key)+r'\s*>)([^<]*)(</'+re.escape(key)+r'\s*>)', re.S)
            if len(child.findall(body)) > 1:
                raise ValueError('Campo duplicado: ' + section + '/' + key)
            if child.search(body):
                body = child.sub(lambda m: m.group(1) + value + m.group(3), body, count=1)
            else:
                body = body.rstrip() + '\n    <'+key+'>'+value+'</'+key+'>\n  '
        text = text[:match.start(1)] + body + text[match.end(1):]
    try:
        document = re.sub(r'<\?xml[^>]*\?>', '', text)
        root = ET.fromstring('<root>' + document + '</root>')
        if not root.findall('ossec_config'):
            raise ValueError('No existe ossec_config')
    except ET.ParseError as exc:
        raise ValueError('XML del manager inválido: ' + str(exc)) from exc
    return text


def main():
    cli = argparse.ArgumentParser()
    choice = cli.add_mutually_exclusive_group(required=True)
    choice.add_argument('--check', action='store_true')
    choice.add_argument('--apply', action='store_true')
    cli.add_argument('path')
    args = cli.parse_args()
    path = Path(args.path)
    if path.is_symlink() or not path.is_file():
        cli.error('Se requiere un archivo regular, no un enlace')
    original = path.read_text(encoding='utf-8')
    updated = apply_profile(original)
    if original == updated:
        print('OK: perfil Wazuh original SCA/FIM/vulnerabilidades')
        return
    if args.check:
        cli.exit(1, 'DRIFT: SCA/FIM/vulnerabilidades no coinciden con el origen\n')
    current_stat = path.stat()
    backup = path.with_name(path.name + '.pre-manager-profile')
    if not backup.exists():
        fd, name = tempfile.mkstemp(prefix='.wazuh-profile-backup-', dir=path.parent)
        try:
            if hasattr(os, 'fchmod'):
                os.fchmod(fd, 0o600)
            else:
                os.chmod(name, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as fp:
                fp.write(original)
            os.replace(name, backup)
        finally:
            if os.path.exists(name):
                os.unlink(name)
    fd, name = tempfile.mkstemp(prefix='.wazuh-profile-', dir=path.parent)
    try:
        if hasattr(os, 'fchmod'):
            os.fchmod(fd, stat.S_IMODE(current_stat.st_mode))
        else:
            os.chmod(name, stat.S_IMODE(current_stat.st_mode))
        if os.name == 'posix':
            os.fchown(fd, current_stat.st_uid, current_stat.st_gid)
        with os.fdopen(fd, 'w', encoding='utf-8') as fp:
            fp.write(updated)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    print('CHANGED: SCA/FIM/vulnerabilidades del manager original')


if __name__ == '__main__':
    main()
