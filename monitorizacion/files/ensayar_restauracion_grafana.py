#!/usr/bin/env python3
"""Ensaya extracción OFFLINE de un respaldo V5, solo en VM aislada autorizada.

No importa Docker, no arranca servicios y no toca ninguna ruta de Grafana vivo.
El backup sigue siendo sensible: todos los artefactos restaurados son privados.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from verificar_backup_grafana import VerifyError, verify

GUARD_CONTENT = "GRAFANA_RESTORE_LAB_ONLY_v1"
MIN_RESERVE_BYTES = 512 * 1024 * 1024


class RestoreError(Exception):
    pass


def check_path_no_symlinks(path: Path, name: str, *, require_exists: bool = True) -> Path:
    if not path.is_absolute() or str(path) == '/' or '..' in path.parts or '\n' in str(path):
        raise RestoreError(f"{name}: ruta absoluta segura obligatoria")
    for part in [path, *path.parents]:
        if part.is_symlink():
            raise RestoreError(f"{name}: contiene un enlace simbólico")
    if require_exists and not path.exists():
        raise RestoreError(f"{name}: no existe")
    return path.resolve(strict=require_exists)


def authorize(guard: Path, root: Path, archive: Path) -> None:
    check_path_no_symlinks(guard, "guard")
    check_path_no_symlinks(archive, "archive")
    check_path_no_symlinks(root, "restore-root", require_exists=False)
    if guard.read_text(encoding='utf-8').strip() != GUARD_CONTENT:
        raise RestoreError("La marca de VM aislada no contiene el valor aprobado")
    guard_stat = guard.lstat()
    if not stat.S_ISREG(guard_stat.st_mode) or guard_stat.st_uid != 0 or stat.S_IMODE(guard_stat.st_mode) != 0o600:
        raise RestoreError("La marca de VM debe ser root:root y modo 0600")
    if archive == root or archive in root.parents or root in archive.parents:
        raise RestoreError("Backup y área de restauración deben ser rutas independientes")
    if root.exists():
        root_stat = root.lstat()
        if not root.is_dir() or root_stat.st_uid != 0 or stat.S_IMODE(root_stat.st_mode) != 0o700:
            raise RestoreError("La carpeta del ensayo debe ser root y 0700")
    if os.geteuid() != 0:
        raise RestoreError("El ensayo requiere sudo, nunca usuario sin privilegios")


def bytes_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def read_members_and_manifest(tar: tarfile.TarFile):
    members = tar.getmembers()
    names = [m.name for m in members]
    if len(names) != len(set(names)):
        raise RestoreError("Tar con nombres duplicados")
    for member in members:
        name = member.name.rstrip('/')
        if name.startswith('/') or '..' in PurePosixPath(name).parts:
            raise RestoreError("Ruta no segura dentro del tar")
        if not member.isfile() and not member.isdir():
            raise RestoreError("Tipo de archivo no permitido dentro del tar")
        if member.isdir() and name != 'grafana' and not name.startswith('grafana/'):
            raise RestoreError("Directorio inesperado en tar")
        if member.isfile() and name != 'META/manifest.json' and not name.startswith('grafana/'):
            raise RestoreError("Archivo inesperado en tar")
    entry = tar.getmember('META/manifest.json')
    if not entry.isfile() or entry.size > 10_000_000:
        raise RestoreError("Manifiesto inválido")
    with tar.extractfile(entry) as f:
        manifest = json.load(f)
    if manifest.get('schema') != 1 or not isinstance(manifest.get('files'), list):
        raise RestoreError("Esquema del manifiesto no compatible")
    declared = {r['path']: r for r in manifest['files']}
    if len(declared) != len(manifest['files']):
        raise RestoreError("Archivos duplicados en manifiesto")
    actual = {m.name: m for m in members if m.isfile() and m.name != 'META/manifest.json'}
    if set(declared) != set(actual):
        raise RestoreError("El manifiesto y el tar tienen distinto contenido")
    must = {'grafana/data/grafana.db', 'grafana/docker-compose.yml', 'grafana/secrets/admin_password'}
    if not must.issubset(actual):
        raise RestoreError("Faltan archivos indispensables")
    return members, declared


def sql_inventory(db: Path, expected_dashboards: int | None = None) -> dict:
    # URI read-only; no crea ni migra ninguna base de datos.
    try:
        uri = db.as_uri() + '?mode=ro'
        con = sqlite3.connect(uri, uri=True, timeout=10)
        try:
            result = con.execute('PRAGMA integrity_check').fetchone()
            if not result or result[0] != 'ok':
                raise RestoreError('El SQLite reconstruido no supera integrity_check')
            tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'dashboard' not in tables:
                # A diferencia de las pruebas sintéticas, una copia real de Grafana debe tener tabla dashboard.
                raise RestoreError('No existe la tabla dashboard de Grafana')
            columns = {r[1] for r in con.execute('PRAGMA table_info(dashboard)')}
            filters = []
            if 'is_folder' in columns:
                filters.append('is_folder = 0')
            if 'deleted' in columns:
                filters.append('deleted = 0')
            where = ' WHERE ' + ' AND '.join(filters) if filters else ''
            dashboards = con.execute('SELECT COUNT(*) FROM dashboard' + where).fetchone()[0]
            if expected_dashboards is not None and dashboards != expected_dashboards:
                raise RestoreError('La cantidad de dashboards restaurados no coincide con la prevista')
            datasources = con.execute('SELECT COUNT(*) FROM data_source').fetchone()[0] if 'data_source' in tables else None
            alerts = con.execute('SELECT COUNT(*) FROM alert_rule').fetchone()[0] if 'alert_rule' in tables else None
        finally:
            con.close()
    except sqlite3.Error as e:
        raise RestoreError('El snapshot SQLite restaurado no se puede inspeccionar') from e
    return {'sqlite': 'ok', 'dashboards': dashboards, 'datasources': datasources, 'alert_rules': alerts}


def verify_restored(root: Path, declared: dict, expected_dashboards: int) -> dict:
    for name, meta in declared.items():
        dest = root.joinpath(*PurePosixPath(name).parts)
        if dest.is_symlink() or not dest.is_file():
            raise RestoreError('Falta un archivo reconstruido o tiene tipo inesperado')
        if dest.stat().st_size != meta['size'] or bytes_sha256(dest) != meta['sha256']:
            raise RestoreError('La restauración no coincide con el manifiesto')
    inventory = sql_inventory(root / 'grafana/data/grafana.db', expected_dashboards)
    return {'files': len(declared), **inventory}


def restore(archive: Path, expected_sha256: str, work_root: Path, guard: Path,
            expected_dashboards: int, reserve_bytes: int) -> dict:
    authorize(guard, work_root, archive)
    if not re.fullmatch(r'[0-9a-fA-F]{64}', expected_sha256):
        raise RestoreError('SHA256 esperado inválido')
    expected_sha256 = expected_sha256.lower()
    # El verificador de V5 comprueba todos los SHA256 y el SQLite ANTES de extraer.
    verified = verify(archive, expected_sha256)
    with tarfile.open(archive, 'r:gz') as tar:
        members, declared = read_members_and_manifest(tar)
        destination = work_root / ('ensayo-' + expected_sha256[:16])
        if destination.is_symlink():
            raise RestoreError('El destino anterior es un enlace simbólico')
        if destination.exists():
            details = verify_restored(destination, declared, expected_dashboards)
            return {'status': 'YA_VALIDADO', 'changed': False, 'location': str(destination),
                    'sha256': verified['sha256'], **details}
        estimated = sum(int(v['size']) for v in declared.values())
        # Reserva por descompresión y verificación del sqlite antes de escribir.
        free = shutil.disk_usage(work_root.parent if not work_root.exists() else work_root).free
        if free < estimated + reserve_bytes:
            raise RestoreError('Espacio insuficiente para restauración aislada y reserva')
        work_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(work_root, 0o700)
        if work_root.stat().st_uid != 0:
            raise RestoreError('El destino no es propiedad de root')
        staging = Path(tempfile.mkdtemp(prefix='.restoring-', dir=work_root))
        try:
            os.chmod(staging, 0o700)
            dirs = [m for m in members if m.isdir()]
            for member in sorted(dirs, key=lambda x: len(PurePosixPath(x.name).parts)):
                target = staging.joinpath(*PurePosixPath(member.name).parts)
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
            for name, meta in sorted(declared.items()):
                member = tar.getmember(name)
                target = staging.joinpath(*PurePosixPath(name).parts)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                h = hashlib.sha256()
                nbytes = 0
                with tar.extractfile(member) as source, target.open('xb') as dest:
                    for chunk in iter(lambda: source.read(1024 * 1024), b''):
                        dest.write(chunk)
                        h.update(chunk)
                        nbytes += len(chunk)
                if nbytes != meta['size'] or h.hexdigest() != meta['sha256']:
                    raise RestoreError('Diferencia al escribir archivo restaurado')
                os.chmod(target, int(meta['mode'], 8))
                os.chown(target, int(meta['uid']), int(meta['gid']))
            for member in sorted(dirs, key=lambda x: len(PurePosixPath(x.name).parts), reverse=True):
                d = staging.joinpath(*PurePosixPath(member.name).parts)
                os.chown(d, member.uid, member.gid)
                os.chmod(d, member.mode & 0o777)
            info = verify_restored(staging, declared, expected_dashboards)
            # Nunca se sobrescribe un ensayo previo. Destino sin ruta de instalación activa.
            staging.rename(destination)
            return {'status': 'RESTAURADO_OFFLINE', 'changed': True, 'location': str(destination),
                    'sha256': verified['sha256'], **info}
        finally:
            if staging.exists():
                shutil.rmtree(staging)


def main(argv=None):
    p = argparse.ArgumentParser(description='Restauración offline exclusivamente en una VM aislada')
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--sha256', required=True)
    p.add_argument('--work-root', type=Path, required=True)
    p.add_argument('--guard', type=Path, required=True)
    p.add_argument('--expect-dashboards', type=int, default=15)
    p.add_argument('--reserve-bytes', type=int, default=MIN_RESERVE_BYTES)
    a = p.parse_args(argv)
    try:
        if a.expect_dashboards < 0 or a.reserve_bytes < MIN_RESERVE_BYTES:
            raise RestoreError('Cantidad esperada o reserva de espacio no válidas')
        result = restore(a.archive, a.sha256, a.work_root, a.guard, a.expect_dashboards, a.reserve_bytes)
    except (RestoreError, VerifyError, OSError, ValueError, KeyError, tarfile.TarError, json.JSONDecodeError) as e:
        print(f'ERROR ENSAYO: {e}', file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
