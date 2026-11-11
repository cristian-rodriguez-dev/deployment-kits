#!/usr/bin/env python3
"""Copia de seguridad segura de Grafana SQLite en Docker (solo escribe en backup-dir).

Se ejecuta en el host de Grafana, con privilegios de AWX. No modifica el contenedor.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SKIP_SQLITE_FILES = {"grafana.db", "grafana.db-wal", "grafana.db-shm", "grafana.db-journal"}
EXPECTED_MOUNTS = {
    "/var/lib/grafana": "data",
    "/etc/grafana/provisioning": "provisioning",
    "/run/secrets/grafana_admin_password": "secrets/admin_password",
}


class BackupError(Exception):
    pass


def safe_directory(path: Path, name: str) -> Path:
    if not path.is_absolute() or str(path) == "/" or ".." in path.parts or "\n" in str(path):
        raise BackupError(f"{name}: ruta absoluta segura obligatoria")
    if path.is_symlink():
        raise BackupError(f"{name}: no se permiten enlaces simbólicos")
    return path.resolve()


def validate_paths(install_dir: Path, backup_dir: Path) -> None:
    if not install_dir.is_dir():
        raise BackupError("El directorio de instalación no existe")
    if install_dir == backup_dir:
        raise BackupError("El directorio de backup no puede coincidir con la instalación")
    for protected in ("data", "provisioning", "secrets"):
        p = install_dir / protected
        if backup_dir == p or p in backup_dir.parents:
            raise BackupError(f"La ruta de backup no puede estar dentro de {protected}/")
        if backup_dir in p.parents:
            raise BackupError(f"La ruta de backup no puede ser ancestro de {protected}/")
    # Evitar un directorio de respaldo anidado en otro árbol copiado accidentalmente.
    if backup_dir == install_dir / "docker-compose.yml":
        raise BackupError("Ruta de backup inválida")
    # Prohibir enlaces simbólicos en los componentes existentes de la ruta.
    for candidate in (install_dir, backup_dir):
        p = candidate
        while p != p.parent:
            if p.is_symlink():
                raise BackupError("La ruta contiene un enlace simbólico")
            p = p.parent


def require_regular_file(p: Path) -> os.stat_result:
    if p.is_symlink():
        raise BackupError(f"Enlace simbólico rechazado: {p.name}")
    s = p.lstat()
    if not stat.S_ISREG(s.st_mode):
        raise BackupError(f"Archivo no regular rechazado: {p.name}")
    return s


def verify_layout(install_dir: Path) -> None:
    for rel in ("data", "provisioning", "secrets"):
        p = install_dir / rel
        if p.is_symlink() or not p.is_dir():
            raise BackupError(f"Directorio obligatorio ausente o inseguro: {rel}")
    for rel in ("docker-compose.yml", "secrets/admin_password", "data/grafana.db"):
        p = install_dir / rel
        if not p.is_file():
            raise BackupError(f"Archivo obligatorio ausente: {rel}")
        require_regular_file(p)


def inspect_running_container(install_dir: Path, project_name: str) -> str:
    compose = install_dir / "docker-compose.yml"
    try:
        ps = subprocess.run(
            ["docker", "compose", "-p", project_name, "-f", str(compose), "ps", "-q", "grafana"],
            capture_output=True, text=True, check=True, timeout=30,
        )
        ids = [s.strip() for s in ps.stdout.splitlines() if s.strip()]
        if len(ids) != 1:
            raise BackupError("Grafana no tiene exactamente un contenedor activo en el proyecto esperado")
        out = subprocess.run(
            ["docker", "inspect", ids[0]], capture_output=True, text=True, check=True, timeout=30,
        )
        details = json.loads(out.stdout)
        if len(details) != 1 or not details[0].get("State", {}).get("Running"):
            raise BackupError("El contenedor de Grafana no está en ejecución")
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as ex:
        raise BackupError("No se pudo inspeccionar Docker Compose y los montajes de Grafana") from ex
    mounts = details[0].get("Mounts", [])
    found = {m.get("Destination"): m for m in mounts}
    for dest, relative in EXPECTED_MOUNTS.items():
        m = found.get(dest)
        expected = str(install_dir / relative)
        if not m or m.get("Type") != "bind" or os.path.realpath(m.get("Source", "")) != expected:
            raise BackupError(f"El montaje {dest} no corresponde a {relative}; no se hará un backup incompleto")
    extras = set(found) - set(EXPECTED_MOUNTS)
    if extras:
        raise BackupError("Existen montajes adicionales en Grafana no cubiertos: " + ", ".join(sorted(extras)))
    return str(details[0].get("Config", {}).get("Image", "no-disponible"))


def online_sqlite_backup(source: Path, target: Path) -> None:
    try:
        with sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=30) as src:
            with sqlite3.connect(target, timeout=30) as dst:
                src.backup(dst, pages=128, sleep=0.1)
                status = dst.execute("PRAGMA quick_check").fetchone()
                if not status or status[0] != "ok":
                    raise BackupError("La copia SQLite no supera PRAGMA quick_check")
        os.chmod(target, 0o600)
    except sqlite3.Error as ex:
        raise BackupError("No se pudo obtener una copia consistente de SQLite") from ex


def paths_to_archive(install_dir: Path, sqlite_snapshot: Path):
    """Obtiene entradas ordenadas, incluyendo directorios vacíos, sin seguir symlinks."""
    for rel in ("data", "provisioning", "secrets"):
        root = install_dir / rel
        for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            if current_path.is_symlink():
                raise BackupError(f"Enlace simbólico rechazado en {rel}/")
            for dirname in dirs:
                if (current_path / dirname).is_symlink():
                    raise BackupError(f"Enlace simbólico en directorio: {dirname}")
            rel_path = current_path.relative_to(install_dir).as_posix()
            yield ("grafana/" + rel_path, current_path, "dir")
            for filename in sorted(files):
                p = current_path / filename
                child_rel = p.relative_to(install_dir)
                if child_rel.parent.as_posix() == "data" and filename in SKIP_SQLITE_FILES:
                    continue
                require_regular_file(p)
                yield ("grafana/" + child_rel.as_posix(), p, "file")
            dirs.sort()
    yield ("grafana/data/grafana.db", sqlite_snapshot, "sqlite")
    for rel in ("docker-compose.yml", ".awx-initialized"):
        p = install_dir / rel
        if p.exists() or p.is_symlink():
            require_regular_file(p)
            yield ("grafana/" + rel, p, "file")


class HashingReader:
    def __init__(self, fileobj):
        self.fileobj = fileobj
        self.hash = hashlib.sha256()
        self.total = 0

    def read(self, n=-1):
        data = self.fileobj.read(n)
        self.hash.update(data)
        self.total += len(data)
        return data


def make_archive(archive_temp: Path, install_dir: Path, sqlite_snapshot: Path,
                 *, image_name: str, created_utc: str) -> dict:
    files_meta = []
    seen = set()
    with tarfile.open(archive_temp, mode="w:gz", format=tarfile.PAX_FORMAT, compresslevel=6) as archive:
        for name, source, kind in paths_to_archive(install_dir, sqlite_snapshot):
            if name in seen:
                raise BackupError(f"Nombre duplicado en archivo: {name}")
            seen.add(name)
            original = install_dir / "data/grafana.db" if kind == "sqlite" else source
            original_stat = original.lstat()
            if kind == "dir":
                if not stat.S_ISDIR(original_stat.st_mode):
                    raise BackupError("El directorio cambió durante el backup")
                info = tarfile.TarInfo(name + "/")
                info.type = tarfile.DIRTYPE
                info.mode = stat.S_IMODE(original_stat.st_mode)
                info.uid, info.gid = original_stat.st_uid, original_stat.st_gid
                info.mtime = int(original_stat.st_mtime)
                archive.addfile(info)
                continue
            source_stat = require_regular_file(source)
            info = tarfile.TarInfo(name)
            info.size = source_stat.st_size
            info.mode = stat.S_IMODE(original_stat.st_mode)
            info.uid, info.gid = original_stat.st_uid, original_stat.st_gid
            info.mtime = int(original_stat.st_mtime)
            with source.open("rb") as fp:
                reader = HashingReader(fp)
                archive.addfile(info, reader)
            after = source.lstat()
            if reader.total != info.size or after.st_size != source_stat.st_size or after.st_mtime_ns != source_stat.st_mtime_ns:
                raise BackupError("Un archivo cambió mientras se copiaba; se descarta el backup")
            files_meta.append({"path": name, "size": reader.total, "sha256": reader.hash.hexdigest(),
                               "mode": f"{info.mode:04o}", "uid": info.uid, "gid": info.gid})
        manifest = {
            "schema": 1,
            "created_utc": created_utc,
            "backup_type": "Grafana Docker Compose SQLite online backup (no downtime)",
            "image": image_name,
            "scope": ["grafana/data", "grafana/provisioning", "grafana/secrets", "grafana/docker-compose.yml", "grafana/.awx-initialized (si existe)"],
            "database_method": "sqlite3.Connection.backup",
            "files": sorted(files_meta, key=lambda x: x["path"]),
        }
        manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        from io import BytesIO
        info = tarfile.TarInfo("META/manifest.json")
        info.mode = 0o600
        info.size = len(manifest_bytes)
        archive.addfile(info, BytesIO(manifest_bytes))
    return {"file_count": len(files_meta), "bytes_uncompressed": sum(f["size"] for f in files_meta)}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(install_dir: Path, backup_dir: Path, project_name: str, reserve_bytes: int) -> dict:
    safe_directory(install_dir, "install-dir")
    safe_directory(backup_dir, "backup-dir")
    validate_paths(install_dir, backup_dir)
    verify_layout(install_dir)
    image_name = inspect_running_container(install_dir, project_name)
    backup_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(backup_dir, 0o700)
    if os.stat(backup_dir).st_uid != 0 or stat.S_IMODE(os.stat(backup_dir).st_mode) != 0o700:
        raise BackupError("Directorio de backups no privado o no propiedad de root")
    # Reserva conservadora; abortar antes de escribir en almacenamiento bajo de espacio.
    estimated_bytes = sum(p.stat().st_size for _, p, kind in paths_to_archive(install_dir, install_dir / "data/grafana.db") if kind != "dir")
    free_bytes = shutil.disk_usage(backup_dir).free
    if free_bytes < int(estimated_bytes * 1.2) + reserve_bytes:
        raise BackupError("Espacio insuficiente para backup y reserva de seguridad; revisar el disco sin borrar datos")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"grafana-full-{stamp}-{secrets.token_hex(4)}.tar.gz"
    final_archive = backup_dir / name
    sidecar = backup_dir / (name + ".sha256")
    if final_archive.exists() or sidecar.exists():
        raise BackupError("El archivo de backup ya existe; prohibido sobrescribir")
    with tempfile.TemporaryDirectory(prefix=".stage-", dir=backup_dir) as stage:
        stage_path = Path(stage)
        sqlite_snapshot = stage_path / "grafana.db"
        online_sqlite_backup(install_dir / "data/grafana.db", sqlite_snapshot)
        tmp_archive = stage_path / name
        stats = make_archive(tmp_archive, install_dir, sqlite_snapshot,
                             image_name=image_name, created_utc=stamp)
        # Chequear que el tar gz se puede leer antes de publicarlo.
        with tarfile.open(tmp_archive, "r:gz") as check:
            if check.getmember("META/manifest.json").size < 20:
                raise BackupError("Manifiesto del backup inválido")
        digest = sha256_file(tmp_archive)
        os.chmod(tmp_archive, 0o600)
        # No se sobrescriben copias previas; nombre impredecible + comprobación previa.
        # Enlace exclusivo en el mismo filesystem: falla si otro backup ya tiene el nombre.
        os.link(tmp_archive, final_archive)
        tmp_archive.unlink()
        os.chmod(final_archive, 0o600)
        tmp_sum = stage_path / (name + ".sha256")
        tmp_sum.write_text(f"{digest}  {name}\n", encoding="utf-8")
        os.chmod(tmp_sum, 0o600)
        os.link(tmp_sum, sidecar)
        tmp_sum.unlink()
    return {"archive": str(final_archive), "sha256": digest,
            "sha256_file": str(sidecar), "archive_size": final_archive.stat().st_size,
            **stats, "database": "sqlite-online-backup", "grafana_modified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Backup consistente de Grafana SQLite")
    parser.add_argument("--install-dir", required=True, type=Path)
    parser.add_argument("--backup-dir", required=True, type=Path)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--reserve-bytes", type=int, default=536870912)
    args = parser.parse_args(argv)
    try:
        if not args.project_name or args.project_name.startswith("-"):
            raise BackupError("Nombre de proyecto Compose inválido")
        if args.reserve_bytes < 0:
            raise BackupError("Reserva de espacio inválida")
        result = run(args.install_dir, args.backup_dir, args.project_name, args.reserve_bytes)
    except (BackupError, OSError, ValueError, tarfile.TarError) as ex:
        # No revelar rutas ni secretos de los archivos contenidos.
        print(f"ERROR BACKUP: {ex}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
