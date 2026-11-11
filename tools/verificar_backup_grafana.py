#!/usr/bin/env python3
"""Verifica offline el backup integral sin extraer todo el contenido.

No necesita dependencias externas; compatible con uv en Windows y Linux.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

REQUIRED = {
    "grafana/data/grafana.db",
    "grafana/docker-compose.yml",
    "grafana/secrets/admin_password",
}
ALLOWED = ("grafana/data/", "grafana/provisioning/", "grafana/secrets/")


class VerifyError(Exception):
    pass


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(archive_path: Path, expected_sha256: str | None = None) -> dict:
    if not archive_path.is_file():
        raise VerifyError("No se encuentra el archivo indicado")
    actual_sha = digest_file(archive_path)
    sidecar = archive_path.with_name(archive_path.name + ".sha256")
    if expected_sha256 is None and sidecar.is_file():
        line = sidecar.read_text(encoding="utf-8").strip()
        m = re.fullmatch(r"([0-9a-f]{64})\s+\*?(.+)", line)
        if not m or m.group(2) != archive_path.name:
            raise VerifyError("El archivo .sha256 no tiene el formato esperado")
        expected_sha256 = m.group(1)
    if expected_sha256 is not None:
        if not re.fullmatch(r"[a-fA-F0-9]{64}", expected_sha256):
            raise VerifyError("SHA256 esperado inválido")
        if actual_sha != expected_sha256.lower():
            raise VerifyError("SHA256 del archivo no coincide")

    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = archive.getmembers()
        paths = [x.name for x in members]
        if len(paths) != len(set(paths)):
            raise VerifyError("Rutas duplicadas en el archivo tar")
        for member in members:
            name = member.name.rstrip("/")
            parts = PurePosixPath(name).parts
            if name.startswith("/") or ".." in parts or not (member.isfile() or member.isdir()):
                raise VerifyError("Tipo de archivo o ruta insegura en el backup")
            if member.isdir() and not name.startswith("grafana/") and name not in ("grafana",):
                raise VerifyError("Directorio fuera de grafana/")
            if member.isfile() and name != "META/manifest.json" and not (
                name in ("grafana/docker-compose.yml", "grafana/.awx-initialized")
                or name.startswith(ALLOWED)
            ):
                raise VerifyError("Archivo inesperado fuera de los directorios de Grafana")
        try:
            manifest_member = archive.getmember("META/manifest.json")
        except KeyError as ex:
            raise VerifyError("Falta el manifiesto del backup") from ex
        if not manifest_member.isfile() or manifest_member.size > 10_000_000:
            raise VerifyError("Manifiesto demasiado grande o inválido")
        with archive.extractfile(manifest_member) as f:
            manifest = json.loads(f.read())
        if manifest.get("schema") != 1 or not isinstance(manifest.get("files"), list):
            raise VerifyError("Esquema del manifiesto inválido")
        declared = {x.get("path"): x for x in manifest["files"]}
        if len(declared) != len(manifest["files"]):
            raise VerifyError("Archivos duplicados en el manifiesto")
        regular = {m.name: m for m in members if m.isfile() and m.name != "META/manifest.json"}
        if set(regular) != set(declared):
            raise VerifyError("Los archivos no coinciden con el manifiesto")
        if not REQUIRED.issubset(regular):
            raise VerifyError("Falta algún archivo imprescindible para restaurar")
        with tempfile.TemporaryDirectory(prefix="grafana-backup-check-") as d:
            sqlite_path = Path(d) / "grafana.db"
            for path, member in regular.items():
                digest = hashlib.sha256()
                nbytes = 0
                with archive.extractfile(member) as f:
                    if path == "grafana/data/grafana.db":
                        out = sqlite_path.open("wb")
                    else:
                        out = None
                    try:
                        while True:
                            block = f.read(1024 * 1024)
                            if not block:
                                break
                            digest.update(block)
                            nbytes += len(block)
                            if out is not None:
                                out.write(block)
                    finally:
                        if out is not None:
                            out.close()
                item = declared[path]
                if nbytes != item.get("size") or nbytes != member.size or digest.hexdigest() != item.get("sha256"):
                    raise VerifyError("Archivo corrupto o no coincidente: " + path)
            try:
                con = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
                with con:
                    row = con.execute("PRAGMA quick_check").fetchone()
                con.close()
            except sqlite3.Error as ex:
                raise VerifyError("No se puede leer el snapshot SQLite") from ex
            if not row or row[0] != "ok":
                raise VerifyError("Integridad SQLite no válida")
    return {"files": len(regular), "sha256": actual_sha, "sqlite": "ok", "verified": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Verificador offline del backup de Grafana")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sha256", help="SHA256 esperado del Job 13 (opcional si existe .sha256)")
    args = parser.parse_args(argv)
    try:
        result = verify(args.archive, args.sha256)
    except (VerifyError, OSError, tarfile.TarError, ValueError, json.JSONDecodeError) as ex:
        print(f"ERROR: {ex}", file=sys.stderr)
        return 1
    print(f"OK: SHA256={result['sha256']}; archivos={result['files']}; SQLite={result['sqlite']}")
    print("OK: backup integro. Aun falta probar restauracion en una VM aislada.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
