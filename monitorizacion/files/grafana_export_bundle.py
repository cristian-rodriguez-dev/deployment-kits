#!/usr/bin/env python3
"""Empaqueta un snapshot Grafana prevalidado. Solo lee el staging, no hace HTTP."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import zipfile

UID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
FORMATS = {"v1", "v2", "legacy"}


def build(stage: Path, destination: Path) -> None:
    stage = stage.resolve(strict=True)
    manifest_path = stage / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    records = manifest.get("dashboards")
    expected = manifest.get("expected_count")
    if not isinstance(records, list) or type(expected) is not int or len(records) != expected or not 1 <= expected <= 5000:
        raise ValueError("Manifiesto incompleto o cantidad no válida")
    if destination.exists():
        raise FileExistsError("No se sobrescriben ZIP existentes")
    if destination.parent.resolve(strict=True) == stage:
        raise ValueError("Destino no puede estar dentro del staging")

    files = []
    seen = set()
    for record in records:
        uid, fmt, title = record["uid"], record["format"], record["title"]
        if not isinstance(uid, str) or not UID_RE.fullmatch(uid) or uid in seen or fmt not in FORMATS:
            raise ValueError("UID o formato inválido o duplicado")
        if not isinstance(title, str) or not title.strip():
            raise ValueError("Título inválido")
        seen.add(uid)
        member = f"dashboards/{fmt}/{uid}.json"
        if record["path"] != member:
            raise ValueError(f"Ruta inesperada: {uid}")
        f = stage / member
        if not f.is_file() or f.is_symlink() or f.resolve().is_relative_to(stage) is False:
            raise ValueError(f"Archivo ausente o no seguro: {member}")
        payload = f.read_bytes()
        data = json.loads(payload)
        if fmt == "legacy":
            valid = (data.get("dashboard", {}).get("uid") == uid and data.get("dashboard", {}).get("title") == title)
        else:
            valid = (data.get("kind") == "Dashboard" and data.get("metadata", {}).get("name") == uid
                     and data.get("apiVersion") == f"dashboard.grafana.app/{fmt}"
                     and data.get("spec", {}).get("title") == title)
        if not valid:
            raise ValueError(f"Contenido distinto del inventario: {uid}")
        record["sha256"] = hashlib.sha256(payload).hexdigest()
        files.append((member, payload))

    manifest_bytes = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    tmp = destination.with_suffix(destination.suffix + ".partial")
    descriptor = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        with os.fdopen(descriptor, "w+b") as stream:
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
                z.writestr("manifest.json", manifest_bytes)
                for member, payload in files:
                    z.writestr(member, payload)
        with zipfile.ZipFile(tmp) as z:
            if z.testzip() is not None or len(z.namelist()) != expected + 1:
                raise ValueError("ZIP truncado o con ficheros de más")
        os.link(tmp, destination)  # Atomicidad y sin sobrescribir copias anteriores.
    finally:
        tmp.unlink(missing_ok=True)
    print(f"OK: {expected} dashboards, archivo ZIP verificado")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Uso: grafana_export_bundle.py DIRECTORIO_TEMPORAL ZIP_DESTINO")
    try:
        build(Path(sys.argv[1]), Path(sys.argv[2]))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        sys.exit(f"ERROR: {type(exc).__name__}: {exc}")
