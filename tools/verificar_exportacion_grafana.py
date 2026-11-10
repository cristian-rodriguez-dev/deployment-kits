#!/usr/bin/env python3
"""Verifica backup Grafana exportado desde AWX y compara los UID de un repo local.

No llama a ninguna API ni modifica dashboards. No extrae archivos salvo petición explícita.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

UID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
FORMATS = {"v1", "v2", "legacy"}


def validate(archive: Path) -> tuple[dict, dict]:
    with zipfile.ZipFile(archive) as z:
        if z.testzip() is not None:
            raise ValueError("ZIP corrupto")
        if "manifest.json" not in z.namelist():
            raise ValueError("Falta manifest.json")
        manifest = json.loads(z.read("manifest.json"))
        records = manifest.get("dashboards")
        n = manifest.get("expected_count")
        if not isinstance(records, list) or type(n) is not int or n != len(records) or not 1 <= n <= 5000:
            raise ValueError("Cantidad o manifiesto inválido")
        if len(z.namelist()) != n + 1 or len(set(z.namelist())) != n + 1:
            raise ValueError("Números de archivos incorrectos o nombres duplicados")
        by_uid = {}
        for record in records:
            uid, fmt, title = record["uid"], record["format"], record["title"]
            if not isinstance(uid, str) or not UID_RE.fullmatch(uid) or uid in by_uid or fmt not in FORMATS:
                raise ValueError("UID duplicado o formato inválido")
            member = f"dashboards/{fmt}/{uid}.json"
            if record["path"] != member or member not in z.namelist():
                raise ValueError(f"Falta dashboard o ruta inválida: {uid}")
            data_bytes = z.read(member)
            if record.get("sha256") != hashlib.sha256(data_bytes).hexdigest():
                raise ValueError(f"SHA256 incorrecto: {uid}")
            data = json.loads(data_bytes)
            if fmt == "legacy":
                ok = data.get("dashboard", {}).get("uid") == uid and data.get("dashboard", {}).get("title") == title
            else:
                ok = (data.get("kind") == "Dashboard" and data.get("metadata", {}).get("name") == uid
                      and data.get("apiVersion") == f"dashboard.grafana.app/{fmt}"
                      and data.get("spec", {}).get("title") == title)
            if not ok:
                raise ValueError(f"Datos inconsistentes: {uid}")
            by_uid[uid] = (record, data, data_bytes)
        if set(z.namelist()) != {"manifest.json"} | {v[0]["path"] for v in by_uid.values()}:
            raise ValueError("Archivos no declarados en manifiesto")
        return manifest, by_uid


def compare_local(repo: Path, by_uid: dict) -> None:
    dashboards_path = repo / "monitorizacion" / "dashboards"
    if not dashboards_path.is_dir():
        raise FileNotFoundError(f"No existe {dashboards_path}")
    matches = []
    different = []
    existing_uids = set()
    for path in sorted(dashboards_path.glob("*.json")):
        original = json.loads(path.read_text(encoding="utf-8"))
        uid = original.get("metadata", {}).get("name")
        if not uid:
            continue
        existing_uids.add(uid)
        if uid not in by_uid:
            different.append(f"{uid}: sin correspondencia en ZIP")
            continue
        record, current, _ = by_uid[uid]
        if record["format"] == "v2" and current.get("spec") == original.get("spec"):
            matches.append(uid)
        else:
            different.append(f"{uid}: formato o spec diferente")
    print(f"Dashboards V2 de Git con contenido igual al servidor: {len(matches)}")
    for uid in matches:
        print(f"  OK {uid}")
    for message in different:
        print(f"  REVISAR {message}")
    missing = [(uid, record["format"], record["title"]) for uid, (record, _, _) in by_uid.items()
               if uid not in existing_uids]
    print(f"Dashboards del servidor todavía ausentes en Git: {len(missing)}")
    for uid, fmt, title in missing:
        print(f"  NUEVO {uid} [{fmt}] {title}")
    print("No se han modificado archivos del repositorio")


def extract(stage: Path, by_uid: dict) -> None:
    if stage.exists():
        raise FileExistsError("El destino de extracción ya existe. Elige una carpeta nueva")
    stage.mkdir(mode=0o700, parents=True)
    for record, _, payload in by_uid.values():
        path = stage / record["path"]
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(payload)
        path.chmod(0o600)
    print(f"Archivos extraídos en {stage} (solo candidatos; no se han incorporado a Git)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip", type=Path, help="ZIP copiado del servidor")
    parser.add_argument("--repositorio", type=Path, help="Raíz de deployment-kits, para comparar 7 JSON")
    parser.add_argument("--extraer", type=Path, help="Carpeta NUEVA para extraer los JSON con seguridad")
    options = parser.parse_args()
    manifest, records = validate(options.zip)
    fmt_counts = {fmt: sum(1 for rec, _, _ in records.values() if rec["format"] == fmt) for fmt in sorted(FORMATS)}
    print(f"Verificación OK: {manifest['expected_count']} dashboards; formatos {fmt_counts}")
    if options.repositorio:
        compare_local(options.repositorio, records)
    if options.extraer:
        extract(options.extraer, records)
    print("Advertencia: revisar JSON antes de publicarlos en Git; pueden incluir información interna.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        sys.exit(f"ERROR: {exc}")
