#!/usr/bin/env python3
"""Captura/compara alerting Grafana mediante GET, sin modificar Grafana.

Los cuerpos de API pueden incluir secretos o URLs privadas: solamente se guardan
localmente en un directorio 0700 y archivos 0600. La salida stdout es un resumen.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API = {
    "alert_rules": ("/api/v1/provisioning/alert-rules", True),
    "contact_points": ("/api/v1/provisioning/contact-points", True),
    "policies": ("/api/v1/provisioning/policies", True),
    "mute_timings": ("/api/v1/provisioning/mute-timings", False),
    "templates": ("/api/v1/provisioning/templates", False),
    "alert_rules_export": ("/api/v1/provisioning/alert-rules/export?format=json", False),
    "contact_points_export": ("/api/v1/provisioning/contact-points/export?format=json", False),
    "policies_export": ("/api/v1/provisioning/policies/export?format=json", False),
    "mute_timings_export": ("/api/v1/provisioning/mute-timings/export?format=json", False),
}
SNAPSHOT_RE = re.compile(r"^alerting-\d{8}T\d{6}Z-[0-9a-f]{12}\.json$")
MAX_RESPONSE_BYTES = 25 * 1024 * 1024


class SnapshotError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SnapshotError("Grafana devolvió una redirección inesperada; no se siguen destinos externos")


def canonical(obj: object) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def safe_json_bytes(data: bytes, endpoint: str) -> object:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"Respuesta no JSON de endpoint {endpoint}") from exc


def api_fetcher(port: int, username: str, password: str):
    if not 1 <= port <= 65535:
        raise SnapshotError("Puerto Grafana inválido")
    if not username or not password:
        raise SnapshotError("Faltan credenciales de Grafana en el entorno protegido")
    base = f"http://127.0.0.1:{port}"
    auth = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    # Nunca enviar credenciales de la API local a un proxy definido en el entorno.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def get(endpoint: str, required: bool) -> dict:
        path, _ = API[endpoint]
        request = urllib.request.Request(
            base + path,
            headers={"Authorization": "Basic " + auth, "Accept": "application/json"},
            method="GET",
        )
        try:
            with opener.open(request, timeout=20) as response:
                payload = response.read(MAX_RESPONSE_BYTES + 1)
                if len(payload) > MAX_RESPONSE_BYTES:
                    raise SnapshotError(f"Respuesta excesiva en endpoint {endpoint}")
                return {"state": "ok", "body": safe_json_bytes(payload, endpoint)}
        except urllib.error.HTTPError as exc:
            if not required and exc.code in (404, 405):
                return {"state": "unsupported", "body": None}
            raise SnapshotError(f"Endpoint {endpoint}: HTTP {exc.code}. No se han modificado recursos") from None
        except urllib.error.URLError as exc:
            raise SnapshotError(f"No se pudo conectar a Grafana al consultar {endpoint}") from exc

    return get


def collect(fetch) -> dict:
    return {name: fetch(name, required) for name, (_, required) in API.items()}


def check_private_dir(root: Path) -> None:
    if not root.is_absolute() or root == Path("/") or ".." in root.parts:
        raise SnapshotError("Ruta de respaldo inválida")
    if root.is_symlink() or not root.is_dir():
        raise SnapshotError("El directorio privado no existe o es un symlink")
    info = root.stat()
    if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != 0:
        raise SnapshotError("El directorio debe pertenecer a root y tener permisos 0700")


def atomic_new_file(path: Path, data: bytes) -> None:
    """Publica un snapshot completo, de forma atómica, sin pisar archivos."""
    fd, temporary_name = tempfile.mkstemp(prefix=".partial-", dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        # link() falla si el destino existe. No usamos replace(), que pisaría backups.
        os.link(str(temporary), str(path), follow_symlinks=False)
        directory_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def safe_read_snapshot(root: Path, path: Path, expected_sha: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise SnapshotError("El SHA256 de referencia no es válido")
    if path.parent != root or not SNAPSHOT_RE.fullmatch(path.name):
        raise SnapshotError("La referencia debe ser un snapshot del directorio privado")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != 0:
        raise SnapshotError("Referencia no regular, no privada o no propiedad de root")
    contents = path.read_bytes()
    if sha256(contents) != expected_sha:
        raise SnapshotError("El SHA256 del respaldo de referencia no coincide")
    snapshot = safe_json_bytes(contents, "referencia")
    if not isinstance(snapshot, dict) or snapshot.get("schema") != "grafana-alerting-snapshot-v1":
        raise SnapshotError("Referencia no es un snapshot compatible")
    if not isinstance(snapshot.get("endpoints"), dict) or set(snapshot["endpoints"]) != set(API):
        raise SnapshotError("Snapshot incompleto")
    return snapshot


def total_for(body: object) -> int:
    if isinstance(body, list):
        return len(body)
    if isinstance(body, dict):
        # Policies = árbol completo; lo contamos como uno.
        return 1
    return 0


def summary_for(snapshot: dict) -> dict:
    return {
        name: ({"state": d["state"], "count": total_for(d["body"])} if d["state"] == "ok" else {"state": "unsupported"})
        for name, d in snapshot["endpoints"].items()
    }


def run(mode: str, root: Path, port: int, user: str, password: str,
        baseline: str | None = None, expected_sha: str | None = None,
        fetch=None) -> dict:
    check_private_dir(root)
    if mode not in {"capture", "compare"}:
        raise SnapshotError("Modo no admitido")
    if mode == "compare" and (not baseline or not expected_sha):
        raise SnapshotError("Compare requiere ruta y SHA256 de referencia")
    fetch = fetch if fetch is not None else api_fetcher(port, user, password)
    current = {"schema": "grafana-alerting-snapshot-v1", "endpoints": collect(fetch)}
    safe_summary = summary_for(current)
    if mode == "compare":
        old = safe_read_snapshot(root, Path(baseline), expected_sha or "")
        different = [name for name in API if canonical(old["endpoints"][name]) != canonical(current["endpoints"][name])]
        return {
            "mode": "COMPARE", "status": "SIN CAMBIOS" if not different else "DERIVA DETECTADA",
            "changed_categories": different, "changed_count": len(different), "categories": safe_summary,
            "grafana_writes": 0,
        }
    blob = canonical(current) + b"\n"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"alerting-{stamp}-{secrets.token_hex(6)}.json"
    dest = root / name
    atomic_new_file(dest, blob)
    return {
        "mode": "CAPTURE", "status": "RESPALDO PRIVADO GENERADO", "snapshot": str(dest),
        "sha256_bytes": sha256(blob), "categories": safe_summary, "grafana_writes": 0,
        "warning": "El JSON puede contener datos sensibles y secretos ocultos: NO subirlo a Git; no sustituye un backup completo",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["capture", "compare"], default="capture")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--baseline")
    parser.add_argument("--sha256")
    args = parser.parse_args()
    try:
        result = run(
            args.mode, args.backup_dir, args.port,
            os.environ.get("GRAFANA_ALERTING_USERNAME", ""),
            os.environ.get("GRAFANA_ALERTING_PASSWORD", ""),
            args.baseline, args.sha256,
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except (SnapshotError, OSError, ValueError) as exc:
        # Nunca mostramos cuerpos HTTP ni excepciones que pudieran llevar credenciales.
        print(f"ERROR SEGURO: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
