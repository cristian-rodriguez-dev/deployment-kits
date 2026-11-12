#!/usr/bin/env python3
"""Validación offline de cobertura de los 16 dashboards V2 del laboratorio.

Opcionalmente compara las especificaciones con el ZIP exportado por el Job 12.
Solo lectura: no conecta a Grafana, no utiliza credenciales y no modifica archivos.
"""
import argparse
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile

EXPECTED_TITLES = {
    'adnk6jm': 'Fleet - Infrastructure Overview',
    'adcfhnb': 'Host Detail',
    'adrxc42': 'K3s Overview',
    'adghvhn': 'Loki Overview',
    'adqmqdw': 'Platform Overview',
    'adgsl8t': 'Security Overview',
    'ad4fsvl': 'Traefik Overview',
    'ads8xnn': 'GeoIP - Map',
    'rYdddlPWk': 'Node Exporter Full',
    'wazuh-vulnerabilities': 'Wazuh - Vulnerabilities',
    'wazuh-agent-status': 'Wazuh — Agent Status',
    'wazuh-mixed-prometheus-example': 'Wazuh — Correlation with Prometheus',
    'wazuh-fim': 'Wazuh — File Integrity (FIM)',
    'wazuh-sca': 'Wazuh — Security Configuration (SCA)',
    'wazuh-security-overview': 'Wazuh — Security Overview',
    'security-triage-observabilidad': 'Security Triage — Observabilidad del Bot',
}

NEW_SHA256 = {
    'ads8xnn': 'ac03b381c2f91dccb799bdfdb80f884ba9aaebb9b8f0c8f14ecf26ccfd2f8f9c',
    'rYdddlPWk': 'bbced6e935d952c73b87d162458631d304200f8ac6646c6c96ef6afdc5ec3ef1',
    'wazuh-vulnerabilities': '553412997d0a3a4a04324c1c6b5de22b0d37407f3a10e1ca782c917b0af92a17',
    'wazuh-agent-status': '85061542785e7313fb9caef5a77c4476e3d04908781b74b0104357e028741dec',
    'wazuh-mixed-prometheus-example': '2cb54029846f2cdb4b6f00017bd8214b3f773654f185edd5d3a0fae31332b4d1',
    'wazuh-fim': '7825733717012e2b2a35a4e1e220c419595104e2d9da0b46bd6dce3490dfc454',
    'wazuh-sca': 'af87edff839d23e6bb97f373180ebcae28576aab465d43c1baca4ab97e06662e',
    'wazuh-security-overview': '9dafc032f6a4db46f7ef8c89deaf456811be60b4cecd90b904f0b53ac616ea24',
    'security-triage-observabilidad': '8b19249694fb30d97c992aaa4c9e5d7c0ce82fe9ee222fafc9bd05a4663e7936',
}


def inspect_repo(repo: Path) -> tuple[dict, int]:
    folder = repo / 'monitorizacion' / 'dashboards'
    if not folder.is_dir():
        raise ValueError(f'No existe directorio de dashboards: {folder}')
    files = sorted(folder.glob('*.json'))
    if len(files) != 16:
        raise ValueError(f'Se esperaban 16 JSON; encontrados {len(files)}')
    found = {}
    panels = 0
    for path in files:
        raw = path.read_bytes()
        obj = json.loads(raw)
        if obj.get('kind') != 'Dashboard' or obj.get('apiVersion') != 'dashboard.grafana.app/v2':
            raise ValueError(f'No es Dashboard V2: {path.name}')
        uid = obj.get('metadata', {}).get('name')
        spec = obj.get('spec', {})
        if uid not in EXPECTED_TITLES:
            raise ValueError(f'UID inesperado en {path.name}: {uid}')
        if uid in found:
            raise ValueError(f'UID duplicado: {uid}')
        if spec.get('title') != EXPECTED_TITLES[uid]:
            raise ValueError(f'Título inesperado para UID {uid}')
        els = spec.get('elements')
        if not isinstance(els, dict):
            raise ValueError(f'No se puede contar paneles en {uid}')
        panels += sum(1 for v in els.values() if isinstance(v, dict) and v.get('kind') == 'Panel')
        if uid in NEW_SHA256 and hashlib.sha256(raw).hexdigest() != NEW_SHA256[uid]:
            raise ValueError(f'El archivo nuevo {uid} ha cambiado respecto al respaldo del 10/11/2026')
        found[uid] = obj
    if set(found) != set(EXPECTED_TITLES):
        raise ValueError('Faltan UID: ' + ', '.join(sorted(set(EXPECTED_TITLES) - set(found))))
    return found, panels


def verify_against_export(found: dict, zip_path: Path) -> None:
    expected_hash = '2869f92a27f9cc8c294619581207d3c2d997b8bb96c60781300071766c6e1fa3'
    if hashlib.sha256(zip_path.read_bytes()).hexdigest() != expected_hash:
        raise ValueError('SHA256 del ZIP exportado diferente del registrado en AWX')
    with ZipFile(zip_path) as bundle:
        manifest = json.loads(bundle.read('manifest.json'))
        records = manifest['dashboards']
        if len(records) != 16 or manifest.get('expected_count') != 16:
            raise ValueError('Manifiesto de exportación incompleto')
        for row in records:
            uid = row['uid']
            if uid not in found:
                raise ValueError(f'Falta {uid} en repositorio')
            raw = bundle.read(row['path'])
            if hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise ValueError(f'SHA256 interno incorrecto para {uid}')
            exported = json.loads(raw)
            if row['format'] != 'v2' or exported.get('metadata', {}).get('name') != uid:
                raise ValueError(f'No es V2 con UID correcto: {uid}')
            if found[uid]['spec'] != exported['spec']:
                raise ValueError(f'La definición de {uid} no coincide con el respaldo de AWX')


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repo', type=Path, default=Path('.'), help='raíz local del repositorio deployment-kits')
    ap.add_argument('--export', type=Path, help='ZIP original descargado del Job Template 12')
    args = ap.parse_args()
    try:
        found, panels = inspect_repo(args.repo)
        print(f'OK: {len(found)} dashboards V2 únicos; {panels} paneles; 9 con SHA256 verificado.')
        if args.export:
            verify_against_export(found, args.export)
            print('OK: 16/16 definiciones coinciden con la exportación íntegra del Job 12.')
        return 0
    except (ValueError, KeyError, OSError, json.JSONDecodeError, RuntimeError) as exc:
        print(f'ERROR: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
