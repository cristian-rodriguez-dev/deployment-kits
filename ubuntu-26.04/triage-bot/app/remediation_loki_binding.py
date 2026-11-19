"""Pilas Observabilidad / Bloque 19E: vínculo CONSULTIVO incidente Grafana ↔ AWX.

Las referencias se capturan en la ruta webhook de Grafana protegida por token,
pero ese token compartido NO verifica criptográficamente la identidad del
emisor. Los campos siguen siendo *afirmaciones del webhook*. Un operador proporciona un Job ID manual; el módulo
verifica su procedencia llamando a AWX con credencial solo lectura. No lanza
jobs, no cambia política/avisos y nunca realiza acciones de recuperación.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.awx_loki_verification import (
    AWXReadOnlyConfig, AWXVerificationError, fetch_verified_observation,
)
from app.remediation_loki import RULE_UID, propose_loki_diagnostic

VERSION = 'loki-awx-incident-binding-v1'
REFERENCE_VERSION = 'grafana-loki-reference-v1'
ALERT_TITLE = 'Critico - Loki no disponible'
MAX_INCIDENT_AGE = timedelta(minutes=15)
MAX_CLOCK_SKEW = timedelta(seconds=30)
UID_LABELS = ('__alert_rule_uid__', 'grafana_rule_uid', 'remediation_rule_uid')
HEX = re.compile(r'[0-9a-fA-F]{16,128}\Z')


def _utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 45:
        return None
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return None
    return dt.astimezone(timezone.utc) if dt.tzinfo is not None else None


def capture_grafana_loki_reference(alert: Any, labels: Any) -> dict | None:
    """Solo metadatos acotados; NO almacena URLs, etiquetas libres ni huella cruda.

    Requiere UID explícito: el webhook por defecto de Grafana no lo garantiza.
    No infiere el UID de un título, generatorURL o expresión PromQL.
    """
    if type(alert) is not dict or type(labels) is not dict:
        return None
    if (alert.get('status') != 'firing'
            or labels.get('alertname') != ALERT_TITLE
            or labels.get('component') != 'loki'
            or labels.get('managed_by') != 'awx'):
        return None
    supplied = [labels[key] for key in UID_LABELS if key in labels]
    if not supplied or any(type(uid) is not str or uid != RULE_UID for uid in supplied):
        return None
    start = _utc(alert.get('startsAt'))
    fingerprint = alert.get('fingerprint')
    if start is None or type(fingerprint) is not str or not HEX.fullmatch(fingerprint):
        return None
    return {
        'version': REFERENCE_VERSION,
        'source': 'grafana_webhook_claim',
        'rule_uid': RULE_UID,
        'component': 'loki',
        'status': 'firing',
        'starts_at_utc': start.isoformat(),
        'fingerprint_sha256': hashlib.sha256(fingerprint.encode('ascii')).hexdigest(),
    }


def _reference_valid(value: Any) -> bool:
    if type(value) is not dict or set(value) != {
        'version', 'source', 'rule_uid', 'component', 'status',
        'starts_at_utc', 'fingerprint_sha256',
    }:
        return False
    if (value.get('version') != REFERENCE_VERSION
            or value.get('source') != 'grafana_webhook_claim'
            or value.get('rule_uid') != RULE_UID
            or value.get('component') != 'loki'
            or value.get('status') != 'firing'):
        return False
    digest = value.get('fingerprint_sha256')
    return (type(digest) is str and bool(re.fullmatch(r'[0-9a-f]{64}', digest))
            and _utc(value.get('starts_at_utc')) is not None)


def _result(incident_id: int | None, reason: str, status: str = 'investigate') -> dict:
    return {
        'version': VERSION, 'incident_id': incident_id,
        'status': status, 'reason_code': reason,
        'awx_job_verified': False, 'linkage': 'not_verified',
        'awx_job_id': None, 'proposal': None,
        'requires_human_review': True, 'execution_allowed': False,
    }


def _read_incident(db_path: Path, incident_id: int) -> tuple | None:
    if (not isinstance(db_path, Path) or not db_path.is_absolute()
            or not db_path.is_file() or db_path.is_symlink()):
        return None
    # SQLite read-only, sin migraciones y sin acceso a otros datos del incidente.
    con = sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True, timeout=3)
    try:
        con.execute('PRAGMA query_only=ON')
        return con.execute(
            'SELECT source, synthetic, title, received_at, analysis '
            'FROM incidents WHERE id=?', (incident_id,),
        ).fetchone()
    finally:
        con.close()


def review_incident(
    *, incident_id: int, job_id: int, db_path: Path,
    config: AWXReadOnlyConfig, now: datetime | None = None,
) -> dict:
    """Una revisión iniciada por operador, nunca desde un webhook.

    La correlación es manual y temporal, NO una prueba criptográfica de que el
    job fue provocado por el incidente. El Job ID jamás procede del payload.
    """
    ident = incident_id if type(incident_id) is int and 0 < incident_id <= 2_147_483_647 else None
    out = _result(ident, 'invalid_input')
    if ident is None or type(job_id) is not int or not 0 < job_id <= 2_147_483_647:
        return out
    current = datetime.now(timezone.utc) if now is None else now
    if not isinstance(current, datetime) or current.tzinfo is None:
        return _result(ident, 'invalid_review_time')
    current = current.astimezone(timezone.utc)
    try:
        row = _read_incident(db_path, ident)
    except (sqlite3.Error, OSError, ValueError):
        row = None
    if row is None:
        return _result(ident, 'incident_unavailable')
    source, synthetic, title, received, analysis = row
    if source != 'grafana' or synthetic != 0 or title != ALERT_TITLE:
        return _result(ident, 'unsupported_incident', 'no_action')
    try:
        obj = json.loads(analysis)
    except (ValueError, TypeError):
        return _result(ident, 'invalid_incident_analysis')
    if type(obj) is not dict or not _reference_valid(obj.get('grafana_loki_reference')):
        return _result(ident, 'missing_rule_uid_reference')
    triage = obj.get('triage')
    if type(triage) is not dict or triage.get('decision') not in ('notify', 'review'):
        return _result(ident, 'incident_not_eligible', 'no_action')
    received_at = _utc(received)
    start = _utc(obj['grafana_loki_reference']['starts_at_utc'])
    if (received_at is None or start is None
            or not timedelta(0) <= current - received_at <= MAX_INCIDENT_AGE
            or start > received_at + timedelta(minutes=2)):
        return _result(ident, 'stale_or_inconsistent_incident')
    try:
        verified = fetch_verified_observation(job_id=job_id, config=config, now=current)
    except AWXVerificationError as exc:
        out = _result(ident, 'awx_verification_failed')
        out['verification_error_code'] = exc.code  # Código fijo, jamás texto remoto.
        return out
    observed_at = _utc(verified.observation.get('observed_at_utc'))
    if (verified.job_id != job_id or observed_at is None
            or observed_at < received_at - MAX_CLOCK_SKEW):
        return _result(ident, 'observation_precedes_incident')
    signal = {'source': 'grafana', 'rule_uid': RULE_UID,
              'component': 'loki', 'status': 'firing'}
    proposal = propose_loki_diagnostic(
        incident_id=ident, signal=signal, observation=verified.observation,
        observation_trusted=True, now=current,
    )
    if (type(proposal) is not dict or proposal.get('execution_allowed') is not False
            or proposal.get('requires_approval') is not True):
        return _result(ident, 'invalid_proposal')
    return {
        'version': VERSION, 'incident_id': ident,
        'status': proposal.get('status'), 'reason_code': proposal.get('reason_code'),
        'awx_job_verified': True,
        'linkage': 'operator_selected_recent_diagnostic',
        'awx_job_id': job_id, 'proposal': proposal,
        'requires_human_review': True, 'execution_allowed': False,
    }


def record_review(*, db_path: Path, review: dict, now: datetime | None = None) -> bool:
    """Registro opt-in independiente y append-only; nunca altera `incidents`.

    Solo debe utilizarse con el objeto devuelto por `review_incident` tras una
    lectura AWX autenticada, NO con dicts recibidos por API/webhook/LLM.
    """
    if (type(review) is not dict or review.get('awx_job_verified') is not True
            or review.get('linkage') != 'operator_selected_recent_diagnostic'
            or review.get('execution_allowed') is not False
            or type(review.get('incident_id')) is not int
            or type(review.get('awx_job_id')) is not int
            or not isinstance(db_path, Path) or not db_path.is_absolute()
            or not db_path.is_file() or db_path.is_symlink()):
        raise ValueError('invalid_review_for_record')
    timestamp = datetime.now(timezone.utc) if now is None else now
    if type(timestamp) is not datetime or timestamp.tzinfo is None:
        raise ValueError('invalid_record_time')
    proposal = review.get('proposal')
    if (type(proposal) is not dict or proposal.get('execution_allowed') is not False
            or proposal.get('requires_approval') is not True):
        raise ValueError('invalid_review_for_record')
    with sqlite3.connect(db_path, timeout=5) as con:
        con.execute('PRAGMA busy_timeout=5000')
        con.execute('''CREATE TABLE IF NOT EXISTS remediation_reviews (
            incident_id INTEGER NOT NULL,
            awx_job_id INTEGER NOT NULL UNIQUE,
            reviewed_at_utc TEXT NOT NULL,
            status TEXT NOT NULL,
            reason_code TEXT NOT NULL,
            proposal_json TEXT NOT NULL,
            PRIMARY KEY (incident_id, awx_job_id)
        )''')
        cursor = con.execute('''INSERT OR IGNORE INTO remediation_reviews
            (incident_id, awx_job_id, reviewed_at_utc, status, reason_code, proposal_json)
            VALUES(?,?,?,?,?,?)''', (
            review['incident_id'], review['awx_job_id'],
            timestamp.astimezone(timezone.utc).isoformat(),
            review['status'], review['reason_code'],
            json.dumps(proposal, ensure_ascii=True, sort_keys=True),
        ))
        return cursor.rowcount == 1


def main() -> int:
    parser = argparse.ArgumentParser(description='19E: revisión consultiva Loki ↔ AWX')
    parser.add_argument('--db', type=Path, required=True)
    parser.add_argument('--incident-id', type=int, required=True)
    parser.add_argument('--job-id', type=int, required=True)
    parser.add_argument('--awx-url', required=True)
    parser.add_argument('--awx-token-file', type=Path, required=True)
    parser.add_argument('--awx-ca-file', type=Path)
    parser.add_argument('--job-template-id', type=int, required=True)
    parser.add_argument('--inventory-id', type=int, required=True)
    parser.add_argument('--project-id', type=int, required=True)
    parser.add_argument('--record', action='store_true', help='Registrar vínculo append-only en SQLite')
    args = parser.parse_args()
    cfg = AWXReadOnlyConfig(
        base_url=args.awx_url, token_file=args.awx_token_file,
        ca_file=args.awx_ca_file, job_template_id=args.job_template_id,
        inventory_id=args.inventory_id, project_id=args.project_id,
    )
    review = review_incident(
        incident_id=args.incident_id, job_id=args.job_id, db_path=args.db,
        config=cfg,
    )
    if args.record and review['awx_job_verified'] is True:
        try:
            review['record_created'] = record_review(db_path=args.db, review=review)
        except (sqlite3.Error, OSError, ValueError):
            review['record_error'] = 'record_unavailable'
    print(json.dumps(review, ensure_ascii=True, sort_keys=True))
    return 0 if review['awx_job_verified'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
