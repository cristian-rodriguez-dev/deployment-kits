"""Bloque 19I: ficha consultiva Alloy para la vista existente de incidentes.

NO confiere identidad ni procedencia a un webhook. NO es una observación
systemd, NO ejecuta AWX, NO escribe SQLite y NO altera decisiones de triaje.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

VERSION = 'alloy-operator-guidance-v1'
SERVICE = 'alloy.service'
AUDIT_TEMPLATE = '19H - Alloy Host - AUDIT'
RECOVERY_WORKFLOW = '19H - Recuperacion Alloy - MANUAL'
MAX_CURRENT_CONTEXT = timedelta(minutes=15)

# Solo indicios textuales, no observaciones verificadas del servicio.
_ALLOY = re.compile(r'(?<![a-z0-9])alloy(?:\.service)?(?![a-z0-9])', re.IGNORECASE)
_NEGATIVE = re.compile(
    r'(?<![a-z0-9])(?:inactive|failed|down|stopped|unavailable|'
    r'inactivo|inactiva|detenido|detenida|ca[ií]do|ca[ií]da|'
    r'no\s+disponible|no\s+arranca|sin\s+datos)(?![a-z0-9])',
    re.IGNORECASE,
)


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not 1 <= len(value) <= 48:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None


def guidance_for_incident(incident: Mapping[str, Any] | None,
                          *, now: datetime | None = None) -> dict | None:
    """Devuelve runbook manual si hay indicio de Alloy y procedencia incierta.

    Un título o etiqueta de webhook NO demuestra que Alloy esté inactivo.
    Nunca se emite `ready_to_apply` ni un comando ejecutable.
    """
    if not isinstance(incident, dict):
        return None
    ident = incident.get('id')
    if (type(ident) is not int or not 0 < ident <= 2_147_483_647
            or incident.get('source') not in ('grafana', 'wazuh')
            or incident.get('synthetic') is not False):
        return None
    title = incident.get('title')
    if (type(title) is not str or not 5 <= len(title) <= 300
            or not _ALLOY.search(title) or not _NEGATIVE.search(title)):
        return None
    current = datetime.now(timezone.utc) if now is None else now
    if not isinstance(current, datetime) or current.tzinfo is None:
        return None
    current = current.astimezone(timezone.utc)
    observed = _timestamp(incident.get('received_at'))
    recent = bool(observed and timedelta(0) <= current - observed <= MAX_CURRENT_CONTEXT)
    return {
        'version': VERSION,
        'incident_id': ident,
        'component': 'alloy_host',
        'service': SERVICE,
        'status': 'review_required',
        'reason_code': ('unverified_recent_alloy_signal' if recent
                        else 'unverified_or_historical_alloy_signal'),
        'signal_origin': 'stored_incident_title_claim',
        'signal_verified': False,
        'service_state': 'unknown',
        'independent_systemd_observation': False,
        'recent_incident': recent,
        'evidence': [
            'El titulo del incidente menciona Alloy y un posible problema.',
            'El aviso almacenado no acredita el estado actual del servicio.',
            'No se dispone de una observacion systemd autenticada en esta ficha.',
        ],
        'audit_job_template': AUDIT_TEMPLATE,
        'recovery_workflow': RECOVERY_WORKFLOW,
        'steps': [
            'Ejecutar manualmente 19H - Alloy Host - AUDIT en AWX.',
            'Si devuelve no_action (active), cerrar sin recuperar.',
            'Si devuelve failed o comprobaciones invalidas, investigar; no iniciar.',
            'Solo si indica inactive y precondiciones validas, decidir si fue una parada intencionada.',
            'Si procede, iniciar el workflow manual de recuperacion y aprobar expresamente.',
            'Comprobar despues Alloy y, por separado, la ingesta de logs.',
        ],
        'requires_human_review': True,
        'requires_human_approval_for_recovery': True,
        'execution_allowed': False,
        'action_executed': False,
        'awx_verified': False,
        'incident_to_service_proven': False,
        'automated_recovery_available': False,
    }
