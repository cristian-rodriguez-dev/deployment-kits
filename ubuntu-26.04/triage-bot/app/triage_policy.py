"""Deterministic notification gate for a small SOC triage lab.

The LLM provides opinions, not proof. Critical input signals are never
silenced by an LLM false-positive label. No network or secret access here.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

PRIORITIES = {'low', 'medium', 'high', 'critical'}
CONFIDENCES = {'low', 'medium', 'high'}
FP_VALUES = {'likely', 'possible', 'unlikely', 'unknown'}
CLASSIFICATIONS = {'benign', 'suspicious', 'incident', 'insufficient_data'}


def hard_critical_source(source: str, severity: str) -> bool:
    """Critical *source* severity, independent of mutable AI priority or title.

    This is deliberately shared with notification workers, so their cooldown
    exemptions use exactly the same threshold as the Smart Triage policy.
    """
    if source == 'grafana':
        return isinstance(severity, str) and severity.lower() == 'critical'
    if source == 'wazuh':
        try:
            return int(severity) >= 12
        except (ValueError, TypeError, OverflowError):
            return False
    return False


def clean_id(value: Any, limit: int = 80) -> str:
    val = str(value or '').strip()[:limit]
    return re.sub(r'[^a-zA-Z0-9_.:/-]', '_', val) or 'unknown'


def event_context(source: str, context: dict | None, fingerprint: str) -> dict:
    context = context if isinstance(context, dict) else {}
    host = clean_id(context.get('host'))
    kind = clean_id(context.get('rule_key'))
    category = clean_id(context.get('category'), 40).lower()
    # Unknown identities should not accidentally correlate unrelated alerts.
    if host == 'unknown':
        host = 'unknown-' + fingerprint[:12]
    if kind == 'unknown':
        kind = 'unknown-' + fingerprint[:12]
    return {'host': host, 'rule_key': kind, 'category': category}


def normalize_ai_fields(analysis: dict) -> None:
    """Untrusted model data must have explicit, bounded enumerated values."""
    classification = str(analysis.get('classification', 'insufficient_data')).lower().strip()
    fp = str(analysis.get('false_positive', 'unknown')).lower().strip()
    confidence = str(analysis.get('confidence', 'low')).lower().strip()
    analysis['classification'] = classification if classification in CLASSIFICATIONS else 'insufficient_data'
    analysis['false_positive'] = fp if fp in FP_VALUES else 'unknown'
    analysis['confidence'] = confidence if confidence in CONFIDENCES else 'low'
    analysis['ai_suggests_notify'] = analysis.get('notify') if type(analysis.get('notify')) is bool else None
    analysis.pop('notify', None)  # final notify decision is policy-controlled, never LLM-controlled
    analysis['reason'] = str(analysis.get('reason') or '')[:400]


def assess(source: str, title: str, severity: str, synthetic: bool, mode: str,
           analysis: dict, context: dict, recent_count: int) -> dict:
    """Return a traceable notification policy, not a prediction of ground truth."""
    normalize_ai_fields(analysis)
    priority = str(analysis.get('priority', 'medium')).lower()
    if priority not in PRIORITIES:
        priority = 'medium'
        analysis['priority'] = priority

    try:
        wazuh_level = int(severity) if source == 'wazuh' else 0
    except (ValueError, TypeError):
        wazuh_level = 0
    severity_lower = str(severity).lower()
    hard_critical = hard_critical_source(source, severity)
    group_src = '|'.join((source, context['host'], context['rule_key']))
    group = hashlib.sha256(group_src.encode('utf-8')).hexdigest()[:24]
    title_lower = title.strip().lower()
    demo = (synthetic or context['category'] in {'demo', 'test', 'lab'}
            or title_lower in {'testalert', 'test alert'}
            or title_lower.startswith(('lab -', 'lab_', 'lab ')))
    fp = analysis['false_positive']
    confidence = analysis['confidence']
    suggestion = analysis['ai_suggests_notify']
    # Ignore an AI downgrade of a hard-critical source event; keep the evidence visible.
    if hard_critical and priority not in {'high', 'critical'}:
        analysis['priority'] = 'high'
        priority = 'high'
    # High source severity cannot be silently downgraded based on an unsubstantiated
    # model guess. Only a high-confidence likely false-positive may suggest review.
    source_high = ((source == 'wazuh' and wazuh_level >= 10)
                   or (source == 'grafana' and severity_lower == 'high'))
    supported_downgrade = (fp == 'likely' and confidence == 'high')
    if source_high and priority in {'low', 'medium'} and not supported_downgrade:
        analysis['priority'] = 'high'
        priority = 'high'

    # Explicit synthetic flag is authoritative. A real source-critical event
    # must never be silenced merely by its title or untrusted category.
    if synthetic:
        decision, why = 'suppress', 'Evento sintético; no enviar avisos automáticos.'
    elif hard_critical:
        decision, why = 'notify', 'Protección por severidad de origen: evento crítico, la IA no puede silenciarlo.'
    elif demo:
        decision, why = 'suppress', 'Evento marcado como prueba/laboratorio; no enviar avisos automáticos.'
    elif priority == 'critical':
        decision, why = 'notify', 'Triaje crítico; se notifica aunque la IA indique posible falso positivo.'
    elif mode != 'gemini':
        if source == 'wazuh' and wazuh_level >= 10:
            decision, why = 'notify', 'Respaldo de seguridad: alerta Wazuh alta sin análisis IA disponible.'
        elif source == 'grafana' and severity_lower == 'high':
            decision, why = 'notify', 'Respaldo de disponibilidad: alerta Grafana alta sin análisis IA.'
        else:
            decision, why = 'review', 'No hay evaluación IA válida; se conserva para revisión.'
    elif fp == 'likely' and confidence in {'medium', 'high'} and priority != 'critical':
        decision, why = 'review', 'Posible falso positivo según IA; requiere revisión humana, sin correo automático.'
    elif priority == 'high' and suggestion is not False:
        decision, why = 'notify', 'Incidente de prioridad alta sin indicios sólidos de falso positivo.'
    elif priority == 'high' and suggestion is False:
        decision, why = 'review', 'La IA propone no notificar; incidente alto retenido para revisión.'
    elif priority == 'medium' and suggestion is True and recent_count >= 2 and fp != 'likely':
        decision, why = 'notify', 'Prioridad media con recurrencia y recomendación IA de notificar.'
    else:
        decision, why = ('review' if fp in {'possible', 'unknown'} else 'suppress',
                         'Evento de baja/media prioridad sin criterios suficientes para notificación.')

    return {
        'policy_version': 'triage-v1',
        'decision': decision,
        'notify': decision == 'notify',
        'reason': why,
        'group_key': group,
        'recent_same_rule_host_30m': recent_count,
        'host': context['host'],
        'rule_key': context['rule_key'],
        'classification': analysis['classification'],
        'false_positive': fp,
        'confidence': confidence,
        'ai_suggests_notify': suggestion,
    }
