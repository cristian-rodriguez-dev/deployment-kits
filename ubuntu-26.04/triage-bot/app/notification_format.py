"""Presentation-only notification formatters for Gmail and Telegram.

Reads only already-stored incident metadata and a local verified asset inventory.
No network, DB writes, policy changes or recovery event detection. Escape ALL
untrusted data and constrain Telegram length after HTML escaping.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from html import escape
from urllib.parse import urlsplit

from app.asset_metadata import for_incident

PRIORITY = {
    'critical': ('CRÍTICA', '#991B1B', '#FEE2E2', '🔴'),
    'high': ('ALTA', '#C2410C', '#FFEDD5', '🟠'),
    'medium': ('MEDIA', '#A16207', '#FEF9C3', '🟡'),
    'low': ('BAJA', '#166534', '#DCFCE7', '🟢'),
}
FP = {'likely': 'Probable', 'possible': 'Posible', 'unlikely': 'Poco probable', 'unknown': 'Sin determinar'}
CONFIDENCE = {'low': 'Baja', 'medium': 'Media', 'high': 'Alta'}

# A different concept from priority: the observable event category / lifecycle.
STATUS = {
    'down': ('HOST SIN CONEXIÓN', '#B91C1C', '#FEF2F2', '🔴',
             'Grafana ha activado una alerta de disponibilidad. Puede deberse al equipo, a la red o al servicio de monitorización.'),
    'recovered': ('SERVICIO RECUPERADO', '#166534', '#F0FDF4', '🟢',
                  'La fuente de monitorización ha informado de la recuperación. Comprueba que los indicadores permanecen estables.'),
    'security': ('EVENTO DE SEGURIDAD', '#9A3412', '#FFF7ED', '🛡️',
                 'Wazuh ha registrado un evento que requiere la revisión indicada en este informe.'),
    'resources': ('UMBRAL DE MONITORIZACIÓN', '#A16207', '#FEFCE8', '📊',
                  'Grafana ha activado una alerta sobre un indicador supervisado.'),
    'other': ('INCIDENTE DETECTADO', '#1D4ED8', '#EFF6FF', '🔎',
              'Se ha recibido un evento del sistema de observabilidad.'),
}


def clean(value, max_len=300) -> str:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ''
    text = str(value).replace('\r', ' ').replace('\n', ' ').replace('\t', ' ')
    return ''.join(c for c in text if ord(c) >= 32 and c not in '\u202e\u202d\u202c\u2066\u2067\u2068\u2069')[:max_len].strip()


def multiline(value, max_len=600) -> str:
    text = str(value or '').replace('\r', '')[:max_len]
    return ''.join(c for c in text if c in '\n\t' or ord(c) >= 32)


def safe_url(value: str) -> str:
    value = clean(value, 350)
    if not value or any(c.isspace() for c in value):
        return ''
    try:
        parsed = urlsplit(value)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
            return ''
    except ValueError:
        return ''
    return value


def _local_date(received) -> str:
    stamp = clean(received, 50)
    try:
        parsed = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            return stamp  # Do not invent a time zone for timestamps without offset.
        try:
            from zoneinfo import ZoneInfo
            local = parsed.astimezone(ZoneInfo('Europe/Madrid'))
            return local.strftime('%d/%m/%Y · %H:%M %Z')
        except (ImportError, KeyError, OSError):
            return parsed.astimezone(timezone.utc).strftime('%d/%m/%Y · %H:%M UTC')
    except ValueError:
        return stamp


def _status(source: str, title: str, analysis: dict) -> str:
    """Never infer recovery from AI prose or a vague title.

    Current Grafana webhook accepts firing only. Future recovery feature must
    explicitly set analysis.alert_lifecycle={status:'resolved',source:'grafana'}.
    """
    lifecycle = analysis.get('alert_lifecycle')
    if (source == 'grafana' and isinstance(lifecycle, dict)
            and lifecycle.get('source') == 'grafana'
            and lifecycle.get('status') == 'resolved'):
        return 'recovered'
    if source == 'grafana' and re.search(r'\bhost[\s_-]*down\b', title, flags=re.I):
        return 'down'
    if source == 'wazuh':
        return 'security'
    if source == 'grafana':
        return 'resources'
    return 'other'


def _steps(status: str, source: str, title: str) -> list[str]:
    """Checklists: actions to verify, never claims that an action happened."""
    if status == 'down':
        return [
            'Comprobar si el equipo está encendido y responde a la red.',
            'Verificar el target y la métrica up en Prometheus; revisar Node Exporter si corresponde.',
            'Consultar en Grafana cuándo comenzó la caída y qué servicios resultaron afectados.',
            'Tras restablecerlo, comprobar que la monitorización vuelve a informar disponibilidad.',
        ]
    if status == 'recovered':
        return [
            'Confirmar que el equipo y sus servicios vuelven a responder.',
            'Revisar el target en Prometheus y la estabilidad de las métricas en Grafana.',
            'Comparar con la alerta de caída correspondiente y documentar la causa si se conoce.',
        ]
    if source == 'wazuh' and any(k in title.casefold() for k in ('brute force', 'sshd', 'ssh ')):
        return [
            'Revisar los intentos SSH, sus horarios y su frecuencia en Wazuh.',
            'Comprobar si hubo autenticaciones correctas y qué cuentas estuvieron implicadas.',
            'Contrastar con los registros del equipo antes de aplicar medidas de bloqueo.',
            'Revisar la configuración de acceso SSH y escalar si hay indicios de intrusión.',
        ]
    if source == 'grafana' and any(k in title.casefold() for k in ('cpu', 'ram', 'memory', 'memoria')):
        return [
            'Revisar la evolución de CPU, memoria y carga del host en Grafana.',
            'Identificar procesos o servicios responsables del consumo sostenido.',
            'Contrastar el umbral, la duración y si afecta a otros equipos.',
        ]
    if source == 'grafana' and any(k in title.casefold() for k in ('disk', 'disco', 'filesystem', 'storage')):
        return [
            'Verificar el espacio disponible y el filesystem afectado.',
            'Identificar el crecimiento de datos o logs antes de limpiar archivos.',
            'Comprobar que el umbral vuelve a estar dentro del rango esperado.',
        ]
    return [
        'Identificar el equipo, el origen y el instante del evento.',
        'Revisar la alerta y sus indicadores asociados en la herramienta de origen.',
        'Confirmar el impacto antes de aplicar cambios o escalar el incidente.',
    ]



def _host_aliases(asset: dict, triage: dict) -> list[str]:
    """Only identifiers tied to the asset by stored metadata/inventory.

    Never guess a hostname from an opaque ID or replace arbitrary numbers.
    The literal agent ID and instance are preserved in technical fields.
    """
    name = clean(asset.get('name'), 90)
    if not name:
        return []
    candidates = (
        asset.get('agent_id'),
        asset.get('instance'),
        triage.get('host') if isinstance(triage, dict) else None,
    )
    aliases = set()
    for value in candidates:
        value = clean(value, 120)
        if (value and value.casefold() != name.casefold()
                and value.casefold() not in ('unknown', 'no identificado')
                and not value.casefold().startswith('unknown-')):
            aliases.add(value)
    return sorted(aliases, key=len, reverse=True)


def _replace_host_refs(text: str, name: str, aliases: list[str]) -> str:
    """Readable names for explicit HOST/AGENT labels, not raw event evidence.

    Replace only verified aliases *after* `Host:`, `Host -`, `Equipo=`, etc.
    Avoid replacing generic IDs in rule numbers, timestamps and log snippets.
    """
    if not text or not name or not aliases:
        return text
    ids = '|'.join(re.escape(alias) for alias in aliases)
    pattern = re.compile(
        r'(?P<key>\b(?:host|equipo|servidor|agente)(?:\s+(?:afectado|id))?\s*'
        r'(?:[:=]|[-–—])\s*)(?P<alias>' + ids + r')(?=$|[\s,.!;:)\]])',
        flags=re.IGNORECASE,
    )
    return pattern.sub(lambda m: m.group('key') + name, text)


def _related_alerts(analysis: dict) -> dict | None:
    """Display bot-local associations, never imply causality or broad coverage."""
    info = analysis.get('correlation')
    if not isinstance(info, dict) or info.get('version') != 'bot-local-v1':
        return None
    if info.get('method') != 'exact_normalized_host' or info.get('scope') != 'incidents_received_by_bot_only':
        return None
    total = info.get('same_host_total')
    if not isinstance(total, int) or isinstance(total, bool) or not 1 <= total <= 250:
        return None
    by_source = info.get('by_source')
    if not isinstance(by_source, dict):
        return None
    wazuh = by_source.get('wazuh')
    grafana = by_source.get('grafana')
    if (not isinstance(wazuh, int) or isinstance(wazuh, bool) or wazuh < 0
            or not isinstance(grafana, int) or isinstance(grafana, bool) or grafana < 0
            or wazuh + grafana > total):
        return None
    window = info.get('window_minutes')
    if not isinstance(window, int) or not 1 <= window <= 60:
        return None
    return {'total': total, 'grafana': grafana, 'wazuh': wazuh,
            'window_minutes': window,
            'truncated': info.get('truncated') is True}

def _observed_telemetry(analysis: dict) -> dict | None:
    """Display only readings attributed to a single, verified Prometheus target.

    These are snapshots from incident ingestion, NOT live state at email-open time.
    """
    t = analysis.get('telemetry')
    if not isinstance(t, dict) or (t.get('version') != 'prometheus-readonly-v1'
                                    or t.get('status') != 'ok'
                                    or t.get('scope') != 'verified_exact_target'):
        return None
    availability = t.get('availability')
    if not isinstance(availability, dict) or availability.get('state') not in ('up', 'down'):
        return None
    state = availability['state']
    metrics = t.get('metrics') if isinstance(t.get('metrics'), dict) else {}
    out = []
    for key, label in (('cpu', 'CPU'), ('ram', 'RAM'), ('disk_root', 'Disco raíz')):
        item = metrics.get(key)
        if not isinstance(item, dict):
            continue
        number = item.get('value_percent')
        age = item.get('age_seconds')
        reading_type = item.get('reading_type')
        if (type(number) not in (float, int) or not 0 <= number <= 100
                or type(age) is not int or not 0 <= age <= 900
                or reading_type not in ('recent', 'historical_or_stale')):
            continue
        out.append({
            'label': label,
            'value': f'{number:.1f}'.replace('.', ',') + ' %',
            'age': age,
            'historical': state == 'down' or reading_type != 'recent',
        })
    return {
        'state': state,
        'state_label': ('Recolección disponible' if state == 'up'
                        else 'Fallo de recopilación'),
        'checked_at': _local_date(t.get('checked_at_utc')) or 'Sin fecha',
        'metrics': out,
    }


def _observed_logs(analysis: dict, asset: dict) -> dict | None:
    """Show only aggregate Loki counts for the same verified asset.

    No original journal lines are rendered or stored by this formatter.
    """
    l = analysis.get('logs_context')
    if (not isinstance(l, dict) or l.get('version') != 'loki-aggregate-readonly-v1'
            or l.get('status') not in ('ok', 'no_logs')
            or l.get('scope') != 'exact_host_department'
            or l.get('log_lines_stored') is not False):
        return None
    sel = l.get('selector')
    if not isinstance(sel, dict) or not isinstance(asset, dict):
        return None
    if (not asset.get('name') or not asset.get('department')
            or sel.get('host') != asset.get('name')
            or sel.get('departamento') != asset.get('department')):
        return None
    if 'inventario' in sel and sel['inventario'] != asset.get('job'):
        return None
    n = l.get('observed_entries_15m')
    groups = l.get('by_unit_source')
    if type(n) is not int or not 0 <= n <= 100_000 or not isinstance(groups, list) or len(groups) > 25:
        return None
    safe, summed = [], 0
    for group in groups:
        if not isinstance(group, dict) or type(group.get('entries')) is not int:
            return None
        count = group['entries']
        if not 0 <= count <= 100_000:
            return None
        summed += count
        unit = clean(group.get('unit'), 65) or 'sin_unidad'
        source = clean(group.get('source'), 40) or 'no_disponible'
        safe.append({'service': unit, 'source': source, 'count': count})
    if summed != n or (l.get('status') == 'no_logs' and n != 0):
        return None
    return {
        'count': n,
        'window': 15,
        'checked_at': _local_date(l.get('checked_at_utc')) or 'Sin fecha',
        'groups': sorted(safe, key=lambda x: -x['count'])[:4],
        'sent_to_ai_aggregates': l.get('aggregates_sent_to_ai') is True,
    }



def _observed_timeline(analysis: dict, asset: dict) -> dict | None:
    """Render three validated, non-overlapping 5m windows for the exact host.

    Never render raw Loki journal text or untrusted service names. This module
    runs in the notification workers even when the Gemini contextual call fails.
    """
    from app.contextual_analysis import sanitized_loki_timeline
    timeline = analysis.get('logs_timeline')
    facts = sanitized_loki_timeline(timeline, asset)
    if facts is None:
        return None
    counts = facts['window_counts_chronological']
    return {
        'counts': counts,
        'total': sum(counts),
        'labels': ['−15 a −10 min', '−10 a −5 min', '−5 a 0 min'],
        'anchor_type': facts['anchor_type'],
        'anchor': _local_date(timeline.get('anchor_utc')) or 'Sin fecha',
        'uses_ai': bool(analysis.get('telemetry_context', {}).get('loki_timeline_used'))
            if isinstance(analysis.get('telemetry_context'), dict) else False,
    }

def _observed_wazuh(analysis: dict, asset: dict) -> dict | None:
    from app.wazuh_enrichment import sanitized_facts
    w = analysis.get('wazuh_context')
    facts = sanitized_facts(w, asset)
    if facts is None:
        return None
    return {
        'rule_level': facts['rule_level'],
        'rule_categories': facts['rule_categories'][:6],
        'mitre_ids': facts['mitre_technique_ids'][:6],
        'count': facts['bot_incidents_same_host_rule_30m'],
        'window_minutes': 30,
        'used_in_ai': w.get('sent_to_ai') is True,
    }


def _diagnostic_context(analysis: dict) -> dict | None:
    """Separate bounded advisory text, never a source of alert state/priority."""
    c = analysis.get('telemetry_context')
    if (not isinstance(c, dict) or c.get('type') != 'advisory_only'
            or c.get('version') not in ('gemini-prometheus-context-v1', 'gemini-observability-context-v2')
            or c.get('changes_triage') is not False):
        return None
    summary = multiline(c.get('summary'), 360).strip()
    reading = multiline(c.get('technical_reading'), 550).strip()
    checks = c.get('recommended_checks')
    if not summary or not reading or not isinstance(checks, list):
        return None
    safe_checks = [multiline(i, 200).strip() for i in checks[:3] if isinstance(i, str)]
    return {
        'summary': summary,
        'reading': reading,
        'checks': [i for i in safe_checks if i],
        'confidence': CONFIDENCE.get(c.get('confidence'), 'Sin determinar'),
        'uses_loki': c.get('loki_aggregates_used') is True,
    }


def _notification_recurrence(triage: dict) -> dict | None:
    """Verified bot-local 30-minute recurrence, informative only.

    The count is of previous received incidents, not all Wazuh/SSH events;
    it is scoped to the same source, host and rule. No severity or send change.
    """
    if (triage.get('policy_version') != 'triage-v1'
            or triage.get('decision') != 'notify'
            or triage.get('notify') is not True):
        return None
    previous = triage.get('recent_same_rule_host_30m')
    if type(previous) is not int or not 0 <= previous <= 100_000:
        return None
    if not previous:
        return None
    return {'total': previous + 1, 'window_minutes': 30,
            'manual_review': previous >= 2}


def details(row: tuple, dashboard_url: str) -> dict:
    """row: id,received_at,source,title,severity,synthetic,analysis_mode,analysis"""
    incident_id, received, source, title, severity, _synthetic, mode, raw = row
    try:
        analysis = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, TypeError):
        analysis = {}
    analysis = analysis if isinstance(analysis, dict) else {}
    triage = analysis.get('triage')
    triage = triage if isinstance(triage, dict) else {}
    source_code = str(source).lower()
    asset = for_incident(source_code, analysis)
    name = clean(asset.get('name'), 90)
    aliases = _host_aliases(asset, triage)
    readable = lambda text: _replace_host_refs(text, name, aliases)
    evidence = analysis.get('evidence', [])
    if isinstance(evidence, str):
        evidence = [evidence]
    if not isinstance(evidence, list):
        evidence = []
    priority = str(analysis.get('priority', '')).lower()
    if priority not in PRIORITY:
        priority = 'medium'
    status = _status(source_code, clean(title, 200), analysis)
    return {
        'id': incident_id,
        'date': _local_date(received),
        'title': readable(clean(title, 180)),
        'source': {'wazuh': 'Wazuh', 'grafana': 'Grafana'}.get(source_code, 'Monitorización'),
        'priority': priority,
        'priority_label': PRIORITY[priority][0],
        'priority_color': PRIORITY[priority][1],
        'priority_bg': PRIORITY[priority][2],
        'priority_icon': PRIORITY[priority][3],
        'severity': clean(severity, 25),
        'host': clean(asset.get('name'), 90) or 'No identificado',
        'department': clean(asset.get('department'), 70) or 'Sin asignar',
        'instance': clean(asset.get('instance'), 100),
        'job': clean(asset.get('job'), 80),
        'agent_id': clean(asset.get('agent_id'), 35),
        'rule_id': clean(asset.get('rule_id'), 35),
        'status': status,
        'status_label': STATUS[status][0],
        'status_color': STATUS[status][1],
        'status_bg': STATUS[status][2],
        'status_icon': STATUS[status][3],
        'status_description': STATUS[status][4],
        'steps': _steps(status, source_code, clean(title, 180)),
        'summary': readable(multiline(analysis.get('summary') or 'Sin resumen disponible', 800)),
        'recommendation': readable(multiline(analysis.get('recommendation'), 450)),
        'evidence': [readable(multiline(e, 220)) for e in evidence[:3] if multiline(e, 220).strip()],
        'reason': multiline(triage.get('reason'), 300),
        'fp': FP.get(triage.get('false_positive'), 'Sin determinar'),
        'confidence': CONFIDENCE.get(triage.get('confidence'), 'Sin determinar'),
        'url': safe_url(dashboard_url),
        'mode': clean(mode, 24),
        'related_alerts': _related_alerts(analysis),
        'notification_recurrence': _notification_recurrence(triage),
        'observed_telemetry': _observed_telemetry(analysis),
        'observed_logs': _observed_logs(analysis, asset),
        'observed_timeline': _observed_timeline(analysis, asset),
        'observed_wazuh': _observed_wazuh(analysis, asset) if source_code == 'wazuh' else None,
        'diagnostic_context': _diagnostic_context(analysis),
    }


def render_email_text(d: dict) -> str:
    parts = [
        f"SECURITY TRIAGE | {d['priority_label']} | Incidente #{d['id']}",
        d['title'], '',
        f"ESTADO: {d['status_label']}", d['status_description'], '',
        f"Equipo afectado: {d['host']}",
        f"Departamento: {d['department']}",
        f"Instancia / IP: {d['instance'] or 'No disponible'}",
        f"Inventario / job: {d['job'] or 'No disponible'}",
        f"Origen: {d['source']}",
        f"Fecha: {d['date']}",
    ]
    if d['agent_id']:
        parts.append('Agente Wazuh: ' + d['agent_id'])
    if d['rule_id']:
        parts.append('Regla Wazuh: ' + d['rule_id'])
    parts += ['', 'ANÁLISIS DEL INCIDENTE (AUTOMATIZADO)', d['summary']]
    if d['evidence']:
        parts += ['', 'SEÑALES DESTACADAS EN EL ANÁLISIS', *('- ' + e for e in d['evidence'])]
    if d.get('related_alerts'):
        c = d['related_alerts']
        parts += ['', 'ACTIVIDAD PREVIA EN EL MISMO EQUIPO',
                  f"{c['total']} incidentes previos en {c['window_minutes']} min "
                  f"(Wazuh: {c['wazuh']}, Grafana: {c['grafana']}).",
                  'Asociación temporal de alertas recibidas por el bot; no demuestra una causa común.']
    recurrence = d.get('notification_recurrence')
    if recurrence:
        parts += ['', 'RECURRENCIA DEL MISMO ORIGEN / EQUIPO / REGLA',
                  f"{recurrence['total']} incidentes recibidos por el bot en "
                  f"{recurrence['window_minutes']} min (incluido este).",
                  'No equivale a intentos individuales ni demuestra un ataque exitoso.']
        if recurrence['manual_review']:
            parts.append('Revisión humana prioritaria recomendada por repetición; sin escalado automático.')
    observed_wazuh = d.get('observed_wazuh')
    if observed_wazuh:
        parts += ['', 'CONTEXTO WAZUH · METADATOS DEL WEBHOOK',
                  f"Nivel de regla: {observed_wazuh['rule_level']}",
                  f"Incidentes recibidos por el bot, mismo equipo/regla en 30 min: {observed_wazuh['count']}"]
        if observed_wazuh['rule_categories']:
            parts.append('Grupos: ' + ', '.join(observed_wazuh['rule_categories']))
        if observed_wazuh['mitre_ids']:
            parts.append('MITRE ATT&CK (etiquetas): ' + ', '.join(observed_wazuh['mitre_ids']))
        parts.append('El estado en vivo del agente no se ha consultado. No son todas las alertas del Indexer.')
    observed = d.get('observed_telemetry')
    if observed:
        parts += ['', 'MÉTRICAS OBSERVADAS POR PROMETHEUS (EN EL INCIDENTE)',
                  f"Recopilación: {observed['state_label']}",
                  f"Consulta: {observed['checked_at']}"]
        parts += [
            f"- {item['label']}: {item['value']}" +
            (' (última lectura histórica)' if item['historical'] else ' (lectura reciente)')
            for item in observed['metrics']
        ]
        if not observed['metrics']:
            parts += ['Sin medidas de CPU, RAM o disco atribuidas a este equipo.']
        parts += ['El estado UP/DOWN se refiere a la recopilación de Prometheus.']
    observed_logs = d.get('observed_logs')
    if observed_logs:
        parts += ['', 'REGISTROS OBSERVADOS POR LOKI (RECUENTOS)',
                  f"Ventana: {observed_logs['window']} min; entradas: {observed_logs['count']}",
                  f"Consulta: {observed_logs['checked_at']}"]
        parts += [f"- {g['service']} ({g['source']}): {g['count']} entradas"
                  for g in observed_logs['groups']]
        parts += ['Los recuentos no indican el contenido, gravedad ni causa de los registros.']
    timeline = d.get('observed_timeline')
    if timeline:
        parts += ['', 'EVOLUCIÓN TEMPORAL DE REGISTROS · LOKI',
                  f"Referencia: {timeline['anchor']} ({'hora del evento' if timeline['anchor_type'] == 'event_time' else 'hora de recepción'})."]
        parts += [f"- {label}: {count} registros"
                  for label, count in zip(timeline['labels'], timeline['counts'])]
        parts += ['Tres ventanas independientes. Volumen observado, sin atribución causal.']
    diagnosis = d.get('diagnostic_context')
    if diagnosis:
        parts += ['', ('DIAGNÓSTICO CONTEXTUAL DE GEMINI (PROMETHEUS + LOKI)'
                       if diagnosis.get('uses_loki') else
                       'DIAGNÓSTICO CONTEXTUAL DE GEMINI (INTERPRETACIÓN)'),
                  diagnosis['summary'], diagnosis['reading']]
        if diagnosis['checks']:
            parts += ['Comprobaciones adicionales:'] + [f'- {item}' for item in diagnosis['checks']]
        parts += [f"Confianza del diagnóstico: {diagnosis['confidence']}"]
    parts += ['', 'PASOS DE COMPROBACIÓN', *('- ' + step for step in d['steps'])]
    if d['recommendation']:
        parts += ['', 'SUGERENCIA ADICIONAL DEL ANÁLISIS', d['recommendation']]
    parts += ['', 'VALORACIÓN DE SMART TRIAGE',
              f"Posible falso positivo: {d['fp']}",
              f"Confianza: {d['confidence']}"]
    if d['url']:
        parts += ['', 'Consultar incidente: ' + d['url']]
    return '\n'.join(parts) + '\n'


def render_email_html(d: dict) -> str:
    """Simple table-based email and inline styles for Gmail/mobile clients."""
    h = lambda x: escape(str(x), quote=True)
    _, fg, bg, _ = PRIORITY[d['priority']]
    sf, sb = d['status_color'], d['status_bg']

    def para(value: str) -> str:
        return h(value).replace('\n', '<br>')

    def cell(label: str, value: str) -> str:
        val = value or 'No disponible'
        missing = not value
        return (
            '<td width="50%" valign="top" style="padding:12px 14px;'
            'border:1px solid #E2E8F0;background:#F8FAFC;border-radius:8px">'
            f'<div style="font-size:10px;font-weight:700;letter-spacing:.6px;color:#64748B">{h(label.upper())}</div>'
            f'<div style="font-size:14px;font-weight:{"400" if missing else "700"};'
            f'color:{"#94A3B8" if missing else "#17243A"};margin-top:6px;'
            f'word-break:break-word">{h(val)}</div></td>'
        )

    def section(title: str, content: str) -> str:
        return (f'<h2 style="font-size:14px;font-weight:800;color:#17243A;'
                f'margin:24px 0 10px">{h(title)}</h2>{content}')

    metadata = (
        '<table role="presentation" cellpadding="0" cellspacing="7" '
        'style="border-spacing:7px;margin:0 -7px;width:100%">'
        f'<tr>{cell("Equipo afectado", d["host"])}{cell("Departamento", d["department"])}</tr>'
        f'<tr>{cell("Instancia / IP", d["instance"])}{cell("Inventario / Job", d["job"])}</tr>'
        f'<tr>{cell("Origen", d["source"])}{cell("Fecha", d["date"])}</tr>'
        '</table>'
    )
    technical = []
    if d['agent_id']:
        technical.append(f'<b>Agente Wazuh:</b> {h(d["agent_id"])}')
    if d['rule_id']:
        technical.append(f'<b>Regla:</b> {h(d["rule_id"])}')
    tech_html = ('<div style="font-size:12px;color:#64748B;margin:10px 0">'
                 + ' &nbsp; · &nbsp; '.join(technical) + '</div>') if technical else ''
    status_html = (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="background:{sb};border:1px solid {sf};border-radius:10px;margin:15px 0 18px">'
        f'<tr><td style="padding:15px 18px">'
        f'<div style="font-size:15px;font-weight:800;color:{sf}">'
        f'{h(d["status_icon"])} &nbsp; {h(d["status_label"])}</div>'
        f'<div style="color:#334155;font-size:13px;line-height:20px;margin-top:7px">'
        f'{h(d["status_description"])}</div></td></tr></table>'
    )
    signals = ''
    if d['evidence']:
        items = ''.join(f'<li style="margin:5px 0">{para(e)}</li>' for e in d['evidence'])
        signals = section('SEÑALES DESTACADAS DEL ANÁLISIS',
                          '<ul style="padding-left:21px;margin:0;color:#334155;'
                          f'font-size:13px;line-height:21px">{items}</ul>')
    actions = ''.join(
        f'<tr><td valign="top" width="25" style="padding:6px 0;color:#2563EB;'
        f'font-weight:800;font-size:13px">{i}.</td><td style="padding:6px 0;'
        f'font-size:13px;line-height:21px;color:#334155">{h(step)}</td></tr>'
        for i, step in enumerate(d['steps'], 1)
    )
    related = d.get('related_alerts')
    related_html = ''
    if related:
        related_html = section('ACTIVIDAD PREVIA DEL MISMO EQUIPO',
            '<div style="background:#F0F9FF;border:1px solid #BAE6FD;'
            'border-radius:8px;padding:12px 14px;color:#0C4A6E;'
            'font-size:13px;line-height:20px">'
            f'<b>{related["total"]} incidentes anteriores en {related["window_minutes"]} min</b>'
            f' &nbsp;·&nbsp; Wazuh: {related["wazuh"]}'
            f' &nbsp;·&nbsp; Grafana: {related["grafana"]}'
            '<div style="font-size:11px;margin-top:6px;color:#475569">'
            'Asociación temporal de incidentes recibidos por el bot; no confirma una causa común.'
            '</div></div>')
    recurrence = d.get('notification_recurrence')
    recurrence_html = ''
    if recurrence:
        review = ('<div style="margin-top:5px"><b>Revisión humana prioritaria recomendada por repetición; '
                  'sin escalado automático.</b></div>') if recurrence['manual_review'] else ''
        recurrence_html = section('RECURRENCIA DE LA MISMA FUENTE / EQUIPO / REGLA',
            '<div style="border:1px solid #CBD5E1;background:#F8FAFC;'
            'padding:12px;border-radius:8px;color:#334155;font-size:12px;line-height:20px">'
            f"{h(recurrence['total'])} incidentes recibidos por el bot en "
            f"{h(recurrence['window_minutes'])} min (incluido este)."
            '<div style="font-size:11px;margin-top:5px">'
            'Recuento del bot, no intentos de acceso ni confirmación de ataque.</div>'
            + review + '</div>')
    observed_wazuh = d.get('observed_wazuh')
    wazuh_html = ''
    if observed_wazuh:
        wazuh_html = section('CONTEXTO DE SEGURIDAD · WAZUH',
            '<div style="border:1px solid #FED7AA;background:#FFF7ED;'
            'padding:12px;border-radius:8px;color:#7C2D12;font-size:12px;line-height:21px">'
            '<b>Regla: nivel ' + h(observed_wazuh['rule_level']) + '</b>'
            '<div>Incidentes del mismo equipo/regla recibidos por el bot (30 min): ' + h(observed_wazuh['count']) + '</div>'
            + ('<div>Grupos: ' + h(', '.join(observed_wazuh['rule_categories'])) + '</div>'
               if observed_wazuh['rule_categories'] else '')
            + ('<div>MITRE ATT&amp;CK: ' + h(', '.join(observed_wazuh['mitre_ids'])) + '</div>'
               if observed_wazuh['mitre_ids'] else '')
            + '<div style="font-size:11px;color:#9A3412;margin-top:6px">'
            'Solo incidentes recibidos por este bot; agente en vivo e Indexer no consultados.'
            '</div></div>')
    observed = d.get('observed_telemetry')
    observed_html = ''
    if observed:
        rows = ''.join(
            '<tr><td style="padding:7px 9px;border-top:1px solid #E2E8F0">'
            + h(item['label']) + '</td><td align="right" '
            'style="padding:7px 9px;border-top:1px solid #E2E8F0;font-weight:700">'
            + h(item['value']) + (' · histórica' if item['historical'] else ' · reciente')
            + '</td></tr>' for item in observed['metrics']
        ) or ('<tr><td colspan="2" style="padding:8px">'
              'No hay medidas de CPU, RAM o disco disponibles.</td></tr>')
        observed_html = section('MÉTRICAS OBSERVADAS · PROMETHEUS',
            '<div style="border:1px solid #BAE6FD;border-radius:8px;background:#F0F9FF;'
            'padding:12px;color:#0C4A6E;font-size:12px;line-height:20px">'
            '<b>Estado de recopilación: ' + h(observed['state_label']) + '</b>'
            '<div>Consulta al registrar el incidente: ' + h(observed['checked_at']) + '</div>'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"'
            ' style="color:#0C4A6E;font-size:12px;margin-top:9px">'
            + rows + '</table>'
            '<div style="margin-top:8px;font-size:11px">'
            'UP/DOWN describe la recopilación de Prometheus, no confirma si el equipo está apagado.'
            '</div></div>')
    observed_logs = d.get('observed_logs')
    logs_html = ''
    if observed_logs:
        log_groups = ''.join(
            '<tr><td style="padding:6px 8px;border-top:1px solid #E2E8F0">'
            + h(g['service']) + ' · ' + h(g['source'])
            + '</td><td align="right" style="padding:6px 8px;border-top:1px solid #E2E8F0">'
            + h(g['count']) + '</td></tr>'
            for g in observed_logs['groups']
        )
        logs_html = section('ACTIVIDAD REGISTRADA · LOKI',
            '<div style="background:#F8FAFC;border:1px solid #CBD5E1;border-radius:8px;'
            'padding:12px 14px;color:#334155;font-size:12px;line-height:20px">'
            '<b>' + h(observed_logs['count']) + ' entradas en '
            + h(observed_logs['window']) + ' minutos</b>'
            '<div style="color:#64748B">Consulta: ' + h(observed_logs['checked_at']) + '</div>'
            '<table role="presentation" width="100%" style="margin-top:7px;font-size:12px">'
            + log_groups + '</table>'
            '<div style="font-size:11px;color:#64748B;margin-top:7px">'
            'Recuento de entradas; no confirma fallos, intrusión ni causalidad.'
            '</div></div>')
    timeline = d.get('observed_timeline')
    timeline_html = ''
    if timeline:
        max_count = max(timeline['counts']) if any(timeline['counts']) else 1
        timeline_rows = ''.join(
            '<tr><td style="width:112px;padding:7px 5px;color:#334155;font-size:12px">'
            + h(label) + '</td><td style="padding:7px 5px;min-width:120px">'
            '<div style="height:12px;background:#E2E8F0;border-radius:5px">'
            '<div style="height:12px;border-radius:5px;background:#0D9488;width:'
            + str(int(count * 100 / max_count)) + '%"></div></div></td>'
            '<td align="right" style="width:35px;font-size:12px;padding:7px 5px;font-weight:700">'
            + h(count) + '</td></tr>'
            for label, count in zip(timeline['labels'], timeline['counts'])
        )
        reference = 'hora del evento' if timeline['anchor_type'] == 'event_time' else 'hora de recepción'
        timeline_html = section('EVOLUCIÓN TEMPORAL · LOKI',
            '<div style="border:1px solid #99F6E4;background:#F0FDFA;'
            'padding:12px;border-radius:8px;color:#115E59">'
            '<div style="font-size:12px;font-weight:700">'
            + h(timeline['total']) + ' registros en tres ventanas de cinco minutos</div>'
            '<div style="font-size:11px;margin:5px 0 8px">'
            'Referencia: ' + h(timeline['anchor']) + ' · ' + h(reference) + '</div>'
            '<table role="presentation" width="100%" cellspacing="0" style="width:100%">'
            + timeline_rows + '</table>'
            '<div style="font-size:11px;margin-top:7px;color:#475569">'
            'Solo volumen de registros observados; no demuestra fallos ni causalidad.'
            '</div></div>')
    diagnosis = d.get('diagnostic_context')
    diagnostic_html = ''
    if diagnosis:
        check_html = ''.join('<li style="margin:3px 0">' + para(item) + '</li>'
                             for item in diagnosis['checks'])
        diagnostic_html = section(('DIAGNÓSTICO CONTEXTUAL · GEMINI / PROMETHEUS + LOKI'
                                   if diagnosis.get('uses_loki') else
                                   'DIAGNÓSTICO CONTEXTUAL · GEMINI'),
            '<div style="border-left:3px solid #6366F1;background:#EEF2FF;'
            'padding:12px 14px;color:#312E81;font-size:12px;line-height:21px">'
            '<div style="font-weight:700">' + para(diagnosis['summary']) + '</div>'
            '<div style="margin-top:7px">' + para(diagnosis['reading']) + '</div>'
            + ('<ul style="margin:9px 0 0;padding-left:18px">' + check_html + '</ul>'
               if check_html else '')
            + '<div style="margin-top:8px;font-size:11px;color:#4338CA">'
            'Confianza del diagnóstico: ' + h(diagnosis['confidence']) + '</div></div>')
    actions_html = section('PASOS DE COMPROBACIÓN',
                           f'<table role="presentation" cellpadding="0" cellspacing="0">{actions}</table>')
    llm_recommend = section('SUGERENCIA ADICIONAL DEL ANÁLISIS',
        '<div style="font-size:13px;line-height:21px;color:#334155;'
        'padding:11px 13px;background:#EFF6FF;border-left:3px solid #2563EB">'
        + para(d['recommendation']) + '</div>') if d['recommendation'] else ''
    llm_analysis = section('ANÁLISIS DEL INCIDENTE',
        '<div style="font-size:13px;line-height:22px;color:#334155">'
        + para(d['summary']) + '</div>')
    ai_eval = section('VALORACIÓN DEL ANÁLISIS AUTOMATIZADO',
        '<div style="border:1px solid #C7D2FE;border-radius:8px;background:#EEF2FF;'
        'padding:13px 15px;color:#3730A3;font-size:12px;line-height:21px">'
        f'Posible falso positivo: <b>{h(d["fp"])}</b> &nbsp;·&nbsp; '
        f'Confianza: <b>{h(d["confidence"])}</b></div>')
    link_html = (f'<div style="margin-top:24px"><a href="{h(d["url"])}" '
                 'style="background:#2563EB;color:#FFFFFF;text-decoration:none;'
                 'font-weight:700;font-size:13px;padding:13px 18px;border-radius:8px;'
                 'display:inline-block">Consultar incidente en el dashboard</a></div>') if d['url'] else ''
    return f'''<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:20px 10px;background:#F1F5F9;font-family:Arial,Helvetica,sans-serif;color:#17243A">
<table role="presentation" cellpadding="0" cellspacing="0" width="100%"><tr><td align="center">
<table role="presentation" cellpadding="0" cellspacing="0" width="600" style="width:100%;max-width:600px;background:#FFFFFF;border-radius:12px;border:1px solid #E2E8F0">
<tr><td style="padding:24px 27px;background:#17243A;color:#FFFFFF;border-radius:12px 12px 0 0">
<div style="font-size:19px;font-weight:800;letter-spacing:1px">◈ SECURITY TRIAGE</div>
<div style="font-size:11px;letter-spacing:1.2px;color:#CBD5E1;margin-top:6px">INFORME DE INCIDENTE · OBSERVABILIDAD Y SEGURIDAD</div>
</td></tr>
<tr><td style="padding:24px 27px">
<table role="presentation" cellpadding="0" cellspacing="0" width="100%"><tr><td valign="middle">
<div style="font-size:11px;font-weight:700;color:#64748B">INCIDENTE #{h(d['id'])}</div>
<h1 style="font-size:22px;line-height:28px;margin:7px 0;color:#17243A">{h(d['title'])}</h1>
</td><td align="right" valign="top" style="width:115px">
<span style="color:{fg};background:{bg};font-size:12px;display:inline-block;padding:9px 10px;
font-weight:800;border-radius:7px;white-space:nowrap">{h(d['priority_label'])}</span>
</td></tr></table>
<div style="height:3px;background:{fg};border-radius:3px;margin:12px 0 17px"></div>
{status_html}
{metadata}{tech_html}
{llm_analysis}{signals}{related_html}{recurrence_html}{wazuh_html}{observed_html}{logs_html}{timeline_html}{diagnostic_html}{actions_html}{llm_recommend}{ai_eval}{link_html}
</td></tr>
<tr><td style="background:#F8FAFC;color:#64748B;font-size:11px;line-height:19px;
text-align:center;padding:16px 23px;border-top:1px solid #E2E8F0">
Security Triage · Notificación automatizada · Laboratorio de observabilidad
</td></tr></table></td></tr></table></body></html>'''


def _tg(value: str, limit: int = 260) -> str:
    """Bound HTML-escaped content, not the raw input text."""
    out, total = [], 0
    for char in str(value):
        item = escape(char, quote=False)
        if total + len(item) > limit:
            break
        out.append(item)
        total += len(item)
    return ''.join(out)


def render_telegram_html(d: dict) -> str:
    p = [
        '<b>🛡 SECURITY TRIAGE</b>',
        f"{d['priority_icon']} <b>PRIORIDAD {d['priority_label']}</b> · Incidente #{d['id']}",
        f"<b>{_tg(d['title'], 190)}</b>",
        '',
        f"{d['status_icon']} <b>{_tg(d['status_label'], 65)}</b>",
        _tg(d['status_description'], 210),
        '',
        f"🖥 <b>Equipo:</b> {_tg(d['host'], 90)}",
        f"🏢 <b>Departamento:</b> {_tg(d['department'], 70)}",
        f"🌐 <b>Instancia / IP:</b> {_tg(d['instance'] or 'No disponible', 95)}",
        f"🗂 <b>Inventario / job:</b> {_tg(d['job'] or 'No disponible', 90)}",
        f"📡 <b>Origen:</b> {_tg(d['source'], 40)}",
        f"🕒 <b>Fecha:</b> {_tg(d['date'], 45)}",
    ]
    if d['agent_id']:
        p.append(f"🔎 <b>Agente:</b> {_tg(d['agent_id'], 40)}")
    if d['rule_id']:
        p.append(f"📋 <b>Regla:</b> {_tg(d['rule_id'], 40)}")
    p.extend(['', '🧠 <b>ANÁLISIS DEL INCIDENTE</b>', _tg(d['summary'], 720)])
    if d['evidence']:
        p.extend(['', '🔍 <b>SEÑALES DESTACADAS</b>'])
        p.extend('• ' + _tg(e, 155) for e in d['evidence'][:3])
    if d.get('related_alerts'):
        c = d['related_alerts']
        p.extend(['', '🔗 <b>ACTIVIDAD PREVIA DEL MISMO EQUIPO</b>',
                  f"{c['total']} incidentes en {c['window_minutes']} min "
                  f"(Wazuh {c['wazuh']} · Grafana {c['grafana']})",
                  'Relación temporal, sin atribuir causa.'])
    extra_recurrence = []
    recurrence = d.get('notification_recurrence')
    if recurrence:
        extra_recurrence = ['', '🔁 <b>RECURRENCIA DEL MISMO EQUIPO/REGLA</b>',
            f"{recurrence['total']} incidentes recibidos por el bot en "
            f"{recurrence['window_minutes']} min (incluido este).",
            'No indica ataques exitosos ni todos los eventos de Wazuh.']
        if recurrence['manual_review']:
            extra_recurrence.append('⚠️ Revisión humana prioritaria recomendada; sin escalado automático.')
    # Optional addenda are inserted only when the full message fits the Telegram
    # HTML budget. Core incident identity, actions and dashboard always win.
    extra_wazuh = []
    observed_wazuh = d.get('observed_wazuh')
    if observed_wazuh:
        extra_wazuh = ['', '🛡 <b>METADATOS DE WAZUH</b>',
            f"Nivel de regla: {observed_wazuh['rule_level']}",
            f"Incidentes mismo equipo/regla (bot, 30 min): {observed_wazuh['count']}"]
        if observed_wazuh['mitre_ids']:
            extra_wazuh.append('MITRE: ' + _tg(', '.join(observed_wazuh['mitre_ids']), 75))
        extra_wazuh.append('Estado del agente e Indexer no consultados.')
    extra_observed = []
    observed = d.get('observed_telemetry')
    if observed:
        extra_observed = ['', '📊 <b>MÉTRICAS PROMETHEUS</b>',
                          'Recopilación: ' + _tg(observed['state_label'], 55)]
        if observed['metrics']:
            extra_observed += [
                f"• {item['label']}: {item['value']}" +
                (' (histórica)' if item['historical'] else ' (reciente)')
                for item in observed['metrics']
            ]
        else:
            extra_observed.append('Sin métricas recientes disponibles.')
        extra_observed.append('UP/DOWN = estado de recopilación, no de encendido.')
    extra_logs = []
    observed_logs = d.get('observed_logs')
    if observed_logs:
        extra_logs = ['', '📜 <b>ACTIVIDAD LOKI (RECUENTOS)</b>',
                      f"{observed_logs['count']} entradas en {observed_logs['window']} min"]
        extra_logs.extend('• ' + _tg(g['service'], 55) + ': ' + str(g['count'])
                          for g in observed_logs['groups'][:3])
        extra_logs.append('Cantidad de logs ≠ evidencia de fallo o ataque.')
    extra_timeline = []
    timeline = d.get('observed_timeline')
    if timeline:
        extra_timeline = ['', '📈 <b>EVOLUCIÓN DE REGISTROS · LOKI</b>']
        extra_timeline.extend(f"• {label}: {count} logs"
                              for label, count in zip(timeline['labels'], timeline['counts']))
        extra_timeline.append('Tres ventanas de 5 min; no demuestra la causa.')
    extra_diagnostic = []
    diagnosis = d.get('diagnostic_context')
    if diagnosis:
        extra_diagnostic = ['', ('🧠 <b>DIAGNÓSTICO · PROMETHEUS + LOKI</b>'
                                 if diagnosis.get('uses_loki') else
                                 '🧠 <b>DIAGNÓSTICO CONTEXTUAL</b>'),
                            _tg(diagnosis['summary'], 215),
                            _tg(diagnosis['reading'], 245)]
        extra_diagnostic += [f"• {_tg(item, 120)}" for item in diagnosis['checks'][:2]]
    p.extend(['', '🛠 <b>PASOS DE COMPROBACIÓN</b>'])
    p.extend(f"{i}. {_tg(step, 178)}" for i, step in enumerate(d['steps'][:4], 1))
    if d['recommendation']:
        p.extend(['', '💡 <b>SUGERENCIA ADICIONAL</b>', _tg(d['recommendation'], 310)])
    p.extend(['', '🧠 <b>VALORACIÓN AUTOMATIZADA</b>',
              f"Posible falso positivo: <b>{_tg(d['fp'], 36)}</b> · Confianza: <b>{_tg(d['confidence'], 36)}</b>"])
    if d['url']:
        p.extend(['', f"🔗 <a href=\"{escape(d['url'], quote=True)}\">Consultar incidente</a>"])
    insertion = next((i for i, line in enumerate(p)
                      if '🛠 <b>PASOS DE COMPROBACIÓN</b>' in line), len(p))
    for block in (extra_recurrence, extra_wazuh, extra_observed, extra_logs, extra_timeline, extra_diagnostic):
        if block and len('\n'.join(p[:insertion] + block + p[insertion:])) <= 4000:
            p[insertion:insertion] = block
            insertion += len(block)
    result = '\n'.join(p)
    if len(result) > 4096:
        raise ValueError('Telegram text exceeds safe formatting budget')
    return result
