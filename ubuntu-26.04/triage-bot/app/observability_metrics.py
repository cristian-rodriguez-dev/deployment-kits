"""Bounded-label Prometheus metrics from the existing SQLite (read-only).

No raw alert/log/identity field is emitted. No new tables or network calls.
Metrics are snapshots computed from durable records, not delivery guarantees.
"""
from __future__ import annotations

import sqlite3
import time
from collections import Counter
from contextlib import closing
from datetime import datetime
from pathlib import Path

SOURCES = frozenset({'wazuh', 'grafana', 'prometheus', 'loki'})
DECISIONS = frozenset({'notify', 'review', 'suppress'})
MODES = frozenset({'gemini', 'rules_only', 'rules_fallback', 'rules_rate_limited'})
DELIVERY_STATES = frozenset({'pending', 'sending', 'sent', 'suppressed', 'failed'})
CONTEXT_STATES = frozenset({'ok', 'unavailable', 'stale', 'no_data', 'no_alerts'})
CONTEXT_PATHS = (
    ('wazuh_webhook', '$.wazuh_context.status'),
    ('wazuh_indexer', '$.wazuh_indexer.status'),
    ('wazuh_agent_monitoring', '$.wazuh_agent_monitoring.status'),
    ('prometheus', '$.telemetry.status'),
    ('loki', '$.logs_context.status'),
    ('loki_timeline', '$.logs_timeline.status'),
    ('ai_context', '$.telemetry_context.status'),
)
CHANNELS = (('smtp', 'mail_deliveries'), ('telegram', 'telegram_deliveries'))


def _label(value, allowed, fallback='other'):
    return value if type(value) is str and value in allowed else fallback


def _line(name, labels, count):
    # Labels originate only from constant vocabularies, never user-supplied text.
    kv = ','.join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    return f'{name}{{{kv}}} {int(count)}' if kv else f'{name} {int(count)}'


def _json_field(path):
    # JSON paths are constants from this module, not request-supplied parameters.
    return "CASE WHEN json_valid(analysis) THEN json_extract(analysis, '" + path + "') END"


def render(db_path: Path, *, now: int | None = None) -> str:
    """Return Prometheus text, reading existing database without altering it."""
    if now is None:
        now = int(time.time())
    if type(now) is not int or not 1_600_000_000 <= now <= 4_000_000_000:
        raise ValueError('Invalid clock')
    if not isinstance(db_path, Path) or not db_path.is_absolute():
        raise ValueError('Expected absolute database path')

    lines = [
        '# HELP security_triage_incidents_total Incidents persisted by source, decision and synthetic flag.',
        '# TYPE security_triage_incidents_total counter',
    ]

    # SQLite URI mode=ro prevents the metrics endpoint creating/updating the DB.
    with closing(sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True, timeout=2)) as c:
        c.execute('PRAGMA busy_timeout=2000')
        incidents = Counter()
        decisions = _json_field('$.triage.decision')
        for source, synthetic, decision, n in c.execute(
            f'SELECT source, synthetic, {decisions}, COUNT(*) '
            'FROM incidents GROUP BY 1,2,3'
        ):
            key = (
                _label(source, SOURCES),
                'true' if synthetic == 1 else 'false' if synthetic == 0 else 'unknown',
                _label(decision, DECISIONS, 'unknown'),
            )
            incidents[key] += n
        for (source, synthetic, decision), count in sorted(incidents.items()):
            lines.append(_line('security_triage_incidents_total',
                               {'source': source, 'synthetic': synthetic, 'decision': decision}, count))

        lines += [
            '# HELP security_triage_analysis_modes_total Incidents by first-pass AI/rules mode.',
            '# TYPE security_triage_analysis_modes_total counter',
        ]
        modes = Counter()
        for mode, n in c.execute('SELECT analysis_mode, COUNT(*) FROM incidents GROUP BY analysis_mode'):
            modes[_label(mode, MODES)] += n
        for mode, count in sorted(modes.items()):
            lines.append(_line('security_triage_analysis_modes_total', {'mode': mode}, count))

        lines += [
            '# HELP security_triage_enrichment_results_total Persisted enrichment statuses, not live availability.',
            '# TYPE security_triage_enrichment_results_total counter',
        ]
        for component, path in CONTEXT_PATHS:
            statuses = Counter()
            for status, n in c.execute(
                f'SELECT {_json_field(path)}, COUNT(*) FROM incidents GROUP BY 1'
            ):
                if status is None:
                    continue  # Older incidents did not execute this enricher.
                statuses[_label(status, CONTEXT_STATES)] += n
            for status, n in sorted(statuses.items()):
                lines.append(_line('security_triage_enrichment_results_total',
                                   {'component': component, 'status': status}, n))

        lines += [
            '# HELP security_triage_delivery_states Number of delivery records in each stored state.',
            '# TYPE security_triage_delivery_states gauge',
        ]
        existing = {row[0] for row in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('mail_deliveries','telegram_deliveries')"
        )}
        for channel, table in CHANNELS:
            if table not in existing:
                continue
            states = Counter()
            for status, n in c.execute(f'SELECT status, COUNT(*) FROM {table} GROUP BY status'):
                states[_label(status, DELIVERY_STATES)] += n
            for status, n in sorted(states.items()):
                lines.append(_line('security_triage_delivery_states',
                                   {'channel': channel, 'status': status}, n))

        lines += [
            '# HELP security_triage_ai_reservations_last_hour Number of hourly-budget slots reserved, not successful calls.',
            '# TYPE security_triage_ai_reservations_last_hour gauge',
        ]
        ai_count = c.execute(
            'SELECT COUNT(*) FROM ai_requests WHERE requested_at>=? AND requested_at<=?',
            (now - 3600, now)
        ).fetchone()[0]
        lines.append(_line('security_triage_ai_reservations_last_hour', {}, ai_count))

        lines += [
            '# HELP security_triage_last_incident_timestamp_seconds Timestamp of the last stored incident.',
            '# TYPE security_triage_last_incident_timestamp_seconds gauge',
        ]
        last = c.execute('SELECT received_at FROM incidents ORDER BY id DESC LIMIT 1').fetchone()
        if last and type(last[0]) is str:
            try:
                dt = datetime.fromisoformat(last[0].replace('Z', '+00:00'))
                if dt.tzinfo is not None:
                    lines.append(_line('security_triage_last_incident_timestamp_seconds',
                                       {}, int(dt.timestamp())))
            except (ValueError, OverflowError):
                pass
    return '\n'.join(lines) + '\n'
