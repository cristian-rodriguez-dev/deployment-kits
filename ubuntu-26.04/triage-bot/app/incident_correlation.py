"""Bounded, read-only cross-source correlation of incidents *received by this bot*.

No network calls, IP lookup, LLM request, persistence migration or security decision.
Only a literal normalized host match within the same triage_context SQLite table.
This is a related-alerts summary, NOT proof of causation or complete observability.
"""
from __future__ import annotations

import sqlite3

WINDOW_SECONDS = 15 * 60
MAX_MATCHES = 250
DISPLAY_LIMIT = 5
KNOWN_SOURCES = frozenset(('grafana', 'wazuh'))


def _empty(minutes: int = 15) -> dict:
    return {
        'version': 'bot-local-v1',
        'scope': 'incidents_received_by_bot_only',
        'method': 'exact_normalized_host',
        'window_minutes': minutes,
        'same_host_total': 0,
        'by_source': {'grafana': 0, 'wazuh': 0},
        'distinct_rules': 0,
        'multiple_sources': False,
        'recent_incident_ids': [],
        'truncated': False,
    }


def summarize_recent(db: sqlite3.Connection, host: str, now: int,
                     *, window_seconds: int = WINDOW_SECONDS) -> dict:
    """Correlate only past, same-host incidents; never fuzzy-match identifiers.

    Negative/oversized windows and unknown host identifiers return empty results.
    A bounded query avoids expensive scans or oversized incident JSON.
    """
    minutes = window_seconds // 60 if 0 < window_seconds <= 3600 else 15
    result = _empty(minutes)
    if not isinstance(host, str) or len(host) > 80:
        return result
    host = host.strip()
    if len(host) < 3 or host.casefold().startswith('unknown-'):
        return result
    if not isinstance(now, int) or now < 0 or not (0 < window_seconds <= 3600):
        return result

    rows = db.execute('''
        SELECT incident_id, source, rule_key
          FROM triage_context
         WHERE host = ? COLLATE NOCASE AND created_ts >= ? AND created_ts <= ?
         ORDER BY created_ts DESC, incident_id DESC
         LIMIT ?
    ''', (host, now - window_seconds, now, MAX_MATCHES + 1)).fetchall()

    result['truncated'] = len(rows) > MAX_MATCHES
    rows = rows[:MAX_MATCHES]
    by_source = {'grafana': 0, 'wazuh': 0}
    rules = set()
    ids = []
    for incident_id, source, rule_key in rows:
        if source in KNOWN_SOURCES:
            by_source[source] += 1
        rules.add((source, rule_key))
        if len(ids) < DISPLAY_LIMIT:
            ids.append(int(incident_id))
    result.update({
        'same_host_total': len(rows),
        'by_source': by_source,
        'distinct_rules': len(rules),
        'multiple_sources': by_source['grafana'] > 0 and by_source['wazuh'] > 0,
        'recent_incident_ids': ids,
    })
    return result
