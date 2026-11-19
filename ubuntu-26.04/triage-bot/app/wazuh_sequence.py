"""Read-only sequence of *received* Wazuh webhooks for one verified agent.

Not an Indexer event timeline or complete intrusion history. Never infer a
successful login, an attack progression, causation, or host outage. All output
is bounded metadata; no raw logs, credentials, IPs or host names.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.wazuh_enrichment import sanitized_facts as verified_wazuh

VERSION = 'wazuh-received-sequence-v1'
WINDOW = 30 * 60
CANDIDATE_LIMIT = 100
TIMELINE_LIMIT = 6


def _base(status: str = 'insufficient_data') -> dict:
    return {
        'version': VERSION,
        'status': status,
        'source': 'authenticated_wazuh_webhooks_received_by_bot',
        'scope': 'same_verified_wazuh_agent_and_host',
        'time_basis': 'bot_reception_time_not_original_event_time',
        'window_minutes': 30,
        'previous_verified_incidents': 0,
        'prior_same_rule': 0,
        'distinct_rule_count_including_current': 0,
        'timeline': [],
        'observations': [],
        'truncated': False,
        'changes_triage': False,
        'changes_notifications': False,
        'sent_to_ai': False,
        'raw_logs_stored': False,
    }


def _rule(value: Any) -> bool:
    return isinstance(value, str) and value.isascii() and value.isdecimal() and 1 <= len(value) <= 6


def summarize(db: sqlite3.Connection, *, source: str, synthetic: bool,
              asset: dict | None, wazuh_context: dict | None, now: int) -> dict:
    """Read only prior *non-synthetic* bot incidents, using exact validated agent.

    The current incident has not yet been inserted; it is included as an
    explicit current anchor, age=0. A historical row must carry its own valid
    Wazuh webhook metadata, not merely the same host name.
    """
    result = _base()
    if (source != 'wazuh' or synthetic is not False or type(now) is not int
            or now < 1_600_000_000 or not isinstance(asset, dict)
            or verified_wazuh(wazuh_context, asset) is None):
        return result
    selector = wazuh_context['selector']
    host, agent_id, current_rule = selector['host'], selector['agent_id'], selector['rule_id']
    if not isinstance(host, str) or not 1 <= len(host) <= 120 or not _rule(current_rule):
        return result
    # Join is read-only. Bounded work; do not query by raw IP or a loose/fuzzy
    # name, and never treat host matches without a verified agent as evidence.
    rows = db.execute('''
        SELECT ctx.incident_id, ctx.created_ts, ctx.rule_key, inc.analysis
        FROM triage_context AS ctx
        JOIN incidents AS inc ON inc.id = ctx.incident_id
        WHERE ctx.source = 'wazuh' AND inc.source = 'wazuh'
          AND inc.synthetic = 0 AND ctx.host = ? COLLATE BINARY
          AND ctx.created_ts >= ? AND ctx.created_ts <= ?
        ORDER BY ctx.created_ts DESC, ctx.incident_id DESC
        LIMIT ?
    ''', (host, now - WINDOW, now, CANDIDATE_LIMIT + 1)).fetchall()
    truncated = len(rows) > CANDIDATE_LIMIT
    rows = rows[:CANDIDATE_LIMIT]
    verified = []
    for incident_id, received, rule_key, analysis_json in rows:
        if (type(incident_id) is not int or type(received) is not int
                or not now - WINDOW <= received <= now
                or not _rule(rule_key) or not isinstance(analysis_json, str)
                or len(analysis_json) > 64_000):
            continue
        try:
            analysis = json.loads(analysis_json)
        except (ValueError, TypeError):
            continue
        if not isinstance(analysis, dict):
            continue
        metadata = analysis.get('wazuh_context')
        if (not isinstance(metadata, dict)
                or metadata.get('version') != 'wazuh-webhook-metadata-v1'
                or metadata.get('status') != 'ok'
                or metadata.get('source') != 'authenticated_wazuh_webhook'
                or metadata.get('scope') != 'exact_agent_rule_webhook'
                or metadata.get('changes_triage') is not False
                or metadata.get('raw_log_lines_stored') is not False):
            continue
        past_selector = metadata.get('selector')
        if (not isinstance(past_selector, dict)
                or past_selector.get('host') != host
                or past_selector.get('agent_id') != agent_id
                or past_selector.get('rule_id') != rule_key):
            continue
        verified.append((incident_id, received, rule_key))

    # Chronological ordering is based on receipt timestamps only. Equal-second
    # events are ordered by incident ID; no inter-sensor time claim is made.
    verified.sort(key=lambda row: (row[1], row[0]))
    prev_same = sum(rule == current_rule for _, _, rule in verified)
    rules = {rule for _, _, rule in verified}
    rules.add(current_rule)
    burst_prior = sum(ts >= now - 300 for _, ts, _ in verified)
    observations = []
    if prev_same >= 2:
        observations.append('same_rule_received_at_least_3_times_30m')
    if len(rules) >= 2:
        observations.append('different_wazuh_rules_received_30m')
    if burst_prior >= 2:
        observations.append('at_least_3_webhooks_received_5m')
    timeline = [
        {'incident_id': ident, 'rule_id': rule, 'age_seconds': now - ts}
        for ident, ts, rule in verified[-(TIMELINE_LIMIT - 1):]
    ]
    timeline.append({'incident_id': None, 'rule_id': current_rule, 'age_seconds': 0})
    result.update({
        'status': 'ok',
        'previous_verified_incidents': len(verified),
        'prior_same_rule': prev_same,
        'distinct_rule_count_including_current': len(rules),
        'timeline': timeline,
        'observations': observations,
        'truncated': truncated,
    })
    return result
