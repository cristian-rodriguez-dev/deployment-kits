"""Read-only, ephemeral Wazuh incident grouping for the 50-row incident view.

A group is only a UI observation: same *verified* Wazuh agent, exact host and
inventory department, with all received timestamps within an anchored 30-min
window. Never merge alerts across unverified hosts, different agents or sources.
No writes, external requests, raw logs, notification changes or AI input.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from app.wazuh_enrichment import sanitized_facts

VERSION = 'bot-incident-groups-v1'
SCOPE = 'last_50_incidents_received_by_bot'
TIME_BASIS = 'bot_reception_time'
WINDOW_SECONDS = 30 * 60
VIEW_LIMIT = 50
OBSERVATIONS = frozenset(('repeated_rule', 'multiple_rules', 'burst_5m'))


def _empty(status: str) -> dict:
    return {
        'version': VERSION,
        'status': status,
        'scope': SCOPE,
        'time_basis': TIME_BASIS,
        'window_minutes': 30,
        'group_id': None,
        'member_count': 0,
        'member_ids': [],
        'distinct_rule_count': 0,
        'rule_ids': [],
        'max_rule_level': None,
        'max_priority': None,
        'observations': [],
        'limited_history': True,
        'changes_triage': False,
        'changes_notifications': False,
        'sent_to_ai': False,
        'automatic_actions': False,
    }


def _verified(row: dict) -> tuple | None:
    """Extract only an authenticated, internally consistent Wazuh selector."""
    if (not isinstance(row, dict) or row.get('source') != 'wazuh'
            or row.get('synthetic') is not False
            or type(row.get('id')) is not int or not 0 < row['id'] <= 10**12):
        return None
    analysis = row.get('analysis')
    if not isinstance(analysis, dict):
        return None
    asset = analysis.get('asset')
    metadata = analysis.get('wazuh_context')
    if sanitized_facts(metadata, asset) is None:
        return None
    selector = metadata['selector']
    host = selector['host']
    agent_id = selector['agent_id']
    department = selector['department']
    rule_id = selector['rule_id']
    if (not isinstance(host, str) or not 1 <= len(host) <= 120
            or not isinstance(department, str) or len(department) > 80):
        return None
    raw_received = row.get('received_at')
    if not isinstance(raw_received, str) or len(raw_received) > 80:
        return None
    try:
        received = datetime.fromisoformat(raw_received.replace('Z', '+00:00'))
    except ValueError:
        return None
    if received.tzinfo is None or received.utcoffset() is None:
        return None
    timestamp = received.astimezone(timezone.utc).timestamp()
    if not 1_600_000_000 <= timestamp <= 4_000_000_000:
        return None
    return (host, agent_id, department), timestamp, rule_id, metadata['rule_level']


def _priority(level: int) -> str:
    # Same rule-level thresholds as classification(); never use AI priority.
    return ('critical' if level >= 15 else 'high' if level >= 10 else
            'medium' if level >= 7 else 'low')


def _add_group(by_id: dict[int, dict], members: list[tuple]) -> None:
    members = sorted(members, key=lambda p: (p[1], p[0]))
    if not members:
        return
    ids = [p[0] for p in members]
    rules = [p[2] for p in members]
    distinct_rules = sorted(set(rules), key=lambda s: (int(s), s))
    highest = max(p[3] for p in members)
    observations = []
    counts = Counter(rules)
    if any(count >= 2 for count in counts.values()):
        observations.append('repeated_rule')
    if len(distinct_rules) > 1:
        observations.append('multiple_rules')
    for index, record in enumerate(members):
        if index >= 2 and record[1] - members[index - 2][1] <= 300:
            observations.append('burst_5m')
            break
    status = 'grouped' if len(ids) >= 2 else 'single'
    for incident_id in ids:
        group = _empty(status)
        group.update({
            'group_id': f'wazuh-window-{ids[0]}' if status == 'grouped' else None,
            'member_count': len(ids),
            'member_ids': ids[:],
            'distinct_rule_count': len(distinct_rules),
            'rule_ids': distinct_rules[:],
            'max_rule_level': highest,
            'max_priority': _priority(highest),
            'observations': observations[:],
        })
        by_id[incident_id] = group


def annotate(incidents: list[dict]) -> list[dict]:
    """Return shallow copies with read-only grouping, never mutate source rows.

    Limited to the last 50 incidents already authorized and returned by /incidents.
    The group ID is a *view-local window anchor*, not a durable case identifier.
    """
    if not isinstance(incidents, list):
        return []
    rows = incidents[:VIEW_LIMIT]
    grouped_by_identity: dict[tuple, list[tuple]] = defaultdict(list)
    by_id: dict[int, dict] = {}
    id_counts = Counter(row.get('id') for row in rows
                        if isinstance(row, dict) and type(row.get('id')) is int)
    for row in rows:
        if not isinstance(row, dict):
            continue
        incident_id = row.get('id')
        if type(incident_id) is int and id_counts[incident_id] != 1:
            # Ambiguous IDs must never accidentally merge two records.
            by_id[incident_id] = _empty('insufficient_data')
            continue
        if row.get('source') != 'wazuh' or row.get('synthetic') is not False:
            if type(incident_id) is int:
                by_id[incident_id] = _empty('not_applicable')
            continue
        verified = _verified(row)
        if verified is None:
            if type(incident_id) is int:
                by_id[incident_id] = _empty('insufficient_data')
            continue
        identity, timestamp, rule, level = verified
        grouped_by_identity[identity].append((incident_id, timestamp, rule, level))
    for records in grouped_by_identity.values():
        records.sort(key=lambda p: (p[1], p[0]))
        bucket = []
        anchor = None
        for record in records:
            if anchor is None or record[1] - anchor > WINDOW_SECONDS:
                _add_group(by_id, bucket)
                bucket = []
                anchor = record[1]
            bucket.append(record)
        _add_group(by_id, bucket)
    output = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        new = dict(row)
        ident = row.get('id')
        new['incident_group'] = (by_id.get(ident, _empty('insufficient_data'))
                                 if type(ident) is int else _empty('insufficient_data'))
        output.append(new)
    return output
