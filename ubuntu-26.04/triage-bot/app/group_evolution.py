"""Block 9: strictly read-only evolution of verified, view-local Wazuh groups.

Indicators describe observed Wazuh rule levels / rule variety only. They are
NOT a risk score, an escalation of operational priority, a causal inference,
or a notification decision. Group identifiers and membership are ephemeral.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from app.incident_groups import (
    VERSION as GROUP_VERSION, VIEW_LIMIT, WINDOW_SECONDS, _priority, _verified,
)

VERSION = 'bot-group-evolution-v1'
SCOPE = 'last_50_incidents_received_by_bot'
TIME_BASIS = 'bot_reception_time'
FLAGS = frozenset(('later_higher_rule_level', 'new_rule_ids', 'burst_5m'))


def _empty(status: str) -> dict:
    return {
        'version': VERSION, 'status': status,
        'scope': SCOPE, 'time_basis': TIME_BASIS, 'window_minutes': 30,
        'group_id': None, 'member_count': 0,
        'first_rule_level': None, 'latest_rule_level': None,
        'max_rule_level': None, 'peak_increased_after_first': None,
        'introduced_rule_ids': [], 'review_priority': None,
        'priority_source': 'max_verified_wazuh_rule_level',
        'review_indicators': [], 'limited_history': True,
        'changes_triage': False, 'changes_notifications': False,
        'sent_to_ai': False, 'automatic_actions': False,
    }


def _valid_group(row: dict) -> tuple | None:
    info = _verified(row)
    if info is None:
        return None
    group = row.get('incident_group')
    if not isinstance(group, dict) or group.get('version') != GROUP_VERSION:
        return None
    if (group.get('status') not in ('grouped', 'single')
            or group.get('scope') != SCOPE or group.get('time_basis') != TIME_BASIS
            or group.get('window_minutes') != 30 or group.get('limited_history') is not True
            or any(group.get(key) is not False for key in
                   ('changes_triage', 'changes_notifications', 'sent_to_ai', 'automatic_actions'))):
        return None
    ids = group.get('member_ids')
    if (not isinstance(ids, list) or not 1 <= len(ids) <= VIEW_LIMIT
            or any(type(x) is not int or x <= 0 for x in ids)
            or len(set(ids)) != len(ids)
            or group.get('member_count') != len(ids)
            or row['id'] not in ids):
        return None
    if group['status'] == 'grouped':
        if (len(ids) < 2 or group.get('group_id') != f'wazuh-window-{ids[0]}'):
            return None
    elif len(ids) != 1 or group.get('group_id') is not None:
        return None
    return info


def annotate(rows: list[dict]) -> list[dict]:
    """Attach group_evolution without mutating the input or other analyses.

    The input must ALREADY have been annotated by incident_groups.annotate().
    Never construct groups from unverified or incomplete membership.
    """
    if not isinstance(rows, list):
        return []
    current = rows[:VIEW_LIMIT]
    id_counts = Counter(row.get('id') for row in current
                        if isinstance(row, dict) and type(row.get('id')) is int)
    clusters: dict[str, list[tuple]] = defaultdict(list)
    by_id: dict[int, dict] = {}
    for row in current:
        if not isinstance(row, dict):
            continue
        ident = row.get('id')
        if type(ident) is not int or id_counts[ident] != 1:
            continue
        if row.get('source') != 'wazuh' or row.get('synthetic') is not False:
            by_id[ident] = _empty('not_applicable')
            continue
        verified = _valid_group(row)
        if verified is None:
            by_id[ident] = _empty('insufficient_data')
            continue
        group = row['incident_group']
        if group['status'] == 'single':
            by_id[ident] = _empty('single')
            continue
        identity, timestamp, rule_id, level = verified
        clusters[group['group_id']].append((ident, identity, timestamp, rule_id,
                                            level, group))
    for key, events in clusters.items():
        expected_ids = events[0][5]['member_ids']
        ids = [event[0] for event in events]
        identity = events[0][1]
        valid = (len(events) >= 2 and len(events) == len(expected_ids)
                 and set(ids) == set(expected_ids)
                 and all(ev[1] == identity and ev[5] == events[0][5]
                         for ev in events))
        ordered = sorted(events, key=lambda x: (x[2], x[0]))
        if valid:
            valid = (ordered[0][0] == expected_ids[0]
                     and ordered[-1][2] - ordered[0][2] <= WINDOW_SECONDS
                     and [ev[0] for ev in ordered] == expected_ids
                     and max(ev[4] for ev in ordered) == events[0][5]['max_rule_level']
                     and {ev[3] for ev in ordered} == set(events[0][5]['rule_ids'])
                     and _priority(max(ev[4] for ev in ordered)) == events[0][5]['max_priority'])
        if not valid:
            for ident in ids:
                by_id[ident] = _empty('insufficient_data')
            continue
        first, latest = ordered[0], ordered[-1]
        peak = max(ev[4] for ev in ordered)
        higher = peak > first[4]
        introduced = sorted({ev[3] for ev in ordered[1:] if ev[3] != first[3]},
                            key=lambda rule: (int(rule), rule))
        burst = 'burst_5m' in events[0][5]['observations']
        indicators = []
        if higher:
            indicators.append('later_higher_rule_level')
        if introduced:
            indicators.append('new_rule_ids')
        if burst:
            indicators.append('burst_5m')
        summary = _empty('observed')
        summary.update({
            'group_id': key, 'member_count': len(ordered),
            'first_rule_level': first[4], 'latest_rule_level': latest[4],
            'max_rule_level': peak, 'peak_increased_after_first': higher,
            'introduced_rule_ids': introduced,
            'review_priority': _priority(peak),
            'review_indicators': indicators,
        })
        for ident in ids:
            by_id[ident] = dict(summary, introduced_rule_ids=introduced[:],
                                review_indicators=indicators[:])
    output = []
    for row in current:
        if not isinstance(row, dict):
            continue
        result = dict(row)
        ident = row.get('id')
        result['group_evolution'] = (by_id.get(ident, _empty('insufficient_data'))
                                     if type(ident) is int else _empty('insufficient_data'))
        output.append(result)
    return output
