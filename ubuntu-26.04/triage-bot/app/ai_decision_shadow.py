"""Strict, identifier-free evidence for optional, advisory AI shadow comparison.

Never writes decisions, invokes notification workers, or calls the model.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from app.wazuh_enrichment import (sanitized_facts as verified_wazuh,
                                  AI_GROUPS, MITRE_PATTERN)
from app.incident_groups import annotate as annotate_groups
from app.group_evolution import annotate as annotate_evolution

VERSION = 'ai-decision-shadow-v1'
SIGNALS = frozenset({'wazuh_rule_repeated_15m', 'wazuh_multiple_rules_observed_15m',
                     'prometheus_scrape_unavailable', 'loki_observed_log_volume_increase',
                     'loki_ssh_service_log_volume_increase'})
SOURCES = frozenset({'wazuh_webhook', 'wazuh_indexer', 'prometheus', 'loki_timeline'})
SIGNAL_SOURCE = {
    'wazuh_rule_repeated_15m': 'wazuh_indexer',
    'wazuh_multiple_rules_observed_15m': 'wazuh_indexer',
    'prometheus_scrape_unavailable': 'prometheus',
    'loki_observed_log_volume_increase': 'loki_timeline',
    'loki_ssh_service_log_volume_increase': 'loki_timeline',
}
SEQUENCE = frozenset({'same_rule_received_at_least_3_times_30m',
                      'different_wazuh_rules_received_30m',
                      'at_least_3_webhooks_received_5m'})
EVOLUTION = frozenset({'later_higher_rule_level', 'new_rule_ids', 'burst_5m'})
DECISIONS = frozenset({'notify', 'review', 'suppress'})
CLASSIFICATIONS = frozenset({'benign', 'suspicious', 'incident', 'insufficient_data'})
CONFIDENCES = frozenset({'low', 'medium', 'high'})
FP = frozenset({'likely', 'possible', 'unlikely', 'unknown'})
PRIORITIES = frozenset({'low', 'medium', 'high', 'critical'})


def _enums(values: Any, allowed: frozenset[str], maximum: int) -> list[str] | None:
    if (not isinstance(values, list) or len(values) > maximum
            or any(type(x) is not str or x not in allowed for x in values)
            or len(set(values)) != len(values)):
        return None
    return sorted(values)


def evidence(*, source: str, synthetic: bool, asset: dict | None,
             wazuh_context: dict | None, cross_source_patterns: dict | None = None,
             temporal_sequence: dict | None = None, history: dict | None = None) -> dict | None:
    """Whitelist only verified facts; no selector/identity/raw logs are transmitted."""
    if source != 'wazuh' or synthetic is not False:
        return None
    facts = verified_wazuh(wazuh_context, asset)
    if facts is None:
        return None
    output = {
        'source': 'wazuh', 'rule_level': facts['rule_level'],
        'rule_categories': facts['rule_categories'],
        'mitre_technique_ids': facts['mitre_technique_ids'],
        'bot_incidents_same_host_rule_30m': facts['bot_incidents_same_host_rule_30m'],
        'limitations': ('Only verified and partial observations. No proof of successful '
                        'SSH access, causal links, active response, or host shutdown.'),
    }
    c = cross_source_patterns
    if (isinstance(c, dict) and c.get('version') == 'cross-source-patterns-v1'
            and c.get('status') == 'ok' and c.get('changes_triage') is False
            and c.get('changes_notifications') is False
            and c.get('raw_logs_stored') is False and c.get('sent_to_ai') is False):
        sources = _enums(c.get('sources_validated'), SOURCES, 4)
        signals = c.get('signals')
        if (sources is not None and 'wazuh_webhook' in sources
                and isinstance(signals, list) and len(signals) <= 5
                and type(c.get('signal_count')) is int
                and c['signal_count'] == len(signals)):
            kinds = []
            for item in signals:
                if (not isinstance(item, dict) or item.get('kind') not in SIGNALS
                        or item.get('source') not in sources
                        or SIGNAL_SOURCE.get(item.get('kind')) != item.get('source')):
                    break
                kinds.append(item['kind'])
            else:
                if len(set(kinds)) == len(kinds):
                    output['cross_source'] = {'sources_verified': sources,
                                              'signal_kinds': sorted(kinds),
                                              'not_causal_evidence': True}
    t = temporal_sequence
    if (isinstance(t, dict) and t.get('version') == 'wazuh-received-sequence-v1'
            and t.get('status') == 'ok'
            and t.get('source') == 'authenticated_wazuh_webhooks_received_by_bot'
            and t.get('scope') == 'same_verified_wazuh_agent_and_host'
            and t.get('time_basis') == 'bot_reception_time_not_original_event_time'
            and t.get('window_minutes') == 30
            and t.get('changes_triage') is False
            and t.get('changes_notifications') is False
            and t.get('raw_logs_stored') is False and t.get('sent_to_ai') is False):
        kinds = _enums(t.get('observations'), SEQUENCE, 3)
        count = t.get('previous_verified_incidents')
        repeated = t.get('prior_same_rule')
        if (kinds is not None and type(count) is int and type(repeated) is int
                and 0 <= repeated <= count <= 100):
            output['received_sequence'] = {
                'previous_verified_incidents': count, 'prior_same_rule': repeated,
                'observations': kinds, 'partial_history_only': True,
            }
    h = history
    if isinstance(h, dict):
        count = h.get('member_count')
        peak = h.get('max_rule_level')
        kinds = _enums(h.get('review_indicators'), EVOLUTION, 3)
        if (h.get('status') == 'observed' and type(count) is int and 2 <= count <= 50
                and type(peak) is int and facts['rule_level'] <= peak <= 16
                and type(h.get('peak_increased_after_first')) is bool and kinds is not None):
            output['historical_group'] = {
                'verified_members_in_last_50': count,
                'maximum_wazuh_rule_level': peak,
                'peak_increased_after_first': h['peak_increased_after_first'],
                'observations': kinds, 'partial_history_only': True,
            }
    return output



def validated_for_model(data: Any) -> bool:
    """Second trust boundary: reject arbitrary caller-provided model inputs."""
    if not isinstance(data, dict) or set(data) - {
            'source','rule_level','rule_categories','mitre_technique_ids',
            'bot_incidents_same_host_rule_30m','limitations',
            'cross_source','received_sequence','historical_group'}:
        return False
    if (data.get('source') != 'wazuh'
            or type(data.get('rule_level')) is not int
            or not 0 <= data['rule_level'] <= 16
            or type(data.get('bot_incidents_same_host_rule_30m')) is not int
            or not 1 <= data['bot_incidents_same_host_rule_30m'] <= 100001
            or data.get('limitations') != (
                'Only verified and partial observations. No proof of successful '
                'SSH access, causal links, active response, or host shutdown.')):
        return False
    categories = _enums(data.get('rule_categories'), AI_GROUPS, 8)
    mitre = data.get('mitre_technique_ids')
    if (categories is None or not isinstance(mitre, list) or len(mitre)>8
            or any(type(x) is not str or not MITRE_PATTERN.fullmatch(x) for x in mitre)):
        return False
    c = data.get('cross_source')
    if c is not None:
        if (not isinstance(c,dict) or set(c) != {
                'sources_verified', 'signal_kinds', 'not_causal_evidence'}
                or c['not_causal_evidence'] is not True
                or _enums(c['sources_verified'],SOURCES,4) is None
                or 'wazuh_webhook' not in c['sources_verified']
                or _enums(c['signal_kinds'],SIGNALS,5) is None):
            return False
    t = data.get('received_sequence')
    if t is not None:
        if (not isinstance(t,dict) or set(t) != {
                'previous_verified_incidents','prior_same_rule',
                'observations','partial_history_only'}
                or t['partial_history_only'] is not True
                or type(t['previous_verified_incidents']) is not int
                or type(t['prior_same_rule']) is not int
                or not 0 <= t['prior_same_rule'] <= t['previous_verified_incidents'] <= 100
                or _enums(t['observations'],SEQUENCE,3) is None):
            return False
    h = data.get('historical_group')
    if h is not None:
        if (not isinstance(h,dict) or set(h) != {
                'verified_members_in_last_50','maximum_wazuh_rule_level',
                'peak_increased_after_first','observations','partial_history_only'}
                or h['partial_history_only'] is not True
                or type(h['verified_members_in_last_50']) is not int
                or not 2 <= h['verified_members_in_last_50'] <= 50
                or type(h['maximum_wazuh_rule_level']) is not int
                or not data['rule_level'] <= h['maximum_wazuh_rule_level'] <= 16
                or type(h['peak_increased_after_first']) is not bool
                or _enums(h['observations'],EVOLUTION,3) is None):
            return False
    return len(json.dumps(data, ensure_ascii=False)) <= 4096

def historical_evolution(db: Any, current_analysis: dict, now: int) -> dict | None:
    """Compute groups for current+49 historical rows in memory; no SQLite writes."""
    rows = db.execute('''SELECT id,received_at,source,synthetic,analysis
                         FROM incidents ORDER BY id DESC LIMIT 49''').fetchall()
    previous = []
    for ident, received, source, synthetic, data in rows:
        if (type(ident) is not int or not isinstance(data, str)
                or len(data) > 64000 or synthetic not in (0, 1)):
            return None
        obj = json.loads(data)
        if not isinstance(obj, dict):
            return None
        previous.append({'id': ident, 'received_at': received, 'source': source,
                         'synthetic': bool(synthetic), 'analysis': obj})
    new_id = max((row['id'] for row in previous), default=0) + 1
    current = {'id': new_id, 'received_at': datetime.now(timezone.utc).isoformat(),
               'source': 'wazuh', 'synthetic': False, 'analysis': current_analysis}
    grouped = annotate_evolution(annotate_groups([current] + previous))
    return (grouped[0].get('group_evolution')
            if grouped and grouped[0].get('id') == new_id else None)


def available_evidence_ids(facts: Any) -> list[str]:
    """Produce a bounded vocabulary of observable facts, not proof of a decision.

    No free-form model text, host/agent identifiers, raw logs or selectors enter
    these codes. An absent source cannot be cited by the model.
    """
    if not validated_for_model(facts):
        return []
    available = {'wazuh.rule_level'}
    if facts['rule_categories']:
        available.add('wazuh.rule_categories')
    if facts['mitre_technique_ids']:
        available.add('wazuh.mitre_mapping')
    if facts['bot_incidents_same_host_rule_30m'] > 1:
        available.add('wazuh.bot_repeat_count')
    c = facts.get('cross_source')
    if c:
        available.update('cross.' + kind for kind in c['signal_kinds'])
    seq = facts.get('received_sequence')
    if seq:
        available.update('sequence.' + kind for kind in seq['observations'])
    history = facts.get('historical_group')
    if history:
        available.add('group.maximum_rule_level')
        available.update('group.' + kind for kind in history['observations'])
    return sorted(available)


def _citation_quality(proposal: dict, facts: Any) -> dict:
    """Check *reference integrity*, never assert that the reasoning is true.

    Citation IDs can confirm that an observation was present, but cannot prove
    causality, diagnosis or that the recommended decision is appropriate.
    """
    output = {
        'version': 'shadow-grounding-v1',
        'status': 'missing_citations',
        'cited_evidence_count': 0,
        'free_text_reason_verified': False,
        'safe_for_automatic_policy': False,
    }
    cited = proposal.get('supporting_evidence_ids')
    if cited is None:
        return output
    if (type(cited) is not list or not 1 <= len(cited) <= 4
            or any(type(item) is not str or len(item) > 100 for item in cited)
            or len(set(cited)) != len(cited)):
        output['status'] = 'invalid_citations'
        return output
    available = available_evidence_ids(facts)
    if not available or not set(cited).issubset(available):
        output['status'] = 'unsupported_citations'
        return output
    output['status'] = 'cited_observations'
    output['cited_evidence_count'] = len(cited)
    return output


def compare(model: dict | None, actual: str, facts: dict | None) -> dict:
    """Fail closed on malformed proposal; never invoke the actual policy."""
    result = {'version': VERSION, 'status': 'not_evaluated', 'type': 'advisory_only',
              'actual_decision': actual, 'proposed_decision': None,
              'differs_from_current': None, 'source_evidence': facts,
              'changes_triage': False, 'changes_notifications': False,
              'automatic_actions': False}
    if not isinstance(model, dict) or not isinstance(facts, dict) or actual not in DECISIONS:
        return result
    p = model.get('shadow_recommendation')
    if not isinstance(p, dict) or any((p.get(k) not in choices) for k, choices in (
            ('decision', DECISIONS), ('classification', CLASSIFICATIONS),
            ('priority', PRIORITIES), ('false_positive', FP), ('confidence', CONFIDENCES))):
        return result
    reason = p.get('reason')
    if type(reason) is not str or not 1 <= len(reason.strip()) <= 400:
        return result
    quality = _citation_quality(p, facts)
    return dict(result, status='evaluated', proposed_decision=p['decision'],
                differs_from_current=p['decision'] != actual,
                classification=p['classification'], priority=p['priority'],
                false_positive=p['false_positive'], confidence=p['confidence'],
                reason=reason.strip(), requires_human_review=True,
                evidence_grounding=quality)
