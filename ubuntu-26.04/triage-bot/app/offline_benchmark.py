"""Synthetic, networkless regression bench for Security Triage's real policy.

Uses the production deterministic policy and shadow evidence/validation code, but
replays predefined model responses through an intercepted contextual call.
It NEVER calls Gemini, the bot API, SQLite, or notification workers.
Fixtures are NOT representative security detections or analyst ground truth.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
import io
import json
from pathlib import Path
import re
import socket
from typing import Any
from unittest.mock import patch

from app import ai_decision_shadow, contextual_analysis
from app.triage_policy import assess, hard_critical_source
from app.wazuh_enrichment import collect

VERSION = 'offline-triage-benchmark-v1'
MAX_FILE_BYTES = 100_000
MAX_CASES = 50
CASE_ID_RE = re.compile(r'[a-z][a-z0-9-]{2,47}\Z')
ALLOWED_FIELDS = frozenset({
    'id', 'severity', 'synthetic_event', 'mode', 'recent_count',
    'primary_analysis', 'agent_identity_match', 'rule_groups', 'mitre_ids',
    'cross_signal_kinds', 'sequence_observations', 'group_observations',
    'group_peak_level', 'shadow_reply', 'expected_policy_decision',
    'expected_grounding',
})
SIGNAL_SOURCE = ai_decision_shadow.SIGNAL_SOURCE


class BenchInputError(ValueError):
    """A fixture violates the offline dataset contract (never print its content)."""


def _bounded_list(data: Any, allowed: frozenset[str] | set[str], max_items: int) -> bool:
    return (type(data) is list and len(data) <= max_items
            and all(type(x) is str and x in allowed for x in data)
            and len(set(data)) == len(data))


def load_cases(path: str | Path) -> list[dict]:
    """Only load small, explicitly synthetic JSON fixtures; never read production DB."""
    file = Path(path)
    if not file.is_file() or file.stat().st_size > MAX_FILE_BYTES:
        raise BenchInputError('missing or oversized fixture')
    try:
        dataset = json.loads(file.read_text(encoding='utf-8'))
    except (UnicodeError, ValueError) as exc:
        raise BenchInputError('invalid JSON fixture') from exc
    if (type(dataset) is not dict or set(dataset) != {'schema_version', 'provenance', 'cases'}
            or dataset['schema_version'] != 'offline-triage-cases-v1'
            or dataset['provenance'] != 'synthetic_examples_not_ground_truth'
            or type(dataset['cases']) is not list
            or not 1 <= len(dataset['cases']) <= MAX_CASES):
        raise BenchInputError('invalid dataset contract')
    seen = set()
    for case in dataset['cases']:
        if type(case) is not dict or (set(case) - ALLOWED_FIELDS):
            raise BenchInputError('unsupported case fields')
        ident = case.get('id')
        if type(ident) is not str or not CASE_ID_RE.fullmatch(ident) or ident in seen:
            raise BenchInputError('invalid or duplicate case id')
        seen.add(ident)
        level = case.get('severity')
        if type(level) is not int or not 0 <= level <= 16:
            raise BenchInputError('invalid severity')
        if (type(case.get('synthetic_event')) is not bool
                or case.get('mode') not in ('gemini', 'fallback')
                or type(case.get('recent_count')) is not int
                or not 1 <= case['recent_count'] <= 50
                or type(case.get('agent_identity_match')) is not bool
                or case.get('expected_policy_decision') not in ai_decision_shadow.DECISIONS
                or case.get('expected_grounding') not in (
                    'cited_observations', 'unsupported_citations', 'missing_citations',
                    'invalid_citations', 'not_evaluated')):
            raise BenchInputError('invalid case contract')
        primary = case.get('primary_analysis')
        if type(primary) is not dict or set(primary) != {
                'priority', 'classification', 'false_positive', 'confidence', 'notify'}:
            raise BenchInputError('invalid primary analysis')
        if (primary['priority'] not in ai_decision_shadow.PRIORITIES
                or primary['classification'] not in ai_decision_shadow.CLASSIFICATIONS
                or primary['false_positive'] not in ai_decision_shadow.FP
                or primary['confidence'] not in ai_decision_shadow.CONFIDENCES
                or type(primary['notify']) is not bool):
            raise BenchInputError('invalid primary fields')
        if (not _bounded_list(case.get('rule_groups'),
                              frozenset({'sshd', 'attack', 'authentication_failed',
                                         'authentication_success', 'syscheck', 'sca', 'fim'}), 5)
                or not _bounded_list(case.get('mitre_ids'),
                                     frozenset({'T1110', 'T1078', 'T1548'}), 3)
                or not _bounded_list(case.get('cross_signal_kinds'),
                                     frozenset(SIGNAL_SOURCE), 5)
                or not _bounded_list(case.get('sequence_observations'),
                                     ai_decision_shadow.SEQUENCE, 3)
                or not _bounded_list(case.get('group_observations'),
                                     ai_decision_shadow.EVOLUTION, 3)):
            raise BenchInputError('invalid simulated observations')
        peak = case.get('group_peak_level')
        if peak is not None and (type(peak) is not int or not level <= peak <= 16):
            raise BenchInputError('invalid group peak')
        reply = case.get('shadow_reply')
        if reply is not None:
            if (type(reply) is not dict or set(reply) != {
                    'decision', 'classification', 'priority', 'false_positive',
                    'confidence', 'reason', 'supporting_evidence_ids'}
                    or reply['decision'] not in ai_decision_shadow.DECISIONS
                    or reply['classification'] not in ai_decision_shadow.CLASSIFICATIONS
                    or reply['priority'] not in ai_decision_shadow.PRIORITIES
                    or reply['false_positive'] not in ai_decision_shadow.FP
                    or reply['confidence'] not in ai_decision_shadow.CONFIDENCES
                    or type(reply['reason']) is not str
                    or not 1 <= len(reply['reason']) <= 120
                    or type(reply['supporting_evidence_ids']) is not list
                    or len(reply['supporting_evidence_ids']) > 4
                    or any(type(v) is not str or not 1 <= len(v) <= 100
                           for v in reply['supporting_evidence_ids'])):
                raise BenchInputError('invalid replayed model reply')
    return dataset['cases']


def _fake_evidence(case: dict) -> tuple[dict | None, dict, dict]:
    """Synthetic metadata must pass the bot's own Wazuh identity/sanitizer."""
    # Deliberately constant lab-only identifiers, never user-provided.
    asset = {'agent_id': '005', 'rule_id': '5763', 'name': 'fixture-node',
             'department': 'synthetic', 'job': 'synthetic-only'}
    rule = {'id': '5763', 'level': case['severity'],
            'groups': case['rule_groups'], 'mitre': {'id': case['mitre_ids']}}
    agent = {'id': '005' if case['agent_identity_match'] else '006'}
    wz = collect(rule, agent, asset, case['recent_count'] - 1)
    kinds = case['cross_signal_kinds']
    sources = sorted({'wazuh_webhook'} | {SIGNAL_SOURCE[k] for k in kinds})
    cross = {
        'version': 'cross-source-patterns-v1', 'status': 'ok',
        'changes_triage': False, 'changes_notifications': False,
        'raw_logs_stored': False, 'sent_to_ai': False,
        'sources_validated': sources,
        'signals': [{'kind': k, 'source': SIGNAL_SOURCE[k]} for k in kinds],
        'signal_count': len(kinds),
    }
    seq = {
        'version': 'wazuh-received-sequence-v1', 'status': 'ok',
        'source': 'authenticated_wazuh_webhooks_received_by_bot',
        'scope': 'same_verified_wazuh_agent_and_host',
        'time_basis': 'bot_reception_time_not_original_event_time',
        'window_minutes': 30, 'changes_triage': False,
        'changes_notifications': False, 'raw_logs_stored': False,
        'sent_to_ai': False, 'observations': case['sequence_observations'],
        'previous_verified_incidents': case['recent_count'] - 1,
        'prior_same_rule': case['recent_count'] - 1,
    }
    group = None
    if case['group_peak_level'] is not None:
        group = {
            'status': 'observed', 'member_count': max(2, case['recent_count']),
            'max_rule_level': case['group_peak_level'],
            'peak_increased_after_first': 'later_higher_rule_level' in case['group_observations'],
            'review_indicators': case['group_observations'],
        }
    facts = ai_decision_shadow.evidence(
        source='wazuh', synthetic=case['synthetic_event'], asset=asset,
        wazuh_context=wz, cross_source_patterns=cross,
        temporal_sequence=seq, history=group)
    return facts, wz, asset


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


@contextmanager
def _no_network(fake):
    """Prevent network use even if somebody adds a client in the replay path."""
    with (patch('socket.socket.connect', side_effect=AssertionError('network forbidden')),
          patch('socket.create_connection', side_effect=AssertionError('network forbidden')),
          patch.object(contextual_analysis.urllib.request, 'urlopen', fake)):
        yield


def _replay(case: dict, facts: dict | None, wazuh: dict, asset: dict) -> tuple[dict | None, int]:
    if facts is None or case['mode'] != 'gemini':
        return None, 0
    answer = {
        'summary': 'Caso sintético', 'technical_reading': 'Observaciones simuladas',
        'recommended_checks': ['Revisar evidencias simuladas'], 'confidence': 'low',
    }
    if case['shadow_reply'] is not None:
        answer['shadow_decision'] = case['shadow_reply']
    envelope = {'candidates': [{'content': {'parts': [{'text':
                json.dumps(answer, ensure_ascii=False)}]}}]}
    fake_bytes = json.dumps(envelope, ensure_ascii=False).encode('utf-8')
    calls = []

    def fake_urlopen(req, timeout):
        # No real network: verify request includes only the bounded shadow facts.
        request = json.loads(req.data)
        prompt = request['contents'][0]['parts'][0]['text']
        assert 'decision_shadow_allowed_evidence_ids' in prompt
        assert 'fixture-node' not in prompt and '"agent_id"' not in prompt
        assert '"raw_logs"' not in prompt
        calls.append(1)
        return _FakeResponse(fake_bytes)

    with _no_network(fake_urlopen):
        result = contextual_analysis.interpret(
            None, 'wazuh', 'security', 'offline-not-real-key', 'offline-not-real-model',
            wazuh_context=wazuh, asset=asset, shadow_facts=facts)
    assert len(calls) == 1 and result['shadow_evidence_used'] is True
    return result, len(calls)


def run_case(case: dict) -> dict:
    """Use production code; return counters/labels only, never original content."""
    baseline_analysis = deepcopy(case['primary_analysis'])
    baseline = assess(
        'wazuh', 'Simulated Wazuh alert', str(case['severity']),
        case['synthetic_event'], case['mode'], baseline_analysis,
        {'host': 'fixture-node', 'rule_key': '5763', 'category': 'security'},
        case['recent_count'])
    facts, wazuh, asset = _fake_evidence(case)
    advisory, calls = _replay(case, facts, wazuh, asset)
    model = advisory if isinstance(advisory, dict) and advisory.get('shadow_evidence_used') else None
    shadow = ai_decision_shadow.compare(model, baseline['decision'], facts)
    status = shadow.get('evidence_grounding', {}).get('status', 'not_evaluated')
    if shadow['status'] != 'evaluated':
        status = 'not_evaluated'
    safe_critical = not hard_critical_source('wazuh', str(case['severity'])) or (
        case['synthetic_event'] or baseline['decision'] == 'notify')
    safe_synthetic = not case['synthetic_event'] or baseline['decision'] == 'suppress'
    protected = (shadow['changes_triage'] is False
                 and shadow['changes_notifications'] is False
                 and shadow['automatic_actions'] is False)
    return {
        'id': case['id'],
        'baseline': baseline['decision'],
        'shadow': shadow['proposed_decision'],
        'shadow_status': shadow['status'],
        'grounding': status,
        'policy_expectation_met': baseline['decision'] == case['expected_policy_decision'],
        'grounding_expectation_met': status == case['expected_grounding'],
        'protected': protected and safe_critical and safe_synthetic,
        'critical_suppression_suggestion': (hard_critical_source('wazuh', str(case['severity']))
                                             and shadow['proposed_decision'] == 'suppress'),
        'replayed_model_calls': calls,  # local stub responses, never Gemini requests
    }


def report(cases: list[dict]) -> dict:
    rows = [run_case(case) for case in cases]
    counts = Counter()
    pairs = Counter()
    grounding = Counter()
    for row in rows:
        counts['cases'] += 1
        counts['stubbed_contextual_calls'] += row['replayed_model_calls']
        counts['policy_expectation_met' if row['policy_expectation_met']
               else 'policy_expectation_failed'] += 1
        counts['grounding_expectation_met' if row['grounding_expectation_met']
               else 'grounding_expectation_failed'] += 1
        if not row['protected']:
            counts['safety_invariant_failed'] += 1
        if row['critical_suppression_suggestion']:
            counts['critical_suppress_proposed_but_not_applied'] += 1
        if row['shadow_status'] == 'evaluated':
            counts['shadow_evaluated'] += 1
            pairs[row['baseline'] + '__' + row['shadow']] += 1
        else:
            counts['shadow_not_evaluated'] += 1
        grounding[row['grounding']] += 1
    safe = not any((not row['protected'] or not row['policy_expectation_met']
                    or not row['grounding_expectation_met']) for row in rows)
    return {
        'version': VERSION, 'fixture_provenance': 'synthetic_examples_not_ground_truth',
        'status': 'passed' if safe else 'failed', 'network_requests': 0,
        'database_reads': 0, 'database_writes': 0, 'notifications_sent': 0,
        'counts': dict(sorted(counts.items())),
        'decision_pairs': dict(sorted(pairs.items())),
        'grounding': dict(sorted(grounding.items())),
        'cases': [{k: row[k] for k in (
            'id', 'baseline', 'shadow', 'shadow_status', 'grounding',
            'policy_expectation_met', 'grounding_expectation_met', 'protected')}
                  for row in rows],
        'limitations': [
            'Responses are canned synthetic examples, NOT live Gemini model outputs.',
            'Expected decisions are regression-test expectations, NOT analyst ground truth.',
            'No accuracy, recall, false-positive rate or model improvement can be inferred.',
            'The replay calls the real policy and contextual parsing, but not the whole live pipeline.',
            'Grounded citation IDs do not validate causal explanations or conclusions.',
            'Shadow recommendations never change notifications or security decisions.',
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Offline, synthetic security triage regression bench')
    parser.add_argument('--cases', default='evaluation/cases_v1.json',
                        help='synthetic fixture JSON only; never use production data')
    args = parser.parse_args(argv)
    try:
        summary = report(load_cases(args.cases))
    except (BenchInputError, OSError, ValueError, AssertionError, KeyError, TypeError) as exc:
        # Deliberately omit paths and fixture content from error messages.
        parser.exit(2, f'Offline benchmark unavailable ({type(exc).__name__}); no changes made.\n')
    print(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True))
    return 0 if summary['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
