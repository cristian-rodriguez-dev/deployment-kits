"""Offline, evidence-aware consistency checks for *synthetic* multi-axis proposals.

This is NOT the live Security Triage policy and is NOT a model accuracy scorer.
It applies structural validation from the existing shadow contract, followed by
conservative semantic warnings, without interpreting free-text explanations.

It does not modify decisions, notifications, models, SQLite, or any service.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
from typing import Any

from app import multiaxis_shadow, offline_benchmark
from app.ai_decision_shadow import SIGNAL_SOURCE, available_evidence_ids

VERSION = 'offline-multiaxis-consistency-v1'
SCHEMA = 'triage-multiaxis-challenges-v1'
MAX_BYTES = 100_000
MAX_ITEMS = 50
ID_RE = re.compile(r'[a-z][a-z0-9-]{2,47}\Z')


class ChallengeInputError(ValueError):
    """Invalid synthetic evaluation contract. Do not echo untrusted content."""


def read_challenges(path: str | Path, known_cases: set[str]) -> list[dict]:
    file = Path(path)
    if file.is_symlink() or not file.is_file() or not 1 <= file.stat().st_size <= MAX_BYTES:
        raise ChallengeInputError('invalid challenge file')
    try:
        payload = json.loads(file.read_text(encoding='utf-8'))
    except (UnicodeError, ValueError) as exc:
        raise ChallengeInputError('invalid challenge JSON') from exc
    if (type(payload) is not dict or set(payload) != {'schema_version', 'provenance', 'challenges'}
            or payload['schema_version'] != SCHEMA
            or payload['provenance'] != 'synthetic_proposals_not_gemini_outputs'
            or type(payload['challenges']) is not list
            or not 1 <= len(payload['challenges']) <= MAX_ITEMS):
        raise ChallengeInputError('invalid challenge contract')
    seen = set()
    for item in payload['challenges']:
        if (type(item) is not dict or set(item) != {'id', 'case_id', 'proposal'}
                or type(item['id']) is not str or not ID_RE.fullmatch(item['id'])
                or item['id'] in seen or type(item['case_id']) is not str
                or item['case_id'] not in known_cases
                or type(item['proposal']) is not dict):
            raise ChallengeInputError('invalid challenge item')
        seen.add(item['id'])
        # No requirement that the proposal be structurally valid: rejection is a
        # testable result. But bound its size and never echo its arbitrary text.
        if len(json.dumps(item['proposal'], ensure_ascii=False)) > 6000:
            raise ChallengeInputError('oversized candidate proposal')
    return payload['challenges']


def _semantic_warnings(case: dict, proposal: dict) -> list[str]:
    """Explicit risk indicators, NOT automatic incident decisions.

    The fixtures provide no independent proof of benign intent, of a successful
    SSH login or of compromise. Wazuh severity alone is not such proof either.
    """
    flags = []
    if case['synthetic_event'] and proposal.get('notification') == 'notify':
        flags.append('synthetic_notification_conflict')
    if not case['agent_identity_match']:
        flags.append('unverified_asset_identity')
    if (not case['synthetic_event'] and case['severity'] >= 12
            and proposal.get('notification') != 'notify'):
        flags.append('critical_notification_conflict')
    if (not case['synthetic_event'] and case['agent_identity_match']
            and max(case['severity'], case['group_peak_level'] or 0) >= 12
            and proposal.get('investigation') == 'not_required'):
        flags.append('critical_investigation_conflict')
    if proposal.get('evidence_state') == 'benign_supported':
        flags.append('benign_claim_without_verified_benign_evidence')
    # Source diversity is only one factor. Flag for further review rather than
    # claiming to calculate actual confidence or to reject a model outright.
    if (proposal.get('confidence') == 'high'
            and not case['cross_signal_kinds']
            and not case['sequence_observations']
            and not case['group_observations']):
        flags.append('high_confidence_limited_observations')
    if (not case['synthetic_event'] and case['agent_identity_match']
            and case['severity'] >= 8
            and proposal.get('notification') == 'suppress'):
        flags.append('suppression_recommended_despite_security_signal')
    return sorted(flags)


def inspect(case: dict, proposal: Any) -> dict:
    """Use real evidence sanitizer and structural validator. Never echo proposals."""
    if type(case) is not dict or type(proposal) is not dict:
        raise ChallengeInputError('invalid inspection contract')
    facts, _wz, _asset = offline_benchmark._fake_evidence(case)
    available = available_evidence_ids(facts)
    validated = multiaxis_shadow.validate(proposal, facts)
    warnings = _semantic_warnings(case, proposal)
    if facts is None:
        status = 'missing_verified_context'
    elif validated is None:
        status = 'invalid_structure_or_citations'
    elif warnings:
        status = 'review_required'
    else:
        status = 'no_explicit_contradiction_detected'
    sources = {'wazuh'} if available else set()
    for kind in case['cross_signal_kinds']:
        if 'cross.' + kind in available:
            sources.add(SIGNAL_SOURCE[kind])
    return {
        'status': status,
        'cited_ids_structurally_valid': validated is not None,
        'available_evidence_count': len(available),
        'available_sources': sorted(sources),
        'warning_codes': warnings,
        'policy_decision_changed': False,
        'requires_human_review': True,
    }


def report(cases: list[dict], challenges: list[dict]) -> dict:
    known = {c['id']: c for c in cases}
    if len(known) != len(cases):
        raise ChallengeInputError('repeated case identifiers')
    # First establish actual deterministic policy outcomes on the same fixtures.
    policy_report = offline_benchmark.report(cases)
    if policy_report['status'] != 'passed':
        raise ChallengeInputError('baseline regressions failed')
    baseline = {row['id']: row['baseline'] for row in policy_report['cases']}
    counters = Counter()
    warnings = Counter()
    rows = []
    for challenge in challenges:
        ident = challenge['case_id']
        if ident not in known:
            raise ChallengeInputError('unknown synthetic case')
        result = inspect(known[ident], challenge['proposal'])
        counters[result['status']] += 1
        warnings.update(result['warning_codes'])
        rows.append({
            'challenge_id': challenge['id'], 'case_id': ident,
            'baseline_notification_policy': baseline[ident],
            **result,
        })
    return {
        'version': VERSION,
        'provenance': 'fixed_synthetic_challenges_not_model_outputs_or_ground_truth',
        'status': 'completed_offline_review_required',
        'counts': {
            'challenges': len(rows),
            'baseline_regressions_passed': len(cases),
            'no_explicit_contradiction_detected': counters['no_explicit_contradiction_detected'],
            'review_required': counters['review_required'],
            'invalid_structure_or_citations': counters['invalid_structure_or_citations'],
            'missing_verified_context': counters['missing_verified_context'],
        },
        'warning_counts': dict(sorted(warnings.items())),
        'checks': rows,
        'provider_calls': 0, 'database_reads': 0, 'database_writes': 0,
        'notifications_sent': 0, 'policy_changes': 0,
        'model_accuracy_claimed': False,
        'limitations': [
            'Proposals are hand-written synthetic challenges, NOT Gemini responses.',
            'This is a safety consistency audit, NOT a model accuracy or confidence metric.',
            'Valid citations show observation availability; free-text reasons and causality are unverified.',
            'No explicit contradiction detected does NOT imply the recommendation is correct.',
            'Only the live deterministic policy decides actual notification delivery.',
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Offline synthetic multi-axis decision consistency audit')
    parser.add_argument('--cases', default='evaluation/cases_v1.json')
    parser.add_argument('--challenges', default='evaluation/decision_challenges_v1.json')
    args = parser.parse_args(argv)
    try:
        cases = offline_benchmark.load_cases(args.cases)
        challenges = read_challenges(args.challenges, {c['id'] for c in cases})
        result = report(cases, challenges)
    except (ChallengeInputError, offline_benchmark.BenchInputError, OSError,
            ValueError, KeyError, TypeError, AssertionError) as exc:
        parser.exit(2, f'Decision consistency refused ({type(exc).__name__}); no changes made.\n')
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
