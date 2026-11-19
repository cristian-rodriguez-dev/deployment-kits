"""Read-only multi-axis *advisory* and synthetic-review comparison.

No changes to triage_policy, notification dispatch, model prompts, or SQLite.
Legacy review/notify/suppress predictions cannot express all independent axes:
we use explicit 'undetermined', never impute an independent AI judgement.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
from typing import Any

from app import review_evaluation as legacy

VERSION = 'triage-multiaxis-review-v1'
SCHEMA = 'triage-analyst-multiaxis-v1'
NOTIFICATIONS = frozenset({'notify', 'hold', 'suppress', 'undetermined'})
INVESTIGATIONS = frozenset({'required', 'not_required', 'undetermined'})
EVIDENCE_STATES = frozenset({'suspicious_unconfirmed', 'benign_supported', 'unknown'})
AXES = ('notification', 'investigation')
# There is no direct proof of compromise among the fixed synthetic fixtures.
# A 'confirmed_compromise' label is intentionally NOT supported.


def project_legacy(decision: str | None) -> dict:
    """Map *only* what a v1 label actually says, without inventing a second axis."""
    if decision == 'notify':
        return {'notification': 'notify', 'investigation': 'undetermined'}
    if decision == 'review':
        return {'notification': 'undetermined', 'investigation': 'required'}
    if decision == 'suppress':
        return {'notification': 'suppress', 'investigation': 'undetermined'}
    return {'notification': 'undetermined', 'investigation': 'undetermined'}


def checked_multiaxis_reviews(document: Any, version: str, ids: set[str]) -> dict[str, dict]:
    """Strict allow-list schema. Unknown is legitimate and excluded from that axis's score."""
    if (type(document) is not dict
            or set(document) != {'schema_version', 'report_version', 'reviews'}
            or document['schema_version'] != SCHEMA
            or document['report_version'] != version
            or type(document['reviews']) is not list
            or len(document['reviews']) > len(ids)):
        raise legacy.ReviewInputError('multiaxis review contract mismatch')
    labels = {}
    for record in document['reviews']:
        if type(record) is not dict or set(record) != {
                'case_id', 'notification', 'investigation', 'evidence_state', 'reason_code'}:
            raise legacy.ReviewInputError('invalid multiaxis fields')
        ident = record['case_id']
        if (type(ident) is not str or ident not in ids or ident in labels
                or type(record['notification']) is not str
                or record['notification'] not in NOTIFICATIONS
                or type(record['investigation']) is not str
                or record['investigation'] not in INVESTIGATIONS
                or type(record['evidence_state']) is not str
                or record['evidence_state'] not in EVIDENCE_STATES
                or type(record['reason_code']) is not str
                or record['reason_code'] not in legacy.REASONS):
            raise legacy.ReviewInputError('invalid multiaxis review values')
        # An empty pair can be retained from a human abstention, not counted as an error.
        labels[ident] = {key: record[key] for key in (
            'notification', 'investigation', 'evidence_state', 'reason_code')}
    return labels


def migrate_legacy(document: Any, report_version: str, ids: set[str]) -> dict:
    """No auto-upgrading human conclusions: preserve only explicitly expressed axes.

    The user may subsequently add a second, *independently reviewed* axis.
    """
    labels = legacy.checked_reviews(document, report_version, ids)
    rows = []
    for ident, label in sorted(labels.items()):
        decision = label['label']
        converted = project_legacy(decision)
        rows.append({
            'case_id': ident,
            **converted,
            'evidence_state': 'unknown',
            'reason_code': label['reason'],
        })
    return {
        'schema_version': SCHEMA,
        'report_version': report_version,
        'reviews': rows,
    }


def advisory(case: dict, baseline: str) -> dict:
    """Evidence-aware, *non-operative* deterministic advisor for fixed Wazuh fixtures.

    The notification axis is the actual policy decision, not a new policy.
    Investigation is independently recommended only for a known agent with
    explicit observed severity/recurrence/sequence/cross-source flags.
    Absence of information never means a known-benign event.
    """
    if baseline not in legacy.DECISIONS or type(case) is not dict:
        raise legacy.ReviewInputError('invalid advisory input')
    notification = {'notify': 'notify', 'review': 'hold', 'suppress': 'suppress'}[baseline]
    synthetic = case.get('synthetic_event')
    identity = case.get('agent_identity_match')
    severity = case.get('severity')
    recurrence = case.get('recent_count')
    peak = case.get('group_peak_level')
    if (type(synthetic) is not bool or type(identity) is not bool
            or type(severity) is not int or not 0 <= severity <= 16
            or type(recurrence) is not int or not 1 <= recurrence <= 50
            or (peak is not None and (type(peak) is not int or not severity <= peak <= 16))):
        raise legacy.ReviewInputError('invalid advisory evidence')
    signals = ('cross_signal_kinds', 'sequence_observations', 'group_observations')
    if any(type(case.get(key)) is not list or len(case[key]) > 5
           or any(type(v) is not str for v in case[key]) for key in signals):
        raise legacy.ReviewInputError('invalid advisory signals')
    # No claims of successful SSH login or compromise can be derived here.
    concerning = (severity >= 12 or (peak is not None and peak >= 12)
                  or recurrence >= 3 or any(case[key] for key in signals))
    if synthetic:
        # Even severe synthetic fixtures are never deliverable notifications.
        notification = 'suppress'
    elif severity >= 12 and notification != 'notify':
        raise legacy.ReviewInputError('source critical protection mismatch')
    investigation = ('required' if identity and concerning
                     else 'undetermined')
    evidence_state = ('suspicious_unconfirmed' if identity and concerning
                      else 'unknown')
    return {
        'notification': notification,
        'investigation': investigation,
        'evidence_state': evidence_state,
        'source': 'policy_plus_verified_synthetic_observations',
    }


def compare(report: Any, reviews: Any, fixtures: dict[str, dict]) -> dict:
    """Compare dimensions separately; never infer investigation from 'notify'."""
    version, cases = legacy.checked_report(report)
    labels = checked_multiaxis_reviews(reviews, version, set(cases))
    if (type(fixtures) is not dict or set(cases) - set(fixtures)):
        raise legacy.ReviewInputError('synthetic fixture ids not available')
    counts: Counter[str] = Counter()
    matrix: dict[str, Counter[str]] = {axis: Counter() for axis in AXES}
    per_case: list[dict] = []
    for ident, case in cases.items():
        human = labels.get(ident)
        if human is None:
            counts['unreviewed'] += 1
            continue
        counts['reviewed'] += 1
        advice = advisory(fixtures[ident], case['baseline'])
        projected = (project_legacy(case['shadow']) if
                     case['shadow_status'] == 'evaluated'
                     and case['grounding'] == 'cited_observations'
                     else project_legacy(None))
        row = {'id': ident, 'analyst': {
            'notification': human['notification'],
            'investigation': human['investigation'],
            'evidence_state': human['evidence_state'],
        }, 'advisory': {k: advice[k] for k in ('notification', 'investigation', 'evidence_state')},
               'shadow_legacy_projection': projected}
        for axis in AXES:
            label = human[axis]
            if label == 'undetermined':
                counts[f'{axis}_human_abstentions'] += 1
                continue
            counts[f'{axis}_human_labeled'] += 1
            matrix[axis][f'analyst_{label}__advisory_{advice[axis]}'] += 1
            if advice[axis] == label:
                counts[f'{axis}_advisory_agrees'] += 1
            else:
                counts[f'{axis}_advisory_disagrees'] += 1
            # Only grounded model replies enter shadow comparison.
            if case['shadow_status'] == 'evaluated' and case['grounding'] == 'cited_observations':
                if projected[axis] == 'undetermined':
                    counts[f'{axis}_shadow_axis_not_expressed'] += 1
                else:
                    counts[f'{axis}_shadow_axis_comparable'] += 1
                    if projected[axis] == label:
                        counts[f'{axis}_shadow_agrees'] += 1
                    else:
                        counts[f'{axis}_shadow_disagrees'] += 1
            else:
                counts[f'{axis}_shadow_not_evaluable'] += 1
        if human['evidence_state'] != 'unknown':
            counts['evidence_state_human_labeled'] += 1
            if advice['evidence_state'] == human['evidence_state']:
                counts['evidence_state_advisory_agrees'] += 1
            else:
                counts['evidence_state_advisory_disagrees'] += 1
        # No fabricated AI evidence-state score: old AI response has no such axis.
        per_case.append(row)
    keys = [
        'reviewed', 'unreviewed', 'evidence_state_human_labeled',
        'evidence_state_advisory_agrees', 'evidence_state_advisory_disagrees',
    ]
    for axis in AXES:
        keys.extend(f'{axis}_{item}' for item in (
            'human_labeled', 'human_abstentions', 'advisory_agrees',
            'advisory_disagrees', 'shadow_axis_not_expressed',
            'shadow_axis_comparable', 'shadow_agrees', 'shadow_disagrees',
            'shadow_not_evaluable',
        ))
    return {
        'version': VERSION,
        'source_report_version': version,
        'status': 'awaiting_human_review' if not labels else 'reviewed_sample_only',
        'provenance': 'fixed_synthetic_cases_not_ground_truth',
        'counts': {'total_cases': len(cases), **{k: counts[k] for k in keys}},
        'comparisons': {k: dict(sorted(v.items())) for k, v in matrix.items()},
        'reviewed_cases': per_case,
        'accuracy_or_recall_claimed': False,
        'provider_calls': 0, 'database_reads': 0, 'database_writes': 0,
        'notifications_sent': 0, 'policy_changes': 0,
        'limitations': [
            'Synthetic fixtures and analyst judgments are not verified incident ground truth.',
            'Notification and investigation are independent: legacy review means no notification conclusion.',
            'Legacy model replies express one action only. All absent axes remain undetermined.',
            'The advisory is an offline deterministic projection, not active production policy.',
            'No model is asked for a native multidimensional response in this block.',
            'No evidence here proves compromise, attack causality, precision or recall.',
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='Read-only synthetic multi-axis review comparison')
    p.add_argument('--migrate', metavar='OLD_REVIEWS', help='print a conservative v1 conversion to stdout')
    p.add_argument('--reviews', default='evaluation/reviews_multiaxis_template_v1.json')
    p.add_argument('--report', help='optional saved synthetic benchmark report')
    args = p.parse_args(argv)
    try:
        from app import live_shadow_benchmark, offline_benchmark
        fixtures = live_shadow_benchmark.fixed_cases()
        source = legacy._load_json(args.report) if args.report else offline_benchmark.report(list(fixtures.values()))
        report_version, cases = legacy.checked_report(source)
        if args.migrate:
            result = migrate_legacy(legacy._load_json(args.migrate), report_version, set(cases))
        else:
            result = compare(source, legacy._load_json(args.reviews), fixtures)
    except (legacy.ReviewInputError, OSError, ValueError, TypeError, KeyError, AssertionError) as exc:
        p.exit(2, f'Multiaxis evaluation refused ({type(exc).__name__}); no changes made.\n')
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
