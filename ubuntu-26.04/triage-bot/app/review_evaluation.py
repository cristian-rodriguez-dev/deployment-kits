"""Read-only analyst review comparison for synthetic Security Triage benchmarks.

No API key, production database, model call, or alert transport is accessed.
Synthetic fixtures and analyst labels are NOT incident ground truth.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
from typing import Any

VERSION = 'triage-analyst-review-v1'
SCHEMA = 'triage-analyst-labels-v1'
BASELINE_SOURCE = 'offline-triage-benchmark-v1'
LIVE_SOURCE = 'controlled-live-shadow-v1'
SOURCE_PROVENANCE = {
    BASELINE_SOURCE: ('fixture_provenance', 'synthetic_examples_not_ground_truth'),
    LIVE_SOURCE: ('provenance', 'fixed_synthetic_cases_not_ground_truth'),
}
DECISIONS = frozenset({'notify', 'review', 'suppress'})
GROUNDING = frozenset({
    'cited_observations', 'missing_citations', 'invalid_citations',
    'unsupported_citations', 'not_evaluated',
})
REASONS = frozenset({
    'critical_signal', 'verified_pattern', 'likely_benign',
    'insufficient_context', 'other_reviewed_evidence',
})
CASE_RE = re.compile(r'[a-z][a-z0-9-]{2,47}\Z')
MAX_BYTES = 100_000
MAX_CASES = 50


class ReviewInputError(ValueError):
    """Refuse invalid or privacy-risky inputs without repeating their content."""


def _load_json(path: str | Path) -> Any:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ReviewInputError('invalid input file')
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (UnicodeError, ValueError) as exc:
        raise ReviewInputError('invalid input JSON') from exc


def checked_report(report: Any) -> tuple[str, dict[str, dict]]:
    if type(report) is not dict or report.get('version') not in SOURCE_PROVENANCE:
        raise ReviewInputError('unsupported report version')
    version = report['version']
    field, expected = SOURCE_PROVENANCE[version]
    if report.get(field) != expected:
        raise ReviewInputError('report provenance is not synthetic')
    if version == BASELINE_SOURCE and report.get('status') != 'passed':
        raise ReviewInputError('offline regression did not pass')
    if version == LIVE_SOURCE and report.get('mode') not in ('preview_no_network', 'live_synthetic'):
        raise ReviewInputError('unsupported live experiment mode')
    rows = report.get('cases')
    if type(rows) is not list or not 1 <= len(rows) <= MAX_CASES:
        raise ReviewInputError('invalid report cases')
    indexed: dict[str, dict] = {}
    for item in rows:
        if type(item) is not dict:
            raise ReviewInputError('invalid report row')
        ident = item.get('id')
        if type(ident) is not str or not CASE_RE.fullmatch(ident) or ident in indexed:
            raise ReviewInputError('invalid or duplicate case id')
        baseline, shadow = item.get('baseline'), item.get('shadow')
        if baseline not in DECISIONS or (shadow is not None and shadow not in DECISIONS):
            raise ReviewInputError('invalid decision')
        status = item.get('shadow_status')
        if status not in ('evaluated', 'not_evaluated', 'not_executed', 'provider_or_validation_error'):
            raise ReviewInputError('invalid model status')
        grounding = item.get('grounding')
        if grounding not in GROUNDING:
            raise ReviewInputError('invalid grounding status')
        if status != 'evaluated' and shadow is not None:
            raise ReviewInputError('model decision not evaluated')
        if status == 'evaluated' and shadow is None:
            raise ReviewInputError('evaluated decision missing')
        indexed[ident] = {
            'baseline': baseline,
            'shadow': shadow,
            'shadow_status': status,
            'grounding': grounding,
        }
    return version, indexed


def checked_reviews(document: Any, version: str, ids: set[str]) -> dict[str, dict]:
    if (type(document) is not dict or set(document) != {'schema_version', 'report_version', 'reviews'}
            or document['schema_version'] != SCHEMA
            or document['report_version'] != version
            or type(document['reviews']) is not list
            or len(document['reviews']) > len(ids)):
        raise ReviewInputError('review contract mismatch')
    labels: dict[str, dict] = {}
    for record in document['reviews']:
        if type(record) is not dict or set(record) != {'case_id', 'analyst_decision', 'reason_code'}:
            raise ReviewInputError('invalid review fields')
        case_id = record['case_id']
        label = record['analyst_decision']
        reason = record['reason_code']
        if (type(case_id) is not str or case_id not in ids or case_id in labels
                or label not in DECISIONS | {'insufficient_evidence'}
                or reason not in REASONS
                or (label == 'insufficient_evidence') != (reason == 'insufficient_context')):
            raise ReviewInputError('invalid review label, reason or case')
        labels[case_id] = {'label': label, 'reason': reason}
    return labels


def compare(report: Any, reviews: Any) -> dict:
    """Score only independently reviewed cases. Never call result accuracy."""
    version, cases = checked_report(report)
    labels = checked_reviews(reviews, version, set(cases))
    counts: Counter[str] = Counter()
    pairs: Counter[str] = Counter()
    for ident, item in cases.items():
        review = labels.get(ident)
        if review is None:
            counts['unreviewed'] += 1
            continue
        if review['label'] == 'insufficient_evidence':
            counts['human_abstained'] += 1
            continue
        human = review['label']
        counts['reviewed_with_decision'] += 1
        if item['baseline'] == human:
            counts['baseline_agrees_with_reviewer'] += 1
        else:
            counts['baseline_disagrees_with_reviewer'] += 1
        if item['shadow_status'] != 'evaluated':
            counts['shadow_unavailable_on_reviewed'] += 1
            continue
        if item['grounding'] != 'cited_observations':
            counts['shadow_not_grounded_on_reviewed'] += 1
            continue
        counts['shadow_grounded_on_reviewed'] += 1
        if item['shadow'] == human:
            counts['shadow_agrees_with_reviewer'] += 1
        else:
            counts['shadow_disagrees_with_reviewer'] += 1
        if item['baseline'] == human and item['shadow'] != human:
            counts['shadow_worse_than_baseline_on_pairs'] += 1
        if item['baseline'] != human and item['shadow'] == human:
            counts['shadow_better_than_baseline_on_pairs'] += 1
        pairs[f"{item['baseline']}__{item['shadow']}"] += 1
    # Consistently report zero counts; prevents misleading missing keys.
    keys = (
        'unreviewed', 'human_abstained', 'reviewed_with_decision',
        'baseline_agrees_with_reviewer', 'baseline_disagrees_with_reviewer',
        'shadow_unavailable_on_reviewed', 'shadow_not_grounded_on_reviewed',
        'shadow_grounded_on_reviewed', 'shadow_agrees_with_reviewer',
        'shadow_disagrees_with_reviewer', 'shadow_worse_than_baseline_on_pairs',
        'shadow_better_than_baseline_on_pairs',
    )
    return {
        'version': VERSION,
        'status': 'awaiting_human_review' if counts['reviewed_with_decision'] == 0
                  else 'reviewed_sample_only',
        'source_report_version': version,
        'provenance': 'synthetic_cases_with_optional_human_judgments',
        'counts': {'total_cases': len(cases), **{key: counts[key] for key in keys}},
        'decision_pairs_grounded_reviewed_only': dict(sorted(pairs.items())),
        'accuracy_or_recall_claimed': False,
        'policy_changes': 0,
        'provider_calls': 0,
        'database_reads': 0,
        'database_writes': 0,
        'notifications_sent': 0,
        'limitations': [
            'Human review labels express reviewer judgment, not verified incident truth.',
            'All included fixtures are synthetic and are not representative of live attacks.',
            'Only evaluated, evidence-citing shadow responses are compared with reviewers.',
            'Citation grounding verifies supplied identifiers, not whether reasoning is sound.',
            'No changes to triage, notifications, or Gemini prompts are made.',
        ],
    }



def review_queue() -> dict:
    """Only fixed synthetic evidence; deliberately hide both competing decisions."""
    from app import live_shadow_benchmark
    source = live_shadow_benchmark.fixed_cases()
    allowed = (
        'severity', 'synthetic_event', 'recent_count', 'agent_identity_match',
        'rule_groups', 'mitre_ids', 'cross_signal_kinds',
        'sequence_observations', 'group_observations', 'group_peak_level',
    )
    return {
        'version': 'triage-review-queue-v1',
        'provenance': 'fixed_synthetic_cases_not_ground_truth',
        'blind_to_policy_and_shadow_decisions': True,
        'cases': [{'id': ident, **{field: case[field] for field in allowed}}
                  for ident, case in source.items()],
        'instructions': 'Review only synthetic evidence before opening baseline or AI proposals.',
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Offline reviewer comparison; synthetic cases only')
    parser.add_argument('--queue', action='store_true', help='show blind synthetic evidence queue')
    parser.add_argument('--report', help='saved synthetic benchmark JSON (optional)')
    parser.add_argument('--reviews', default='evaluation/reviews_template_v1.json')
    args = parser.parse_args(argv)
    try:
        if args.queue and args.report:
            raise ReviewInputError('queue does not accept external reports')
        if args.queue:
            print(json.dumps(review_queue(), ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        if args.report:
            source = _load_json(args.report)
        else:
            from app import live_shadow_benchmark, offline_benchmark
            cases = list(live_shadow_benchmark.fixed_cases().values())
            source = offline_benchmark.report(cases)
        result = compare(source, _load_json(args.reviews))
    except (ReviewInputError, OSError, ValueError, KeyError, TypeError, AssertionError) as exc:
        parser.exit(2, f'Analyst review refused ({type(exc).__name__}); no changes made.\n')
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
