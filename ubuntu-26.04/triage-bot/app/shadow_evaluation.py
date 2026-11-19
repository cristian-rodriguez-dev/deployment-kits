"""Aggregate-only, offline report for advisory Gemini decisions.

Runs on existing SQLite data in read-only mode. No API access, no AI calls,
no notifications, and no output of incident content, identities or prompts.
Agreement with existing policy is NOT an accuracy or detection-quality metric.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import sqlite3

DECISIONS = frozenset({'notify', 'review', 'suppress'})
GROUNDING = frozenset({'cited_observations', 'missing_citations',
                       'invalid_citations', 'unsupported_citations'})


def summarize(path: str | Path, limit: int = 200) -> dict:
    """Read at most `limit` newest real Wazuh incidents without any writes."""
    if type(limit) is not int or not 1 <= limit <= 5000:
        raise ValueError('limit must be between 1 and 5000')
    db_path = Path(path).expanduser().resolve(strict=True)
    if not db_path.is_file():
        raise ValueError('SQLite database is not a file')
    uri = db_path.as_uri() + '?mode=ro'
    counts: Counter[str] = Counter()
    decisions: Counter[str] = Counter()
    grounding: Counter[str] = Counter()
    # Opening mode=ro avoids creating the DB and prevents all writes.
    with sqlite3.connect(uri, uri=True, timeout=5) as db:
        rows = db.execute('''SELECT analysis FROM incidents
                             WHERE source='wazuh' AND synthetic=0
                             ORDER BY id DESC LIMIT ?''', (limit,)).fetchall()
    counts['real_wazuh_rows'] = len(rows)
    for (raw,) in rows:
        if type(raw) is not str or len(raw) > 250_000:
            counts['invalid_analysis'] += 1
            continue
        try:
            incident = json.loads(raw)
        except (ValueError, TypeError):
            counts['invalid_analysis'] += 1
            continue
        if not isinstance(incident, dict):
            counts['invalid_analysis'] += 1
            continue
        shadow = incident.get('ai_decision_shadow')
        if not isinstance(shadow, dict):
            counts['without_shadow'] += 1
            continue
        counts['shadow_present'] += 1
        if (shadow.get('version') != 'ai-decision-shadow-v1'
                or shadow.get('changes_triage') is not False
                or shadow.get('changes_notifications') is not False
                or shadow.get('automatic_actions') is not False):
            counts['invalid_shadow_contract'] += 1
            continue
        if shadow.get('status') == 'not_evaluated':
            counts['not_evaluated'] += 1
            continue
        if shadow.get('status') != 'evaluated':
            counts['invalid_shadow_contract'] += 1
            continue
        actual = shadow.get('actual_decision')
        proposed = shadow.get('proposed_decision')
        if actual not in DECISIONS or proposed not in DECISIONS:
            counts['invalid_shadow_contract'] += 1
            continue
        triage = incident.get('triage')
        if isinstance(triage, dict) and triage.get('decision') in DECISIONS:
            if actual != triage['decision']:
                counts['invalid_shadow_contract'] += 1
                continue
        differs = shadow.get('differs_from_current')
        if differs is not None and (type(differs) is not bool or differs != (actual != proposed)):
            counts['invalid_shadow_contract'] += 1
            continue
        counts['evaluated'] += 1
        if actual == proposed:
            counts['agreement'] += 1
        else:
            counts['disagreement'] += 1
        if actual == 'notify' and proposed == 'suppress':
            counts['notify_to_suppress_proposal'] += 1
        decisions[f'{actual}__{proposed}'] += 1
        quality = shadow.get('evidence_grounding')
        status = quality.get('status') if isinstance(quality, dict) else None
        if status not in GROUNDING:
            status = 'not_recorded'
        grounding[status] += 1
    return {
        'version': 'shadow-evaluation-readonly-v1',
        'scope': 'newest_real_wazuh_incidents_only',
        'sample_limit': limit,
        'counts': dict(sorted(counts.items())),
        'decision_pairs': dict(sorted(decisions.items())),
        'grounding': dict(sorted(grounding.items())),
        'limitations': [
            'Agreement is not accuracy; no ground truth or analyst labels.',
            'Newer incidents are not a representative random sample.',
            'Unevaluated cases are not model mistakes or negative detections.',
            'Cited observation IDs do not verify free-text reasons or causality.',
            'No automatic policy changes or notification suppression.',
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Read-only, aggregate AI shadow evaluation')
    parser.add_argument('--db', default=os.getenv('DB_PATH', '/data/incidents.db'),
                        help='SQLite incidents DB; default: DB_PATH')
    parser.add_argument('--limit', type=int, default=200, help='1..5000 recent Wazuh rows')
    args = parser.parse_args(argv)
    try:
        result = summarize(args.db, args.limit)
    except (OSError, ValueError, sqlite3.Error) as exc:
        # No private path values or exception details in stdout/stderr.
        parser.exit(2, f'Report unavailable ({type(exc).__name__}); no changes made.\n')
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
