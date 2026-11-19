"""Opt-in, bounded Gemini experiment on *fixed synthetic* cases only.

This tool never reads incident databases, changes production policy or sends
notifications. A dry-run is the default. Live execution requires multiple
explicit gates and a secret mounted as a read-only file.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re
import stat
import time
from typing import Callable

from app import ai_decision_shadow, contextual_analysis
from app.offline_benchmark import _fake_evidence, load_cases
from app.triage_policy import assess, hard_critical_source

VERSION = 'controlled-live-shadow-v1'
FIXTURE_HASH = 'fcdcc052042ca019cf5870cc9f8f1bba1f97de5f90b2c3fd3119cef9ccc0e65e'
FIXTURE_FILE = Path(__file__).resolve().parents[1] / 'evaluation' / 'cases_v1.json'
KEY_FILE = Path('/run/secrets/gemini_key')
DEFAULT_CASES = (
    'critical-model-tries-suppress',
    'verified-loki-volume-not-login',
    'wazuh-sequence-and-group-growth',
)
MAX_CALLS = 3
_MODEL = re.compile(r'gemini-[a-z0-9.-]{1,60}\Z')
_KEY = re.compile(r'(?:[A-Za-z0-9_-]{20,180}|AQ\.[A-Za-z0-9_-]{17,177})\Z')


class ControlledBenchmarkError(ValueError):
    pass


def fixed_cases() -> dict[str, dict]:
    if not FIXTURE_FILE.is_file() or sha256(FIXTURE_FILE.read_bytes()).hexdigest() != FIXTURE_HASH:
        raise ControlledBenchmarkError('fixed fixture integrity check failed')
    return {case['id']: case for case in load_cases(FIXTURE_FILE)}


def select_cases(data: dict[str, dict], case_ids: list[str]) -> list[dict]:
    if not (1 <= len(case_ids) <= MAX_CALLS) or len(set(case_ids)) != len(case_ids):
        raise ControlledBenchmarkError('invalid requested call count or duplicate case')
    cases = []
    for key in case_ids:
        case = data.get(key)
        if (case is None or case['mode'] != 'gemini'
                or case['synthetic_event'] is not False or not case['agent_identity_match']):
            raise ControlledBenchmarkError('not a permitted synthetic fixture for live comparison')
        cases.append(case)
    return cases


def read_key(path: Path = KEY_FILE) -> str:
    # No environment variable, command-line API key, or production .env parsing.
    if path.is_symlink() or not path.is_file():
        raise ControlledBenchmarkError('read-only Gemini secret file not available')
    item = path.stat()
    if (not stat.S_ISREG(item.st_mode) or item.st_size > 256 or item.st_size < 20
            or item.st_mode & 0o077):
        raise ControlledBenchmarkError('secret must be a restricted regular file')
    secret = path.read_text(encoding='ascii').strip()
    if not _KEY.fullmatch(secret):
        raise ControlledBenchmarkError('invalid secret format')
    return secret


def baseline_for(case: dict) -> tuple[str, dict, dict, dict]:
    baseline_analysis = deepcopy(case['primary_analysis'])
    policy = assess('wazuh', 'Simulated Wazuh alert', str(case['severity']),
           case['synthetic_event'], case['mode'], baseline_analysis,
           {'host': 'fixture-node', 'rule_key': '5763', 'category': 'security'},
           case['recent_count'])
    facts, wazuh, asset = _fake_evidence(case)
    if not ai_decision_shadow.validated_for_model(facts):
        raise ControlledBenchmarkError('synthetic facts do not pass production validation')
    return policy['decision'], facts, wazuh, asset


def execute(cases: list[dict], *, live: bool, confirmed: bool,
            model: str | None, key_path: Path = KEY_FILE,
            interpreter: Callable = contextual_analysis.interpret) -> dict:
    # No key read, API client, or network call in preview mode.
    if live and not confirmed:
        raise ControlledBenchmarkError('live mode requires explicit synthetic-data confirmation')
    if live and (type(model) is not str or not _MODEL.fullmatch(model)):
        raise ControlledBenchmarkError('specify a valid Gemini model identifier')
    if not 1 <= len(cases) <= MAX_CALLS:
        raise ControlledBenchmarkError('call budget exceeded')
    prepared = []
    for case in cases:
        baseline, facts, wazuh, asset = baseline_for(case)
        prepared.append((case, baseline, facts, wazuh, asset))
    report = {
        'version': VERSION, 'mode': 'live_synthetic' if live else 'preview_no_network',
        'provenance': 'fixed_synthetic_cases_not_ground_truth',
        'model': model if live else None,
        'maximum_provider_requests': MAX_CALLS if live else 0,
        'attempted_provider_requests': 0,
        'database_reads': 0, 'database_writes': 0, 'notifications_sent': 0,
        'production_decisions_changed': 0,
        'cases': [],
        'limitations': [
            'Synthetic scenarios are NOT incident ground truth.',
            'Agreement with the baseline is NOT evidence of accuracy.',
            'Citation IDs prove only that an observation was supplied, not causality.',
            'Model output may vary between runs; do not auto-change alert policies.',
            'The experiment does not replay the full live production pipeline.',
        ],
    }
    secret = read_key(key_path) if live else None
    decision_pairs = Counter()
    grounding = Counter()
    for case, baseline, facts, wazuh, asset in prepared:
        row = {'id': case['id'], 'baseline': baseline, 'shadow': None,
               'shadow_status': 'not_executed' if not live else 'not_evaluated',
               'grounding': 'not_evaluated', 'provider_request_attempted': False}
        if live:
            start = time.monotonic()
            row['provider_request_attempted'] = True
            report['attempted_provider_requests'] += 1
            try:
                result = interpreter(None, 'wazuh', 'security', secret, model,
                                     timeout=8, wazuh_context=wazuh,
                                     asset=asset, shadow_facts=facts)
                gated = ai_decision_shadow.compare(result, baseline, facts)
                row['shadow'] = gated.get('proposed_decision')
                row['shadow_status'] = gated['status']
                row['grounding'] = gated.get('evidence_grounding', {}).get('status', 'not_evaluated')
                if row['shadow_status'] == 'evaluated':
                    decision_pairs[baseline + '__' + row['shadow']] += 1
                grounding[row['grounding']] += 1
                # Policy remains unchanged; never return/free-text model reasoning.
                if hard_critical_source('wazuh', str(case['severity'])) and baseline != 'notify':
                    raise ControlledBenchmarkError('critical safety invariant failed')
            except ControlledBenchmarkError:
                raise
            except Exception as exc:
                # No API response/body/secret/HTTP headers ever printed.
                row['shadow_status'] = 'provider_or_validation_error'
                row['error_type'] = type(exc).__name__[:55]
            row['latency_ms'] = int((time.monotonic() - start) * 1000)
        report['cases'].append(row)
    report['decision_pairs'] = dict(sorted(decision_pairs.items()))
    report['grounding'] = dict(sorted(grounding.items()))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Synthetic-only, opt-in Gemini shadow trial')
    parser.add_argument('--live', action='store_true', help='allow limited external Gemini calls')
    parser.add_argument('--confirm-send-synthetic', action='store_true',
                        help='explicitly confirm that sanitized synthetic data may be transmitted')
    parser.add_argument('--model', help='Gemini model (required for --live)')
    parser.add_argument('--case', action='append', help='choose permitted synthetic case; maximum 3')
    args = parser.parse_args(argv)
    try:
        cases = select_cases(fixed_cases(), args.case or list(DEFAULT_CASES))
        result = execute(cases, live=args.live, confirmed=args.confirm_send_synthetic,
                         model=args.model)
    except (ControlledBenchmarkError, OSError, ValueError, KeyError, TypeError) as exc:
        # Reject without repeating file, API or untrusted message contents.
        parser.exit(2, f'Controlled benchmark refused ({type(exc).__name__}); no production changes.\n')
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
