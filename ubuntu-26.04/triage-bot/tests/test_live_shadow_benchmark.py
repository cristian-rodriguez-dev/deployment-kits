"""Controlled experiment tests; all provider calls are fakes."""
import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app import live_shadow_benchmark as trial


class ControlledGeminiTrialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = trial.fixed_cases()
        cls.cases = trial.select_cases(cls.data, list(trial.DEFAULT_CASES))

    def test_fixed_fixture_integrity_and_exact_three(self):
        self.assertEqual(len(self.cases), 3)
        self.assertEqual(len(self.data), 13)

    def test_dry_run_without_key_or_network(self):
        with (patch.object(trial, 'read_key', side_effect=AssertionError('key read')),
              patch.object(trial.contextual_analysis, 'interpret', side_effect=AssertionError('network'))):
            report = trial.execute(self.cases, live=False, confirmed=False, model=None)
        self.assertEqual(report['attempted_provider_requests'], 0)
        self.assertEqual(report['mode'], 'preview_no_network')
        self.assertEqual(report['production_decisions_changed'], 0)
        self.assertEqual(report['database_writes'], 0)
        self.assertEqual(report['notifications_sent'], 0)

    def test_live_requires_explicit_confirmation(self):
        with self.assertRaises(trial.ControlledBenchmarkError):
            trial.execute(self.cases, live=True, confirmed=False, model='gemini-2.5-flash')

    def test_model_identifier_is_validated(self):
        for name in (None, '', 'other', 'gemini-2.5-flash/../../secret', 'gemini-2.5-flash?x=1'):
            with self.subTest(name=name), self.assertRaises(trial.ControlledBenchmarkError):
                trial.execute(self.cases, live=True, confirmed=True, model=name)

    def test_no_duplicates_or_more_than_three(self):
        with self.assertRaises(trial.ControlledBenchmarkError):
            trial.select_cases(self.data, list(trial.DEFAULT_CASES) + ['medium-uncertain-review'])
        with self.assertRaises(trial.ControlledBenchmarkError):
            trial.select_cases(self.data, [trial.DEFAULT_CASES[0]] * 2)

    def test_only_known_verified_synthetic_examples(self):
        for name in ('unverified-agent-must-fail-closed', 'synthetic-critical-never-notify',
                     'does-not-exist', 'high-level-without-ai'):
            with self.subTest(name=name), self.assertRaises(trial.ControlledBenchmarkError):
                trial.select_cases(self.data, [name])

    def test_rejects_modified_case_fixture(self):
        with patch.object(trial, 'FIXTURE_HASH', '0' * 64):
            with self.assertRaises(trial.ControlledBenchmarkError):
                trial.fixed_cases()

    def test_fake_live_provider_records_pairs_and_preserves_policy(self):
        def fake_interpret(telemetry, source, family, key, model, **kwargs):
            self.assertIsNone(telemetry)
            self.assertEqual(source, 'wazuh')
            self.assertEqual(family, 'security')
            self.assertEqual(key, 'test-key')
            self.assertEqual(model, 'gemini-2.5-flash')
            self.assertEqual(kwargs['timeout'], 8)
            facts = kwargs['shadow_facts']
            citations = trial.ai_decision_shadow.available_evidence_ids(facts)
            self.assertIn('wazuh.rule_level', citations)
            return {'shadow_recommendation': {
                'decision': 'suppress', 'classification': 'suspicious',
                'priority': 'low', 'false_positive': 'likely',
                'confidence': 'low', 'reason': 'Synthetic proposal',
                'supporting_evidence_ids': ['wazuh.rule_level']}}
        with patch.object(trial, 'read_key', return_value='test-key'):
            report = trial.execute(self.cases, live=True, confirmed=True,
                                   model='gemini-2.5-flash', interpreter=fake_interpret)
        self.assertEqual(report['attempted_provider_requests'], 3)
        self.assertEqual(report['decision_pairs']['notify__suppress'], 2)
        self.assertEqual(report['grounding']['cited_observations'], 3)
        self.assertEqual(report['cases'][0]['baseline'], 'notify')
        self.assertEqual(report['cases'][0]['shadow'], 'suppress')
        self.assertEqual(report['production_decisions_changed'], 0)
        self.assertEqual(report['notifications_sent'], 0)
        self.assertNotIn('Synthetic proposal', json.dumps(report))
        self.assertNotIn('test-key', json.dumps(report))

    def test_provider_error_is_bounded_redacted(self):
        def bad_provider(*_, **__):
            raise RuntimeError('private token printed in exception')
        with patch.object(trial, 'read_key', return_value='test-key'):
            report = trial.execute(self.cases[:1], live=True, confirmed=True,
                                   model='gemini-2.5-flash', interpreter=bad_provider)
        text = json.dumps(report)
        self.assertEqual(report['cases'][0]['shadow_status'], 'provider_or_validation_error')
        self.assertNotIn('private token', text)
        self.assertEqual(report['cases'][0]['error_type'], 'RuntimeError')

    def test_secret_file_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'key'
            path.write_text('Abcdefghijklmnopqrstuvwxyz12345678', encoding='ascii')
            path.chmod(0o600)
            self.assertEqual(len(trial.read_key(path)), 34)
            path.chmod(0o644)
            with self.assertRaises(trial.ControlledBenchmarkError):
                trial.read_key(path)


    def test_gemini_auth_key_with_dot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "key"
            valid = "AQ." + "A" * 50
            path.write_text(valid, encoding="ascii")
            path.chmod(0o600)

            self.assertEqual(trial.read_key(path), valid)

            path.write_text("invalid." + "A" * 50, encoding="ascii")
            with self.assertRaises(trial.ControlledBenchmarkError):
                trial.read_key(path)

    def test_symlink_secret_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / 'key'
            secret.write_text('Abcdefghijklmnopqrstuvwxyz12345678', encoding='ascii')
            secret.chmod(0o600)
            alias = Path(directory) / 'alias'
            alias.symlink_to(secret)
            with self.assertRaises(trial.ControlledBenchmarkError):
                trial.read_key(alias)

    def test_preview_command_only(self):
        with (patch.object(trial, 'read_key', side_effect=AssertionError('key read')),
              patch.object(trial.contextual_analysis, 'interpret', side_effect=AssertionError('network')),
              contextlib.redirect_stdout(io.StringIO()) as output):
            self.assertEqual(trial.main([]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result['mode'], 'preview_no_network')
        self.assertEqual(result['attempted_provider_requests'], 0)

    def test_cli_live_gate(self):
        with self.assertRaises(SystemExit) as result:
            trial.main(['--live', '--model', 'gemini-2.5-flash'])
        self.assertEqual(result.exception.code, 2)

    def test_invalid_fact_cannot_reach_provider(self):
        bad = deepcopy(self.cases[0])
        bad['agent_identity_match'] = False
        with patch.object(trial, 'read_key', side_effect=AssertionError('key read')):
            with self.assertRaises(trial.ControlledBenchmarkError):
                trial.execute([bad], live=False, confirmed=False, model=None)

    def test_report_never_contains_raw_facts(self):
        report = trial.execute(self.cases, live=False, confirmed=False, model=None)
        report_string = json.dumps(report)
        for value in ('fixture-node', 'agent_id', '5763', 'raw_logs', 'password'):
            self.assertNotIn(value, report_string)


if __name__ == '__main__':
    unittest.main()
