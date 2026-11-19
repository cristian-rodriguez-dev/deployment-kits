"""Block 12: offline safety evaluation. No Gemini, Docker, SQL or notifications."""
import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from app import offline_benchmark as bench

CASES = Path(__file__).resolve().parents[1] / 'evaluation' / 'cases_v1.json'


class SyntheticBenchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = bench.load_cases(CASES)
        cls.results = bench.report(cls.cases)
        cls.by_id = {item['id']: item for item in cls.results['cases']}

    def test_all_fixture_cases_valid_and_unique(self):
        self.assertEqual(len(self.cases), 13)
        self.assertEqual(len(self.by_id), 13)
        self.assertEqual(self.results['status'], 'passed')
        self.assertEqual(self.results['counts']['cases'], 13)

    def test_uses_actual_policy_and_shadow_gate(self):
        with patch.object(bench, 'assess', wraps=bench.assess) as real_policy:
            with patch.object(bench.ai_decision_shadow, 'compare',
                              wraps=bench.ai_decision_shadow.compare) as real_shadow:
                bench.run_case(self.cases[0])
        real_policy.assert_called_once()
        real_shadow.assert_called_once()

    def test_real_critical_protected_from_shadow_suppress(self):
        row = self.by_id['critical-model-tries-suppress']
        self.assertEqual(row['baseline'], 'notify')
        self.assertEqual(row['shadow'], 'suppress')
        self.assertTrue(row['protected'])
        self.assertEqual(self.results['counts']['critical_suppress_proposed_but_not_applied'], 1)

    def test_high_fallback_still_notifies_without_ai(self):
        row = self.by_id['high-level-without-ai']
        self.assertEqual(row['baseline'], 'notify')
        self.assertEqual(row['shadow_status'], 'not_evaluated')

    def test_synthetic_is_suppressed_even_when_critical(self):
        row = self.by_id['synthetic-critical-never-notify']
        self.assertEqual(row['baseline'], 'suppress')
        self.assertEqual(row['shadow_status'], 'not_evaluated')

    def test_missing_proposal_does_not_turn_into_approval(self):
        row = self.by_id['missing-shadow-proposal']
        self.assertEqual(row['shadow_status'], 'not_evaluated')
        self.assertIsNone(row['shadow'])

    def test_unverified_agent_has_no_shadow_context(self):
        row = self.by_id['unverified-agent-must-fail-closed']
        self.assertEqual(row['shadow_status'], 'not_evaluated')
        self.assertIsNone(row['shadow'])

    def test_unobserved_loki_citation_is_rejected(self):
        row = self.by_id['invented-loki-citation']
        self.assertEqual(row['grounding'], 'unsupported_citations')
        self.assertTrue(row['protected'])

    def test_duplicate_citations_are_invalid(self):
        row = self.by_id['duplicated-citation-invalid']
        self.assertEqual(row['grounding'], 'invalid_citations')

    def test_correlated_signal_citation_is_present_but_not_attack_proof(self):
        row = self.by_id['verified-loki-volume-not-login']
        self.assertEqual(row['grounding'], 'cited_observations')
        self.assertTrue(any('do not validate causal' in x
                            for x in self.results['limitations']))

    def test_sequence_and_group_input_replay(self):
        row = self.by_id['wazuh-sequence-and-group-growth']
        self.assertEqual(row['baseline'], 'notify')
        self.assertEqual(row['shadow'], 'notify')
        self.assertEqual(row['grounding'], 'cited_observations')

    def test_all_expects_match_without_claiming_accuracy(self):
        self.assertEqual(self.results['counts']['policy_expectation_met'], 13)
        self.assertEqual(self.results['counts']['grounding_expectation_met'], 13)
        text = json.dumps(self.results)
        self.assertNotIn('accuracy_rate', text)
        self.assertNotIn('precision', text)
        self.assertIn('NOT analyst ground truth', text)

    def test_report_does_not_expose_identifiers_or_canned_reason(self):
        text = json.dumps(self.results)
        self.assertNotIn('fixture-node', text)
        self.assertNotIn('offline-not-real-key', text)
        self.assertNotIn('Simulated recommendation', text)
        self.assertNotIn('5763', text)
        self.assertEqual(self.results['network_requests'], 0)
        self.assertEqual(self.results['database_reads'], 0)
        self.assertEqual(self.results['database_writes'], 0)
        self.assertEqual(self.results['notifications_sent'], 0)

    def test_no_database_connection_even_during_replay(self):
        with patch.object(sqlite3, 'connect', side_effect=AssertionError('DB forbidden')):
            row = bench.run_case(self.cases[0])
        self.assertEqual(row['baseline'], 'notify')

    def test_input_and_analysis_are_not_modified(self):
        data = deepcopy(self.cases[0])
        bench.run_case(data)
        self.assertEqual(data, self.cases[0])

    def test_deviation_from_expectation_fails_benchmark(self):
        cases = deepcopy(self.cases)
        cases[0]['expected_policy_decision'] = 'suppress'
        report = bench.report(cases)
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['counts']['policy_expectation_failed'], 1)

    def test_grounding_mismatch_fails_benchmark(self):
        cases = deepcopy(self.cases)
        cases[0]['expected_grounding'] = 'unsupported_citations'
        report = bench.report(cases)
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['counts']['grounding_expectation_failed'], 1)

    def test_command_line_prints_only_aggregate_and_returns_zero(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = bench.main(['--cases', str(CASES)])
        self.assertEqual(rc, 0)
        result = json.loads(out.getvalue())
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['counts']['cases'], 13)

    def test_file_size_and_provenance_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / 'cases.json'
            file.write_text(' ' * (bench.MAX_FILE_BYTES + 1))
            with self.assertRaises(bench.BenchInputError):
                bench.load_cases(file)
            dataset = {'schema_version':'offline-triage-cases-v1',
                       'provenance':'production_incidents', 'cases':self.cases}
            file.write_text(json.dumps(dataset), encoding='utf-8')
            with self.assertRaises(bench.BenchInputError):
                bench.load_cases(file)

    def test_duplicate_case_ids_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / 'cases.json'
            dataset = {'schema_version':'offline-triage-cases-v1',
                       'provenance':'synthetic_examples_not_ground_truth',
                       'cases':[self.cases[0], deepcopy(self.cases[0])]}
            file.write_text(json.dumps(dataset), encoding='utf-8')
            with self.assertRaises(bench.BenchInputError):
                bench.load_cases(file)

    def test_arbitrary_sensitive_or_foreign_fields_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / 'cases.json'
            case = deepcopy(self.cases[0]); case['raw_log'] = 'secret'
            dataset = {'schema_version':'offline-triage-cases-v1',
                       'provenance':'synthetic_examples_not_ground_truth',
                       'cases':[case]}
            file.write_text(json.dumps(dataset), encoding='utf-8')
            with self.assertRaises(bench.BenchInputError):
                bench.load_cases(file)

    def test_no_real_gemini_or_sqlite_module_dependencies_in_benchmark(self):
        # The run is entirely driven by imported pure policy, sanitizers and a
        # stubbed response: no import of app.main, DB_PATH or Gemini key needed.
        code = (Path(bench.__file__)).read_text(encoding='utf-8')
        self.assertNotIn('from app import main', code)
        self.assertNotIn('sqlite3.connect', code)
        self.assertNotIn('GEMINI_KEY', code)
        self.assertNotIn('mail_notifier', code)
        self.assertNotIn('telegram_notifier', code)


if __name__ == '__main__':
    unittest.main()
