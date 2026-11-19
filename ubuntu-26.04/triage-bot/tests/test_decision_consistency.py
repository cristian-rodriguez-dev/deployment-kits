"""Risk-focused offline tests. These exercises never call Gemini or change policy."""
from __future__ import annotations

import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from app import decision_consistency as dc, offline_benchmark


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'evaluation' / 'cases_v1.json'
CHALLENGES = ROOT / 'evaluation' / 'decision_challenges_v1.json'


class DecisionConsistencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = offline_benchmark.load_cases(FIXTURES)
        cls.known = {item['id']: item for item in cls.cases}
        cls.challenges = dc.read_challenges(CHALLENGES, set(cls.known))
        cls.by_id = {item['id']: item for item in cls.challenges}

    def assessment(self, name):
        row = self.by_id[name]
        return dc.inspect(self.known[row['case_id']], row['proposal'])

    def temporary_input(self, payload):
        folder = tempfile.TemporaryDirectory()
        file = Path(folder.name) / 'cases.json'
        file.write_text(json.dumps(payload), encoding='utf-8')
        return folder, file

    def test_fixture_contract_and_ten_challenges(self):
        self.assertEqual(len(self.cases), 13)
        self.assertEqual(len(self.challenges), 10)
        self.assertEqual(len(self.by_id), len(self.challenges))

    def test_critical_suppress_is_detected_with_real_citations(self):
        row = self.assessment('critical-suppress')
        self.assertTrue(row['cited_ids_structurally_valid'])
        self.assertIn('critical_notification_conflict', row['warning_codes'])
        self.assertIn('suppression_recommended_despite_security_signal', row['warning_codes'])

    def test_critical_dismisses_investigation_is_detected(self):
        self.assertIn('critical_investigation_conflict',
                      self.assessment('critical-ignores-investigation')['warning_codes'])

    def test_loki_volume_not_proof_of_benign_activity(self):
        row = self.assessment('loki-unsupported-benign')
        self.assertEqual(row['available_sources'], ['loki_timeline', 'wazuh'])
        self.assertIn('benign_claim_without_verified_benign_evidence', row['warning_codes'])

    def test_high_confidence_without_corrob_is_warning_not_accuracy(self):
        row = self.assessment('medium-high-confidence-only-wazuh')
        self.assertIn('high_confidence_limited_observations', row['warning_codes'])
        self.assertEqual(row['status'], 'review_required')

    def test_evolving_wazuh_notify_and_review_can_coexist(self):
        row = self.assessment('wazuh-evolution-coherent')
        self.assertTrue(row['cited_ids_structurally_valid'])
        self.assertEqual(row['status'], 'no_explicit_contradiction_detected')
        self.assertEqual(row['warning_codes'], [])
        self.assertGreater(row['available_evidence_count'], 2)

    def test_invented_loki_citation_is_rejected(self):
        row = self.assessment('invented-loki-citation')
        self.assertFalse(row['cited_ids_structurally_valid'])
        self.assertEqual(row['status'], 'invalid_structure_or_citations')
        self.assertEqual(row['available_sources'], ['wazuh'])

    def test_unverified_agent_is_not_evaluable(self):
        row = self.assessment('unverified-agent-claim')
        self.assertEqual(row['status'], 'missing_verified_context')
        self.assertIn('unverified_asset_identity', row['warning_codes'])
        self.assertEqual(row['available_evidence_count'], 0)

    def test_synthetic_event_never_notify(self):
        row = self.assessment('synthetic-notification')
        self.assertEqual(row['status'], 'missing_verified_context')
        self.assertIn('synthetic_notification_conflict', row['warning_codes'])

    def test_prometheus_scrape_does_not_claim_host_compromise(self):
        row = self.assessment('prometheus-scrape-with-review')
        self.assertEqual(row['status'], 'no_explicit_contradiction_detected')
        self.assertEqual(row['available_sources'], ['prometheus', 'wazuh'])

    def test_low_level_benign_not_established_by_model_classification(self):
        row = self.assessment('low-benign-not-proven')
        self.assertIn('benign_claim_without_verified_benign_evidence', row['warning_codes'])

    def test_report_does_not_treat_unflagged_as_accuracy(self):
        report = dc.report(self.cases, self.challenges)
        self.assertFalse(report['model_accuracy_claimed'])
        self.assertEqual(report['status'], 'completed_offline_review_required')
        self.assertEqual(report['counts']['challenges'], 10)
        self.assertEqual(report['counts']['baseline_regressions_passed'], 13)
        self.assertEqual(report['provider_calls'], 0)
        self.assertEqual(report['database_writes'], 0)
        self.assertEqual(report['notifications_sent'], 0)
        self.assertEqual(report['policy_changes'], 0)

    def test_baselines_are_from_real_deterministic_policy(self):
        report = dc.report(self.cases, self.challenges)
        rows = {row['challenge_id']: row for row in report['checks']}
        self.assertEqual(rows['critical-suppress']['baseline_notification_policy'], 'notify')
        self.assertEqual(rows['wazuh-evolution-coherent']['baseline_notification_policy'], 'notify')
        self.assertEqual(rows['loki-unsupported-benign']['baseline_notification_policy'], 'review')

    def test_no_proposals_or_cases_are_modified(self):
        cases, challenges = deepcopy(self.cases), deepcopy(self.challenges)
        dc.report(self.cases, self.challenges)
        self.assertEqual(cases, self.cases)
        self.assertEqual(challenges, self.challenges)

    def test_do_not_reflect_untrusted_reason_or_secret(self):
        challenges = deepcopy(self.challenges)
        challenges[0]['proposal']['notification_reason'] = 'SECRET_API_KEY_DO_NOT_ECHO'
        result = dc.report(self.cases, challenges)
        self.assertNotIn('SECRET_API_KEY_DO_NOT_ECHO', json.dumps(result))

    def test_network_calls_forbidden_during_evaluation(self):
        with (patch('socket.create_connection', side_effect=AssertionError('network forbidden')),
              patch('socket.socket.connect', side_effect=AssertionError('network forbidden'))):
            out = dc.report(self.cases, self.challenges)
        self.assertEqual(out['provider_calls'], 0)

    def test_read_challenges_rejects_bad_schema(self):
        obj = json.loads(CHALLENGES.read_text())
        obj['schema_version'] = 'other'
        folder, file = self.temporary_input(obj)
        with folder, self.assertRaises(dc.ChallengeInputError):
            dc.read_challenges(file, set(self.known))

    def test_read_challenges_rejects_non_synthetic_provenance(self):
        obj = json.loads(CHALLENGES.read_text())
        obj['provenance'] = 'real_production_incidents'
        folder, file = self.temporary_input(obj)
        with folder, self.assertRaises(dc.ChallengeInputError):
            dc.read_challenges(file, set(self.known))

    def test_read_challenges_rejects_unknown_case(self):
        obj = json.loads(CHALLENGES.read_text())
        obj['challenges'][0]['case_id'] = 'unknown-asset'
        folder, file = self.temporary_input(obj)
        with folder, self.assertRaises(dc.ChallengeInputError):
            dc.read_challenges(file, set(self.known))

    def test_read_challenges_rejects_duplicate_id(self):
        obj = json.loads(CHALLENGES.read_text())
        obj['challenges'][1]['id'] = obj['challenges'][0]['id']
        folder, file = self.temporary_input(obj)
        with folder, self.assertRaises(dc.ChallengeInputError):
            dc.read_challenges(file, set(self.known))

    def test_read_challenges_rejects_unexpected_fields(self):
        obj = json.loads(CHALLENGES.read_text())
        obj['challenges'][0]['credential'] = 'NO_SECRET_EXPECTED'
        folder, file = self.temporary_input(obj)
        with folder, self.assertRaises(dc.ChallengeInputError):
            dc.read_challenges(file, set(self.known))

    def test_read_challenges_rejects_more_than_max(self):
        obj = json.loads(CHALLENGES.read_text())
        obj['challenges'] = [deepcopy(obj['challenges'][0]) for _ in range(dc.MAX_ITEMS + 1)]
        folder, file = self.temporary_input(obj)
        with folder, self.assertRaises(dc.ChallengeInputError):
            dc.read_challenges(file, set(self.known))

    def test_read_challenges_rejects_large_candidate(self):
        obj = json.loads(CHALLENGES.read_text())
        obj['challenges'][0]['proposal']['notification_reason'] = 'A' * 10000
        folder, file = self.temporary_input(obj)
        with folder, self.assertRaises(dc.ChallengeInputError):
            dc.read_challenges(file, set(self.known))

    def test_read_challenges_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            symlink = Path(folder) / 'link.json'
            symlink.symlink_to(CHALLENGES)
            with self.assertRaises(dc.ChallengeInputError):
                dc.read_challenges(symlink, set(self.known))

    def test_cli_runs_offline(self):
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            result = dc.main(['--cases', str(FIXTURES), '--challenges', str(CHALLENGES)])
        self.assertEqual(result, 0)
        report = json.loads(captured.getvalue())
        self.assertEqual(report['counts']['challenges'], 10)
        self.assertEqual(report['policy_changes'], 0)

    def test_cli_fails_closed_on_missing_file_without_data_echo(self):
        with contextlib.redirect_stderr(io.StringIO()) as captured:
            with self.assertRaises(SystemExit) as cm:
                dc.main(['--challenges', 'does-not-exist.json'])
        self.assertEqual(cm.exception.code, 2)
        self.assertNotIn('traceback', captured.getvalue().lower())

    def test_invalid_input_to_inspect_is_rejected(self):
        with self.assertRaises(dc.ChallengeInputError):
            dc.inspect(None, None)


if __name__ == '__main__':
    unittest.main()
