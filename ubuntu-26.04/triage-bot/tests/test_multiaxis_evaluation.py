"""Multi-axis human review contract; no model, database, network, or alert transport."""
from __future__ import annotations

from copy import deepcopy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app import multiaxis_evaluation as multi, review_evaluation as legacy
from app import live_shadow_benchmark, offline_benchmark


class MultiAxisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = live_shadow_benchmark.fixed_cases()
        cls.report = offline_benchmark.report(list(cls.fixtures.values()))

    def blank(self):
        return {'schema_version': multi.SCHEMA,
                'report_version': legacy.BASELINE_SOURCE, 'reviews': []}

    def add(self, document, ident, notification, investigation, evidence='unknown', reason='verified_pattern'):
        document['reviews'].append({
            'case_id': ident, 'notification': notification,
            'investigation': investigation, 'evidence_state': evidence,
            'reason_code': reason,
        })

    def test_full_suite_has_expected_fixed_cases(self):
        self.assertEqual(len(self.fixtures), 13)
        self.assertEqual(self.report['status'], 'passed')

    def test_safe_legacy_projection_is_partial(self):
        self.assertEqual(multi.project_legacy('review'),
                         {'notification': 'undetermined', 'investigation': 'required'})
        self.assertEqual(multi.project_legacy('notify'),
                         {'notification': 'notify', 'investigation': 'undetermined'})
        self.assertEqual(multi.project_legacy('suppress'),
                         {'notification': 'suppress', 'investigation': 'undetermined'})
        self.assertEqual(multi.project_legacy(None),
                         {'notification': 'undetermined', 'investigation': 'undetermined'})

    def test_migrate_three_human_labels_conservatively(self):
        doc = {'schema_version': legacy.SCHEMA,
               'report_version': legacy.BASELINE_SOURCE,
               'reviews': [
                   {'case_id': 'critical-model-tries-suppress', 'analyst_decision': 'notify',
                    'reason_code': 'critical_signal'},
                   {'case_id': 'verified-loki-volume-not-login', 'analyst_decision': 'review',
                    'reason_code': 'verified_pattern'},
                   {'case_id': 'wazuh-sequence-and-group-growth', 'analyst_decision': 'review',
                    'reason_code': 'verified_pattern'},
               ]}
        converted = multi.migrate_legacy(doc, legacy.BASELINE_SOURCE, set(self.fixtures))
        checked = multi.checked_multiaxis_reviews(converted, legacy.BASELINE_SOURCE, set(self.fixtures))
        self.assertEqual(len(checked), 3)
        self.assertEqual(checked['critical-model-tries-suppress']['notification'], 'notify')
        self.assertEqual(checked['critical-model-tries-suppress']['investigation'], 'undetermined')
        self.assertEqual(checked['verified-loki-volume-not-login']['notification'], 'undetermined')
        self.assertEqual(checked['verified-loki-volume-not-login']['investigation'], 'required')
        self.assertEqual(checked['wazuh-sequence-and-group-growth']['notification'], 'undetermined')
        self.assertEqual(checked['wazuh-sequence-and-group-growth']['investigation'], 'required')

    def test_wazuh_combined_label_supported_without_mutating_legacy(self):
        r = self.blank()
        self.add(r, 'wazuh-sequence-and-group-growth', 'notify', 'required', 'suspicious_unconfirmed')
        out = multi.compare(self.report, r, self.fixtures)
        self.assertEqual(out['counts']['notification_advisory_agrees'], 1)
        self.assertEqual(out['counts']['investigation_advisory_agrees'], 1)
        self.assertEqual(out['counts']['evidence_state_advisory_agrees'], 1)
        row = out['reviewed_cases'][0]
        self.assertEqual(row['shadow_legacy_projection']['investigation'], 'undetermined')
        self.assertEqual(out['counts']['investigation_shadow_axis_not_expressed'], 1)
        self.assertFalse(out['accuracy_or_recall_claimed'])

    def test_critical_event_model_suppress_does_not_override_protection(self):
        r = self.blank()
        self.add(r, 'critical-model-tries-suppress', 'notify', 'required', 'suspicious_unconfirmed')
        result = multi.compare(self.report, r, self.fixtures)
        row = result['reviewed_cases'][0]
        self.assertEqual(row['advisory']['notification'], 'notify')
        self.assertEqual(row['shadow_legacy_projection']['notification'], 'suppress')
        self.assertEqual(result['counts']['notification_shadow_disagrees'], 1)
        self.assertEqual(result['policy_changes'], 0)

    def test_loki_volume_requires_review_without_confirming_intrusion(self):
        r = self.blank()
        self.add(r, 'verified-loki-volume-not-login', 'undetermined', 'required', 'suspicious_unconfirmed')
        row = multi.compare(self.report, r, self.fixtures)['reviewed_cases'][0]
        self.assertEqual(row['advisory']['notification'], 'hold')
        self.assertEqual(row['advisory']['investigation'], 'required')
        self.assertEqual(row['advisory']['evidence_state'], 'suspicious_unconfirmed')

    def test_synthetic_critical_never_notifies(self):
        r = self.blank()
        self.add(r, 'synthetic-critical-never-notify', 'suppress', 'required')
        out = multi.compare(self.report, r, self.fixtures)
        self.assertEqual(out['reviewed_cases'][0]['advisory']['notification'], 'suppress')

    def test_unverified_agent_never_yields_confirmed_investigation(self):
        r = self.blank()
        self.add(r, 'unverified-agent-must-fail-closed', 'undetermined', 'undetermined')
        row = multi.compare(self.report, r, self.fixtures)['reviewed_cases'][0]
        self.assertEqual(row['advisory']['investigation'], 'undetermined')
        self.assertEqual(row['advisory']['evidence_state'], 'unknown')

    def test_malformed_evidence_rejected(self):
        broken = dict(self.fixtures['wazuh-sequence-and-group-growth'])
        broken['recent_count'] = True
        with self.assertRaises(legacy.ReviewInputError):
            multi.advisory(broken, 'notify')

    def test_no_review_no_accuracy_claim(self):
        out = multi.compare(self.report, self.blank(), self.fixtures)
        self.assertEqual(out['status'], 'awaiting_human_review')
        self.assertEqual(out['counts']['unreviewed'], 13)
        self.assertEqual(out['provider_calls'], 0)

    def test_inadequate_legacy_status_cannot_score_shadow(self):
        r = self.blank()
        self.add(r, 'invented-loki-citation', 'suppress', 'required')
        out = multi.compare(self.report, r, self.fixtures)
        self.assertEqual(out['counts']['notification_shadow_not_evaluable'], 1)
        self.assertEqual(out['counts']['investigation_shadow_not_evaluable'], 1)

    def test_unknown_axes_excluded_separately(self):
        r = self.blank()
        self.add(r, 'verified-loki-volume-not-login', 'undetermined', 'required')
        out = multi.compare(self.report, r, self.fixtures)
        self.assertEqual(out['counts']['notification_human_labeled'], 0)
        self.assertEqual(out['counts']['notification_human_abstentions'], 1)
        self.assertEqual(out['counts']['investigation_human_labeled'], 1)

    def test_reject_confirmed_compromise_without_direct_proof(self):
        r = self.blank()
        self.add(r, 'verified-loki-volume-not-login', 'hold', 'required', 'confirmed_compromise')
        with self.assertRaises(legacy.ReviewInputError):
            multi.compare(self.report, r, self.fixtures)

    def test_reject_duplicate_case_and_unknown_fields(self):
        r = self.blank()
        self.add(r, 'verified-loki-volume-not-login', 'hold', 'required')
        r['reviews'].append(dict(r['reviews'][0]))
        with self.assertRaises(legacy.ReviewInputError):
            multi.compare(self.report, r, self.fixtures)
        r['reviews'].pop()
        r['reviews'][0]['hidden_secret'] = 'NEVER_ECHO'
        with self.assertRaises(legacy.ReviewInputError):
            multi.compare(self.report, r, self.fixtures)

    def test_reject_report_mismatch(self):
        r = self.blank()
        r['report_version'] = legacy.LIVE_SOURCE
        with self.assertRaises(legacy.ReviewInputError):
            multi.compare(self.report, r, self.fixtures)

    def test_offline_cli_default_has_no_provider_calls(self):
        with contextlib.redirect_stdout(io.StringIO()) as stream:
            status = multi.main([])
        result = json.loads(stream.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(result['counts']['total_cases'], 13)
        self.assertEqual(result['provider_calls'], 0)

    def test_cli_migrate_only_prints_safe_fields(self):
        legacy_doc = {'schema_version': legacy.SCHEMA,
                      'report_version': legacy.BASELINE_SOURCE,
                      'reviews': [{'case_id': 'critical-model-tries-suppress',
                                   'analyst_decision': 'notify',
                                   'reason_code': 'critical_signal'}]}
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / 'reviews.json'
            file.write_text(json.dumps(legacy_doc), encoding='utf-8')
            with contextlib.redirect_stdout(io.StringIO()) as stream:
                status = multi.main(['--migrate', str(file)])
            result = json.loads(stream.getvalue())
            self.assertEqual(status, 0)
            self.assertEqual(result['reviews'][0]['notification'], 'notify')
            self.assertEqual(result['reviews'][0]['investigation'], 'undetermined')

    def test_no_exfiltration_even_if_report_has_secret_extras(self):
        bad_report = deepcopy(self.report)
        bad_report['api_key'] = 'NEVER_ECHO_SECRET'
        r = self.blank()
        self.add(r, 'critical-model-tries-suppress', 'notify', 'required')
        with patch('socket.create_connection', side_effect=AssertionError('network')):
            out = multi.compare(bad_report, r, self.fixtures)
        dumped = json.dumps(out)
        self.assertNotIn('NEVER_ECHO_SECRET', dumped)
        self.assertNotIn('api_key', dumped)

    def test_invalid_evidence_labels_and_bool_rejected(self):
        for value in ('confirmed_compromise', 'true', True):
            r = self.blank()
            self.add(r, 'critical-model-tries-suppress', 'notify', 'required', value)
            with self.subTest(value=value), self.assertRaises(legacy.ReviewInputError):
                multi.compare(self.report, r, self.fixtures)

    def test_no_model_reply_does_not_count_as_wrong(self):
        r = self.blank()
        self.add(r, 'high-level-without-ai', 'notify', 'undetermined')
        out = multi.compare(self.report, r, self.fixtures)
        self.assertEqual(out['counts']['notification_shadow_not_evaluable'], 1)
        self.assertEqual(out['counts']['notification_shadow_disagrees'], 0)


if __name__ == '__main__':
    unittest.main()
