"""Offline human-review comparison: no provider, database, or notification calls."""
from copy import deepcopy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app import review_evaluation as quality


class AnalystQualityTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            'version': quality.BASELINE_SOURCE,
            'fixture_provenance': 'synthetic_examples_not_ground_truth',
            'status': 'passed',
            'cases': [
                {'id': 'alpha-case', 'baseline': 'notify', 'shadow': 'review',
                 'shadow_status': 'evaluated', 'grounding': 'cited_observations'},
                {'id': 'beta-case', 'baseline': 'review', 'shadow': 'suppress',
                 'shadow_status': 'evaluated', 'grounding': 'unsupported_citations'},
                {'id': 'gamma-case', 'baseline': 'suppress', 'shadow': None,
                 'shadow_status': 'not_evaluated', 'grounding': 'not_evaluated'},
            ]
        }
        self.reviews = {'schema_version': quality.SCHEMA,
                        'report_version': quality.BASELINE_SOURCE,
                        'reviews': []}

    def add(self, ident, label, reason):
        self.reviews['reviews'].append({
            'case_id': ident, 'analyst_decision': label, 'reason_code': reason})

    def test_empty_labels_does_not_claim_accuracy(self):
        out = quality.compare(self.report, self.reviews)
        self.assertEqual(out['status'], 'awaiting_human_review')
        self.assertEqual(out['counts']['unreviewed'], 3)
        self.assertFalse(out['accuracy_or_recall_claimed'])
        self.assertEqual(out['provider_calls'], 0)
        self.assertEqual(out['notifications_sent'], 0)

    def test_grounded_pair_is_scored_separately(self):
        self.add('alpha-case', 'review', 'verified_pattern')
        out = quality.compare(self.report, self.reviews)
        self.assertEqual(out['status'], 'reviewed_sample_only')
        self.assertEqual(out['counts']['baseline_disagrees_with_reviewer'], 1)
        self.assertEqual(out['counts']['shadow_agrees_with_reviewer'], 1)
        self.assertEqual(out['counts']['shadow_better_than_baseline_on_pairs'], 1)
        self.assertEqual(out['decision_pairs_grounded_reviewed_only'], {'notify__review': 1})

    def test_invented_citation_cannot_be_scored_as_correct(self):
        self.add('beta-case', 'suppress', 'likely_benign')
        out = quality.compare(self.report, self.reviews)
        self.assertEqual(out['counts']['shadow_not_grounded_on_reviewed'], 1)
        self.assertEqual(out['counts']['shadow_agrees_with_reviewer'], 0)

    def test_no_model_response_not_scored_as_error(self):
        self.add('gamma-case', 'suppress', 'likely_benign')
        out = quality.compare(self.report, self.reviews)
        self.assertEqual(out['counts']['shadow_unavailable_on_reviewed'], 1)
        self.assertEqual(out['counts']['baseline_agrees_with_reviewer'], 1)
        self.assertEqual(out['counts']['shadow_disagrees_with_reviewer'], 0)

    def test_human_abstention_not_counted_as_wrong(self):
        self.add('alpha-case', 'insufficient_evidence', 'insufficient_context')
        out = quality.compare(self.report, self.reviews)
        self.assertEqual(out['counts']['human_abstained'], 1)
        self.assertEqual(out['counts']['reviewed_with_decision'], 0)

    def test_reject_wrong_report_version_and_provenance(self):
        for field, value in [
            ('version', 'untrusted'),
            ('fixture_provenance', 'production'),
            ('status', 'failed'),
        ]:
            with self.subTest(field=field):
                bad = deepcopy(self.report)
                bad[field] = value
                with self.assertRaises(quality.ReviewInputError):
                    quality.compare(bad, self.reviews)

    def test_reject_duplicate_and_unknown_case_ids(self):
        for ident in ('alpha-case', 'not-in-report'):
            self.reviews['reviews'] = [
                {'case_id': 'alpha-case', 'analyst_decision': 'notify',
                 'reason_code': 'critical_signal'},
                {'case_id': ident, 'analyst_decision': 'notify',
                 'reason_code': 'critical_signal'},
            ]
            with self.subTest(ident=ident), self.assertRaises(quality.ReviewInputError):
                quality.compare(self.report, self.reviews)

    def test_reject_unexpected_review_fields_and_text(self):
        self.reviews['reviews'] = [{
            'case_id': 'alpha-case', 'analyst_decision': 'review',
            'reason_code': 'verified_pattern', 'free_text': 'secret@example.invalid',
        }]
        with self.assertRaises(quality.ReviewInputError):
            quality.compare(self.report, self.reviews)

    def test_reject_invalid_reason_for_abstention(self):
        self.add('alpha-case', 'insufficient_evidence', 'critical_signal')
        with self.assertRaises(quality.ReviewInputError):
            quality.compare(self.report, self.reviews)

    def test_reject_out_of_sync_review_source(self):
        self.reviews['report_version'] = quality.LIVE_SOURCE
        with self.assertRaises(quality.ReviewInputError):
            quality.compare(self.report, self.reviews)

    def test_reject_inconsistent_shadow_status(self):
        self.report['cases'][2]['shadow'] = 'notify'
        with self.assertRaises(quality.ReviewInputError):
            quality.compare(self.report, self.reviews)

    def test_reject_duplicate_report_rows(self):
        self.report['cases'].append(deepcopy(self.report['cases'][0]))
        with self.assertRaises(quality.ReviewInputError):
            quality.compare(self.report, self.reviews)

    def test_accept_live_synthetic_trial_preview_without_labels(self):
        live = deepcopy(self.report)
        live['version'] = quality.LIVE_SOURCE
        live['provenance'] = 'fixed_synthetic_cases_not_ground_truth'
        live['mode'] = 'preview_no_network'
        live.pop('fixture_provenance')
        live.pop('status')
        live['cases'][2]['shadow_status'] = 'not_executed'
        self.reviews['report_version'] = quality.LIVE_SOURCE
        out = quality.compare(live, self.reviews)
        self.assertEqual(out['counts']['unreviewed'], 3)

    def test_reject_oversized_or_symlinked_file(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / 'labels.json'
            f.write_text('x' * (quality.MAX_BYTES + 1), encoding='utf-8')
            with self.assertRaises(quality.ReviewInputError):
                quality._load_json(f)
            f.write_text('{}', encoding='utf-8')
            alias = Path(d) / 'alias.json'
            alias.symlink_to(f)
            with self.assertRaises(quality.ReviewInputError):
                quality._load_json(alias)

    def test_default_cli_reads_fixed_synthetic_cases_only(self):
        with contextlib.redirect_stdout(io.StringIO()) as buff:
            code = quality.main(['--reviews', str(
                Path(__file__).resolve().parents[1] / 'evaluation/reviews_template_v1.json')])
        out = json.loads(buff.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(out['status'], 'awaiting_human_review')
        self.assertEqual(out['counts']['total_cases'], 13)
        self.assertEqual(out['counts']['reviewed_with_decision'], 0)
        self.assertNotIn('fixture-node', buff.getvalue())

    def test_blind_review_queue_hides_decisions_and_model_replies(self):
        queue = quality.review_queue()
        dumped = json.dumps(queue)
        self.assertEqual(len(queue['cases']), 13)
        for hidden in ('shadow_reply', 'primary_analysis', 'expected_policy_decision',
                       'expected_grounding', 'supporting_evidence_ids'):
            self.assertNotIn(hidden, dumped)
        self.assertTrue(queue['blind_to_policy_and_shadow_decisions'])

    def test_never_calls_provider_on_compare(self):
        with patch('socket.create_connection', side_effect=AssertionError('network')):
            out = quality.compare(self.report, self.reviews)
        self.assertEqual(out['provider_calls'], 0)

    def test_report_does_not_echo_secret_fields(self):
        self.report['API_KEY'] = 'SECRET_EXAMPLE_DO_NOT_ECHO'
        self.report['cases'][0]['raw_logs'] = 'SECRET_EXAMPLE_DO_NOT_ECHO'
        self.add('alpha-case', 'notify', 'critical_signal')
        out = quality.compare(self.report, self.reviews)
        self.assertNotIn('SECRET_EXAMPLE_DO_NOT_ECHO', json.dumps(out))


if __name__ == '__main__':
    unittest.main()
