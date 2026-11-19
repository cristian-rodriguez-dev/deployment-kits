"""Block 11: evidence citations and offline read-only evaluation."""
import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import ai_decision_shadow as shadow
from app import shadow_evaluation as evaluate
from app import contextual_analysis
from test_ai_decision_shadow import ASSET, wz


class EvidenceGroundingTests(unittest.TestCase):
    def setUp(self):
        self.facts = shadow.evidence(source='wazuh', synthetic=False,
                                     asset=ASSET, wazuh_context=wz())
        self.proposal = {'decision': 'review', 'classification': 'suspicious',
                         'priority': 'medium', 'false_positive': 'possible',
                         'confidence': 'low', 'reason': 'Revisar datos verificados'}

    def test_fixed_codes_no_identifiers_and_only_present_observations(self):
        codes = shadow.available_evidence_ids(self.facts)
        self.assertIn('wazuh.rule_level', codes)
        self.assertIn('wazuh.bot_repeat_count', codes)
        self.assertNotIn('cross.loki_ssh_service_log_volume_increase', codes)
        self.assertNotIn('PRIVATE_HOST_DO_NOT_SEND', json.dumps(codes))
        self.assertEqual(shadow.available_evidence_ids({'bad': True}), [])

    def test_valid_citation_but_no_automatic_policy(self):
        p = {**self.proposal, 'supporting_evidence_ids': ['wazuh.rule_level']}
        r = shadow.compare({'shadow_recommendation': p}, 'notify', self.facts)
        self.assertEqual(r['status'], 'evaluated')
        self.assertEqual(r['evidence_grounding']['status'], 'cited_observations')
        self.assertEqual(r['evidence_grounding']['cited_evidence_count'], 1)
        self.assertFalse(r['evidence_grounding']['safe_for_automatic_policy'])
        self.assertFalse(r['evidence_grounding']['free_text_reason_verified'])
        self.assertEqual(r['actual_decision'], 'notify')
        self.assertTrue(r['differs_from_current'])

    def test_cannot_cite_sources_not_collected_or_fake_codes(self):
        for bogus in (["cross.loki_ssh_service_log_volume_increase"],
                      ['wazuh.rule_level', 'unexpected.host'],
                      ['wazuh.rule_level', 'wazuh.rule_level']):
            p = {**self.proposal, 'supporting_evidence_ids': bogus}
            r = shadow.compare({'shadow_recommendation': p}, 'notify', self.facts)
            self.assertIn(r['evidence_grounding']['status'],
                          ('unsupported_citations', 'invalid_citations'))
            self.assertFalse(r['evidence_grounding']['safe_for_automatic_policy'])

    def test_multisource_codes_only_when_source_is_verified(self):
        c = {
            'version':'cross-source-patterns-v1', 'status':'ok',
            'changes_triage':False, 'changes_notifications':False,
            'raw_logs_stored':False, 'sent_to_ai':False,
            'sources_validated':['wazuh_webhook','prometheus'],
            'signal_count':1,
            'signals':[{'kind':'prometheus_scrape_unavailable','source':'prometheus'}],
        }
        facts = shadow.evidence(source='wazuh', synthetic=False, asset=ASSET,
                                wazuh_context=wz(), cross_source_patterns=c)
        codes = shadow.available_evidence_ids(facts)
        self.assertIn('cross.prometheus_scrape_unavailable', codes)
        self.assertNotIn('cross.loki_observed_log_volume_increase', codes)
        fake = {**self.proposal,
                'supporting_evidence_ids':['cross.loki_observed_log_volume_increase']}
        status = shadow.compare({'shadow_recommendation':fake}, 'notify', facts)
        self.assertEqual(status['evidence_grounding']['status'],
                         'unsupported_citations')

    def test_malformed_model_citations_not_persisted_unbounded(self):
        from test_ai_decision_shadow import FakeResponse
        raw_citation = 'UNTRUSTED_' + ('z'*5000)
        decision = {**self.proposal,'supporting_evidence_ids':[raw_citation]}
        body = {'candidates':[{'content':{'parts':[{'text':json.dumps({
            'summary':'Lectura','technical_reading':'Parcial','confidence':'low',
            'recommended_checks':['Revisar'],'shadow_decision':decision,
        })}]}}]}
        def fake_urlopen(req, timeout):
            return FakeResponse(json.dumps(body).encode())
        with patch.object(contextual_analysis.urllib.request,'urlopen',fake_urlopen):
            r = contextual_analysis.interpret(None,'wazuh','security','key','model',
                  asset=ASSET,wazuh_context=wz(),shadow_facts=self.facts)
        self.assertEqual(r['shadow_recommendation']['supporting_evidence_ids'],[])
        self.assertNotIn('UNTRUSTED_', json.dumps(r))

    def test_invalid_types_fail_closed(self):
        for bad in ([], [True], ['wazuh.rule_level'] * 5, 'wazuh.rule_level',
                    [{'host': 'SECRET'}], [1]):
            p = {**self.proposal, 'supporting_evidence_ids': bad}
            r = shadow.compare({'shadow_recommendation': p}, 'notify', self.facts)
            self.assertEqual(r['evidence_grounding']['status'], 'invalid_citations')

    def test_contextual_prompt_sends_only_allowed_codes(self):
        from test_ai_decision_shadow import FakeResponse
        body = {'candidates': [{'content': {'parts': [{'text': json.dumps({
            'summary': 'Analizado', 'technical_reading': 'Parcial',
            'recommended_checks': ['Revisar'], 'confidence': 'low',
            'shadow_decision': {**self.proposal,
                'supporting_evidence_ids': ['wazuh.rule_level']}
        })}]}}]}
        requests = []
        def fake_urlopen(req, timeout):
            requests.append(req)
            return FakeResponse(json.dumps(body).encode())
        with patch.object(contextual_analysis.urllib.request, 'urlopen', fake_urlopen):
            r = contextual_analysis.interpret(
                None, 'wazuh', 'security', 'dummy', 'dummy',
                asset=ASSET, wazuh_context=wz(), shadow_facts=self.facts)
        self.assertEqual(len(requests), 1)
        self.assertEqual(r['shadow_recommendation']['supporting_evidence_ids'],
                         ['wazuh.rule_level'])
        sent = requests[0].data.decode()
        self.assertIn('decision_shadow_allowed_evidence_ids', sent)
        self.assertNotIn('PRIVATE_HOST_DO_NOT_SEND', sent)
        self.assertNotIn('unexpected.host', sent)


class OfflineReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / 'incidents.db'
        with sqlite3.connect(self.db) as c:
            c.execute('CREATE TABLE incidents (id INTEGER PRIMARY KEY, '
                      'source TEXT, synthetic INT, analysis TEXT)')

    def insert(self, source='wazuh', synthetic=0, analysis=None):
        with sqlite3.connect(self.db) as c:
            c.execute('INSERT INTO incidents (source,synthetic,analysis) '
                      'VALUES (?,?,?)', (source, synthetic, json.dumps(analysis or {})))

    def test_aggregate_disagreement_and_no_identifiers(self):
        base = {'version':'ai-decision-shadow-v1','changes_triage':False,
                'changes_notifications':False,'automatic_actions':False,
                'status':'evaluated','actual_decision':'notify',
                'proposed_decision':'suppress',
                'evidence_grounding':{'status':'cited_observations'},
                'reason':'PRIVATE_SECRET_DO_NOT_PRINT',
                'source_evidence':{'host':'PRIVATE_HOST_DO_NOT_PRINT'}}
        self.insert(analysis={'ai_decision_shadow':base})
        self.insert(analysis={'ai_decision_shadow':{**base,'proposed_decision':'notify'}})
        self.insert(analysis={'ai_decision_shadow':{**base,'status':'not_evaluated'}})
        self.insert(analysis={})
        self.insert(source='grafana',analysis={'ai_decision_shadow':base})
        self.insert(source='wazuh', synthetic=1, analysis={'ai_decision_shadow':base})
        result = evaluate.summarize(self.db)
        self.assertEqual(result['counts']['real_wazuh_rows'],4)
        self.assertEqual(result['counts']['shadow_present'],3)
        self.assertEqual(result['counts']['evaluated'],2)
        self.assertEqual(result['counts']['notify_to_suppress_proposal'],1)
        self.assertEqual(result['counts']['agreement'],1)
        self.assertEqual(result['counts']['disagreement'],1)
        payload = json.dumps(result)
        self.assertNotIn('PRIVATE_SECRET_DO_NOT_PRINT',payload)
        self.assertNotIn('PRIVATE_HOST_DO_NOT_PRINT',payload)

    def test_sqlite_remains_unchanged_and_nonexistent_path_not_created(self):
        self.insert(analysis={'junk':'something'})
        before = self.db.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            exit_code = evaluate.main(['--db',str(self.db),'--limit','50'])
        self.assertEqual(exit_code,0)
        self.assertIn('without_shadow',buf.getvalue())
        self.assertEqual(self.db.read_bytes(),before)
        with self.assertRaises(FileNotFoundError):
            evaluate.summarize(Path(self.temp.name)/'missing.db')

    def test_invalid_contract_is_not_counted_as_evaluated(self):
        self.insert(analysis={'ai_decision_shadow':{
            'status':'evaluated','version':'ai-decision-shadow-v1',
            'changes_triage':True,'changes_notifications':False,
            'automatic_actions':False,'actual_decision':'notify',
            'proposed_decision':'suppress'}})
        report = evaluate.summarize(self.db)
        self.assertEqual(report['counts']['invalid_shadow_contract'],1)
        self.assertNotIn('evaluated',report['counts'])

    def test_no_accuracy_claim_without_human_labels(self):
        report=evaluate.summarize(self.db)
        self.assertTrue(any('Agreement is not accuracy' in line
                            for line in report['limitations']))


if __name__=='__main__':
    unittest.main()
