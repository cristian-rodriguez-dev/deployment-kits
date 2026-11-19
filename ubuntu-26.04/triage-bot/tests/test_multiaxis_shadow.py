"""Block 16: native independent axes, provider mocked, no live calls or notifications."""
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import ai_decision_shadow as legacy
from app import contextual_analysis as ctx
from app import multiaxis_shadow as ms
from app.wazuh_enrichment import collect as collect_wazuh

ASSET = {'agent_id': '005', 'rule_id': '5763', 'name': 'SECRET_HOST_NEVER_SEND',
         'department': 'Sistemas'}
RULE = {'id': '5763', 'level': 15, 'groups': ['sshd', 'attack'],
        'mitre': {'id': ['T1110']}}
AGENT = {'id': '005'}


def facts():
    return legacy.evidence(source='wazuh', synthetic=False, asset=ASSET,
                           wazuh_context=collect_wazuh(RULE, AGENT, ASSET, 4))


def native(notification='notify', investigation='required', evidence_state='suspicious_unconfirmed'):
    return {
        'notification': notification, 'investigation': investigation,
        'evidence_state': evidence_state, 'confidence': 'medium',
        'notification_reason': 'Nivel Wazuh observado',
        'investigation_reason': 'Revisar recurrencia y gravedad',
        'evidence_reason': 'Hay observaciones, no compromiso probado',
        'notification_evidence_ids': ['wazuh.rule_level'],
        'investigation_evidence_ids': ['wazuh.bot_repeat_count'],
        'evidence_state_evidence_ids': ['wazuh.rule_level'],
    }


class Response(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *args): self.close()


class NativeShadowTests(unittest.TestCase):
    def test_independent_notify_and_investigate(self):
        model = {'multiaxis_shadow_evidence_used': True,
                 'multiaxis_shadow_recommendation': native()}
        compared = ms.compare(model, 'notify', facts())
        self.assertEqual(compared['status'], 'evaluated')
        self.assertEqual(compared['actual_notification'], 'notify')
        self.assertFalse(compared['notification_differs'])
        self.assertEqual(compared['recommendation']['investigation'], 'required')
        self.assertEqual(compared['recommendation']['evidence_state'], 'suspicious_unconfirmed')
        self.assertIsNone(compared['actual_investigation'])
        for flag in ('changes_triage', 'changes_notifications', 'automatic_actions',
                     'reason_text_verified', 'causality_verified'):
            self.assertFalse(compared[flag])

    def test_critical_suppress_proposal_never_changes_policy(self):
        rec = native(notification='suppress')
        compared = ms.compare({'multiaxis_shadow_evidence_used': True,
                               'multiaxis_shadow_recommendation': rec}, 'notify', facts())
        self.assertEqual(compared['status'], 'evaluated')
        self.assertEqual(compared['actual_notification'], 'notify')
        self.assertTrue(compared['notification_differs'])
        self.assertTrue(compared['protected_notification_retained'])
        self.assertFalse(compared['changes_notifications'])

    def test_malformed_recommendation_fails_closed(self):
        for change in (
            {'notification': 'block_ip'},
            {'investigation': 'execute_recovery'},
            {'evidence_state': 'confirmed_compromise'},
            {'confidence': 'certain'},
            {'notification_evidence_ids': ['loki.fake']},
            {'notification_evidence_ids': ['wazuh.rule_level'] * 2},
            {'notification_evidence_ids': [True]},
            {'notification_evidence_ids': []},
            {'investigation_evidence_ids': []},
            {'evidence_state_evidence_ids': []},
            {'notification_reason': ''},
            {'notification_reason': 'x' * 600},
            {'notification_reason': 'bad\nline'},
            {'reason': 'extra field'},
        ):
            with self.subTest(change=change):
                item = {**native(), **change}
                self.assertIsNone(ms.validate(item, facts()))
                out = ms.compare({'multiaxis_shadow_evidence_used': True,
                                  'multiaxis_shadow_recommendation': item}, 'notify', facts())
                self.assertEqual(out['status'], 'invalid_or_unsupported_proposal')
                self.assertIsNone(out['recommendation'])

    def test_unknown_axes_allow_zero_citations(self):
        rec = native(notification='undetermined', investigation='undetermined',
                     evidence_state='unknown')
        for axis in ('notification', 'investigation', 'evidence_state'):
            rec[axis + '_evidence_ids'] = []
        self.assertEqual(ms.validate(rec, facts())['evidence_state'], 'unknown')

    def test_untrusted_or_missing_facts_cannot_be_compared(self):
        rec = native()
        self.assertEqual(ms.compare({'multiaxis_shadow_evidence_used': True,
                                     'multiaxis_shadow_recommendation': rec}, 'notify',
                                    {**facts(), 'host': 'SECRET_HOST_NEVER_SEND'})['status'],
                         'not_evaluated')
        self.assertEqual(ms.compare({'multiaxis_shadow_recommendation': rec}, 'notify', facts())['status'],
                         'not_evaluated')
        self.assertEqual(ms.compare(None, 'notify', facts())['status'], 'not_evaluated')

    def test_contextual_second_call_both_proposals_and_identifier_free(self):
        payload = {'candidates': [{'content': {'parts': [{
            'text': json.dumps({
                'summary': 'Contexto parcial', 'technical_reading': 'No confirma intrusión',
                'recommended_checks': ['Investigar alertas'], 'confidence': 'medium',
                'shadow_multiaxis': native(),
                'shadow_decision': {'decision': 'notify', 'classification': 'suspicious',
                                    'priority': 'critical', 'false_positive': 'possible',
                                    'confidence': 'medium', 'reason': 'Alerta',
                                    'supporting_evidence_ids': ['wazuh.rule_level']},
            })
        }]}}]}
        requests = []
        def response(req, timeout):
            requests.append(req)
            return Response(json.dumps(payload).encode())
        with patch.object(ctx.urllib.request, 'urlopen', response):
            result = ctx.interpret(None, 'wazuh', 'security', 'test-key', 'fake-model',
                                   asset=ASSET,
                                   wazuh_context=collect_wazuh(RULE, AGENT, ASSET, 4),
                                   shadow_facts=facts(), multiaxis_shadow_enabled=True)
        self.assertEqual(len(requests), 1)
        prompt = requests[0].data.decode()
        self.assertIn('shadow_multiaxis', prompt)
        self.assertIn('shadow_decision', prompt)
        self.assertIn('investigation', prompt)
        self.assertNotIn('SECRET_HOST_NEVER_SEND', prompt)
        self.assertNotIn('"agent_id"', prompt)
        self.assertTrue(result['multiaxis_shadow_evidence_used'])
        self.assertEqual(result['multiaxis_shadow_recommendation']['investigation'], 'required')
        self.assertEqual(result['shadow_recommendation']['decision'], 'notify')
        self.assertFalse(result['changes_triage'])

    def test_bad_raw_provider_fields_never_stored(self):
        candidate = {**native(), 'host': 'SECRET_HOST_NEVER_SEND'}
        payload = {'candidates': [{'content': {'parts': [{
            'text': json.dumps({'summary': 'Resumen', 'technical_reading': 'Lectura',
                                'confidence': 'low', 'recommended_checks': [],
                                'shadow_multiaxis': candidate})
        }]}}]}
        with patch.object(ctx.urllib.request, 'urlopen', lambda *a, **kw:
                          Response(json.dumps(payload).encode())):
            result = ctx.interpret(None, 'wazuh', 'security', 'key', 'model',
                                   asset=ASSET, wazuh_context=collect_wazuh(RULE, AGENT, ASSET, 4),
                                   shadow_facts=facts(), multiaxis_shadow_enabled=True)
        self.assertIsNone(result['multiaxis_shadow_recommendation'])
        self.assertNotIn('SECRET_HOST_NEVER_SEND', json.dumps(result))

    def test_feature_off_or_no_verified_shadow_keeps_legacy_prompt(self):
        payload = {'candidates': [{'content': {'parts': [{
            'text': json.dumps({'summary': 'Resumen', 'technical_reading': 'Lectura',
                                'confidence': 'low', 'recommended_checks': []})
        }]}}]}
        requests = []
        def response(req, timeout):
            requests.append(req)
            return Response(json.dumps(payload).encode())
        with patch.object(ctx.urllib.request, 'urlopen', response):
            off = ctx.interpret(None, 'wazuh', 'security', 'key', 'model',
                                asset=ASSET,
                                wazuh_context=collect_wazuh(RULE, AGENT, ASSET, 4),
                                shadow_facts=facts())
            no_shadow = ctx.interpret(None, 'wazuh', 'security', 'key', 'model',
                                       asset=ASSET,
                                       wazuh_context=collect_wazuh(RULE, AGENT, ASSET, 4),
                                       multiaxis_shadow_enabled=True)
        self.assertNotIn('shadow_multiaxis', requests[0].data.decode())
        self.assertNotIn('shadow_multiaxis', requests[1].data.decode())
        self.assertFalse(off['multiaxis_shadow_evidence_used'])
        self.assertFalse(no_shadow['multiaxis_shadow_evidence_used'])

    def test_main_no_additional_calls_notification_unchanged(self):
        from app import main
        primary = {'summary': 'Crítica', 'priority': 'critical', 'evidence': [],
                   'recommendation': 'Revisar', 'classification': 'incident',
                   'false_positive': 'unlikely', 'confidence': 'high', 'notify': True}
        def secondary(*args, **kwargs):
            self.assertTrue(kwargs['multiaxis_shadow_enabled'])
            self.assertIn('shadow_facts', kwargs)
            proposal = native()
            proposal['investigation_evidence_ids'] = ['wazuh.rule_level']
            return {'version': 'gemini-observability-context-v2', 'type': 'advisory_only',
                    'changes_triage': False, 'wazuh_metadata_used': True,
                    'shadow_evidence_used': True,
                    'shadow_recommendation': None,
                    'multiaxis_shadow_evidence_used': True,
                    'multiaxis_shadow_recommendation': proposal}
        with tempfile.TemporaryDirectory() as tmp:
            with patch.multiple(main, DB=Path(tmp)/'test.db', AI_ENABLED=True,
                                AI_REAL_EVENTS_ENABLED=True, GEMINI_KEY='fake',
                                AI_MAX_CALLS_PER_HOUR=2, AI_SHADOW_DECISIONS_ENABLED=True,
                                AI_MULTIAXIS_SHADOW_ENABLED=True,
                                WAZUH_METADATA_ENABLED=True, AI_WAZUH_METADATA_CONTEXT_ENABLED=True,
                                INCIDENT_GROUPING_ENABLED=False, GROUP_EVOLUTION_ENABLED=False,
                                PROMETHEUS_ENRICH_ENABLED=False, WAZUH_INDEXER_ENABLED=False,
                                WAZUH_AGENT_MONITORING_ENABLED=False, LOKI_ENRICH_ENABLED=False,
                                LOKI_TIMELINE_ENABLED=False, CROSS_SOURCE_CORRELATION_ENABLED=False,
                                WAZUH_TEMPORAL_SEQUENCE_ENABLED=False), \
                 patch.object(main, 'gemini_analyze', return_value=primary) as first, \
                 patch.object(main, 'interpret_context', side_effect=secondary) as second:
                main.setup()
                out = main.store('wazuh', 'SSH brute force', '15', '', False, 'unique-multi-1',
                                 asset=ASSET, wazuh_rule=RULE, wazuh_agent=AGENT)
                analysis = out['analysis']
                self.assertEqual(analysis['triage']['decision'], 'notify')
                self.assertEqual(analysis['ai_multiaxis_shadow']['status'], 'evaluated')
                self.assertEqual(analysis['ai_multiaxis_shadow']['recommendation']['investigation'],
                                 'required')
                self.assertFalse(analysis['ai_multiaxis_shadow']['changes_notifications'])
                self.assertEqual(first.call_count, 1)
                self.assertEqual(second.call_count, 1)
                with main.conn() as db:
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM ai_requests').fetchone()[0], 2)

    def test_main_flag_disabled_never_passes_native_instruction(self):
        from app import main
        with tempfile.TemporaryDirectory() as tmp:
            with patch.multiple(main, DB=Path(tmp)/'test.db', AI_ENABLED=False,
                                AI_SHADOW_DECISIONS_ENABLED=True,
                                AI_MULTIAXIS_SHADOW_ENABLED=False,
                                WAZUH_METADATA_ENABLED=True):
                main.setup()
                out = main.store('wazuh', 'test', '15', '', False, 'unique-multi-2',
                                 asset=ASSET, wazuh_rule=RULE, wazuh_agent=AGENT)
                self.assertNotIn('ai_multiaxis_shadow', out['analysis'])

    def test_main_quota_denial_does_not_invent_native_recommendation(self):
        from app import main
        primary = {'summary': 'Crítica', 'priority': 'critical', 'evidence': [],
                   'recommendation': 'Revisar', 'classification': 'incident',
                   'false_positive': 'unlikely', 'confidence': 'high', 'notify': True}
        with tempfile.TemporaryDirectory() as tmp:
            with patch.multiple(main, DB=Path(tmp)/'test.db', AI_ENABLED=True,
                                AI_REAL_EVENTS_ENABLED=True, GEMINI_KEY='fake',
                                AI_MAX_CALLS_PER_HOUR=1, AI_SHADOW_DECISIONS_ENABLED=True,
                                AI_MULTIAXIS_SHADOW_ENABLED=True,
                                WAZUH_METADATA_ENABLED=True, AI_WAZUH_METADATA_CONTEXT_ENABLED=True,
                                PROMETHEUS_ENRICH_ENABLED=False, WAZUH_INDEXER_ENABLED=False,
                                WAZUH_AGENT_MONITORING_ENABLED=False, LOKI_ENRICH_ENABLED=False,
                                LOKI_TIMELINE_ENABLED=False, CROSS_SOURCE_CORRELATION_ENABLED=False,
                                WAZUH_TEMPORAL_SEQUENCE_ENABLED=False), \
                 patch.object(main, 'gemini_analyze', return_value=primary), \
                 patch.object(main, 'interpret_context') as second:
                main.setup()
                out = main.store('wazuh', 'SSH brute force', '15', '', False, 'unique-multi-3',
                                 asset=ASSET, wazuh_rule=RULE, wazuh_agent=AGENT)
                second.assert_not_called()
                self.assertEqual(out['analysis']['ai_multiaxis_shadow']['status'], 'not_evaluated')
                self.assertEqual(out['analysis']['triage']['decision'], 'notify')
