"""No real network calls, no notification delivery, temporary SQLite only."""
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import contextual_analysis as ctx
from app.wazuh_enrichment import collect as wazuh_collect


ASSET = {
    'agent_id': '005', 'rule_id': '5763',
    'name': 'PRIVATE_HOST_KEEP_OUT', 'department': 'Sistemas',
}
RULE = {'id': '5763', 'level': 15, 'groups': ['sshd', 'attack'], 'mitre': {'id': ['T1110']}}
AGENT = {'id': '005'}


def wazuh_context():
    return wazuh_collect(RULE, AGENT, ASSET, 2)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.close()


class ContextOnlyTests(unittest.TestCase):
    def test_wazuh_works_without_prometheus(self):
        data = ctx.validated_context(None, 'wazuh', 'security',
                                     asset=ASSET, wazuh_context=wazuh_context())
        self.assertIn('wazuh_metadata', data)
        self.assertNotIn('observed', data)
        self.assertNotIn('loki_aggregates', data)
        self.assertNotIn('PRIVATE_HOST_KEEP_OUT', json.dumps(data))
        self.assertNotIn('005', json.dumps(data))

    def test_prometheus_backward_compatible_without_wazuh(self):
        telemetry = {
            'status': 'ok', 'scope': 'verified_exact_target',
            'availability': {'state': 'up'}, 'metrics': {},
        }
        data = ctx.validated_context(telemetry, 'grafana', 'availability')
        self.assertIn('observed', data)
        self.assertNotIn('wazuh_metadata', data)

    def test_formatter_accepts_both_advisory_versions(self):
        from app.notification_format import _diagnostic_context
        for version in ('gemini-prometheus-context-v1',
                        'gemini-observability-context-v2'):
            result = _diagnostic_context({'telemetry_context': {
                'version': version, 'type': 'advisory_only',
                'changes_triage': False, 'summary': 'Observado',
                'technical_reading': 'Se necesitan mas comprobaciones',
                'recommended_checks': ['Revisar agente'], 'confidence': 'low',
            }})
            self.assertEqual(result['summary'], 'Observado')
        self.assertIsNone(_diagnostic_context({'telemetry_context': {
            'version': 'gemini-observability-context-v2',
            'type': 'advisory_only', 'changes_triage': True,
        }}))

    def test_grafana_cannot_reuse_wazuh_context(self):
        self.assertIsNone(ctx.validated_context(None, 'grafana', 'other',
                          asset=ASSET, wazuh_context=wazuh_context()))

    def test_mismatched_identity_rejected(self):
        bad_asset = {**ASSET, 'agent_id': '004'}
        self.assertIsNone(ctx.validated_context(None, 'wazuh', 'security',
                          asset=bad_asset, wazuh_context=wazuh_context()))

    def test_no_sources_rejected(self):
        self.assertIsNone(ctx.validated_context(None, 'wazuh', 'security'))
        with self.assertRaises(ValueError):
            ctx.interpret(None, 'wazuh', 'security', 'test-key', 'fake-model')

    def test_bad_sources_rejected(self):
        self.assertIsNone(ctx.validated_context(None, 'other', 'security',
                          asset=ASSET, wazuh_context=wazuh_context()))
        self.assertIsNone(ctx.validated_context(None, 'wazuh', 'fake-family',
                          asset=ASSET, wazuh_context=wazuh_context()))

    def test_mocked_gemini_prompt_has_only_sanitized_wazuh(self):
        response = {'candidates': [{'content': {'parts': [{
            'text': json.dumps({
                'summary': 'Analisis limitado',
                'technical_reading': 'Metadatos de alerta, no confirma ataque',
                'recommended_checks': ['Revisar el estado del agente'],
                'confidence': 'low',
                'notify': False,
                'priority': 'critical',
            })
        }]}}]}
        requests = []
        def fake_urlopen(req, timeout):
            requests.append(req)
            return FakeResponse(json.dumps(response).encode())
        with patch.object(ctx.urllib.request, 'urlopen', fake_urlopen):
            result = ctx.interpret(None, 'wazuh', 'security',
                                   'test-key', 'fake-model',
                                   asset=ASSET, wazuh_context=wazuh_context())
        self.assertEqual(len(requests), 1)
        body = requests[0].data.decode()
        self.assertIn('wazuh_metadata', body)
        self.assertNotIn('PRIVATE_HOST_KEEP_OUT', body)
        self.assertNotIn('"agent_id"', body)
        self.assertNotIn('"rule_id"', body)
        self.assertTrue(result['wazuh_metadata_used'])
        self.assertIsNone(result['observed'])
        self.assertFalse(result['changes_triage'])
        self.assertNotIn('notify', result)
        self.assertNotIn('priority', result)
        self.assertEqual(result['version'], 'gemini-observability-context-v2')

    def test_main_quota_and_triage_unchanged_without_prometheus(self):
        from app import main
        fake_primary = {
            'summary': 'Alerta Wazuh', 'priority': 'critical',
            'evidence': [], 'recommendation': 'Revisar', 'uncertainty': '',
            'classification': 'incident', 'false_positive': 'unlikely',
            'confidence': 'high', 'notify': True, 'reason': 'Nivel alto',
        }
        fake_secondary = {
            'version': 'gemini-observability-context-v2',
            'type': 'advisory_only', 'changes_triage': False,
            'wazuh_metadata_used': True,
            'loki_aggregates_used': False,
            'loki_timeline_used': False,
            'summary': 'Resumen', 'technical_reading': 'Lectura',
            'recommended_checks': [], 'confidence': 'low',
        }
        with tempfile.TemporaryDirectory() as tmp:
            patches = dict(
                DB=Path(tmp) / 'test.db', AI_ENABLED=True,
                AI_REAL_EVENTS_ENABLED=True, GEMINI_KEY='fake-key',
                AI_MAX_CALLS_PER_HOUR=10, WAZUH_METADATA_ENABLED=True,
                AI_WAZUH_METADATA_CONTEXT_ENABLED=True,
                AI_PROMETHEUS_CONTEXT_ENABLED=False,
                AI_LOKI_CONTEXT_ENABLED=False,
                AI_LOKI_TIMELINE_CONTEXT_ENABLED=False,
                PROMETHEUS_ENRICH_ENABLED=False,
                WAZUH_INDEXER_ENABLED=False,
                WAZUH_AGENT_MONITORING_ENABLED=False,
                LOKI_ENRICH_ENABLED=False, LOKI_TIMELINE_ENABLED=False,
            )
            with patch.multiple(main, **patches), \
                 patch.object(main, 'gemini_analyze', return_value=fake_primary), \
                 patch.object(main, 'interpret_context', return_value=fake_secondary) as secondary:
                main.setup()
                out = main.store('wazuh', 'SSH brute force', '15',
                                 'Wazuh rule 5763', False, 'unique-b2',
                                 asset=ASSET, wazuh_agent=AGENT, wazuh_rule=RULE)
                self.assertFalse(out['duplicate'])
                self.assertEqual(out['mode'], 'gemini')
                self.assertTrue(out['analysis']['wazuh_context']['sent_to_ai'])
                self.assertEqual(out['analysis']['telemetry_context']['version'],
                                 'gemini-observability-context-v2')
                secondary.assert_called_once()
                args, kwargs = secondary.call_args
                self.assertIsNone(args[0])  # no Prometheus metrics
                self.assertEqual(kwargs['wazuh_context']['status'], 'ok')
                self.assertEqual(out['analysis']['triage']['decision'], 'notify')
                with sqlite3.connect(main.DB) as db:
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM ai_requests').fetchone()[0], 2)

    def test_no_safe_context_does_not_spend_second_ai_call(self):
        from app import main
        with tempfile.TemporaryDirectory() as tmp:
            patches = dict(
                DB=Path(tmp) / 'test.db', AI_ENABLED=True,
                AI_REAL_EVENTS_ENABLED=True, GEMINI_KEY='fake-key',
                AI_MAX_CALLS_PER_HOUR=10, WAZUH_METADATA_ENABLED=False,
                AI_WAZUH_METADATA_CONTEXT_ENABLED=True,
                AI_PROMETHEUS_CONTEXT_ENABLED=False,
                AI_LOKI_CONTEXT_ENABLED=False,
                AI_LOKI_TIMELINE_CONTEXT_ENABLED=False,
                PROMETHEUS_ENRICH_ENABLED=False,
                WAZUH_INDEXER_ENABLED=False,
                WAZUH_AGENT_MONITORING_ENABLED=False,
                LOKI_ENRICH_ENABLED=False, LOKI_TIMELINE_ENABLED=False,
            )
            primary = {
                'summary': 'ok', 'priority': 'critical', 'evidence': [],
                'classification': 'incident', 'notify': True,
                'confidence': 'high', 'false_positive': 'unlikely',
            }
            with patch.multiple(main, **patches), \
                 patch.object(main, 'gemini_analyze', return_value=primary), \
                 patch.object(main, 'interpret_context') as secondary:
                main.setup()
                out = main.store('wazuh', 'SSH brute force', '15',
                                 'Wazuh rule 5763', False, 'unique-b2-empty',
                                 asset=ASSET, wazuh_agent=AGENT, wazuh_rule=RULE)
                secondary.assert_not_called()
                self.assertNotIn('telemetry_context', out['analysis'])
                with sqlite3.connect(main.DB) as db:
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM ai_requests').fetchone()[0], 1)


if __name__ == '__main__':
    unittest.main()
