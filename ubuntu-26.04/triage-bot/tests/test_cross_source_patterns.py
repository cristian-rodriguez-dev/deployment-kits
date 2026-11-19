"""Block 5: deterministic, fail-closed, no-network incident correlation tests."""
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from app.cross_source_patterns import correlate
from app.wazuh_enrichment import collect as wazuh_collect
from app.loki_timeline import _base as loki_base, _iso as loki_iso

NOW = 1_794_483_600
ASSET = {
    'name': 'PRIVATE_HOST_KEEP_OUT', 'department': 'Sistemas',
    'job': 'inventario-Sistemas', 'agent_id': '005', 'rule_id': '5763',
}
RULE = {'id': '5763', 'level': 15, 'groups': ['sshd', 'attack']}
AGENT = {'id': '005'}


def _utc(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat(timespec='seconds')


def wazuh():
    return wazuh_collect(RULE, AGENT, ASSET, 2)


def indexer():
    return {
        'version': 'wazuh-indexer-aggregate-v2', 'status': 'ok',
        'source': 'wazuh_indexer_aggregations',
        'scope': 'agent_id_received_last_15m', 'frequency_scope':
        'wazuh_indexer_agent_scoped_alert_documents',
        'window_minutes': 15, 'changes_triage': False,
        'raw_alerts_stored': False, 'sent_to_ai': False,
        'agent_id': '005', 'rule_id': '5763',
        'time_window_utc': {'start': _utc(NOW - 900), 'end': _utc(NOW)},
        'total_alerts_agent_15m': 12, 'alerts_same_rule_agent_15m': 7,
        'top_rules': [{'id': '5763', 'count': 7}, {'id': '5760', 'count': 5}],
    }


def prometheus(state='down'):
    return {
        'version': 'prometheus-readonly-v1', 'status': 'ok',
        'scope': 'verified_exact_target', 'changes_security_decision': False,
        'window_minutes': 15,
        'target': {'nodename': ASSET['name'], 'departamento': ASSET['department'],
                   'job': ASSET['job'], 'instance': ''},
        'availability': {'state': state, 'raw_sample_freshness': 'not_verified'},
        'metrics': {},
    }


def loki(counts=(1, 2, 20), anchor_type='event_time'):
    result = loki_base('ok', NOW, anchor=NOW, anchor_type=anchor_type)
    result.update({
        'selector': {'host': ASSET['name'], 'departamento': ASSET['department'],
                     'inventario': ASSET['job']},
        'buckets': [
            {'start_utc': loki_iso(t - 300), 'end_utc': loki_iso(t), 'entries': n}
            for t, n in zip((NOW - 600, NOW - 300, NOW), counts)
        ],
        'observed_entries_15m': sum(counts),
        'by_unit_source': [{'unit': 'ssh.service', 'source': 'journald',
                            'counts': list(counts)}],
    })
    return result


def run(**sources):
    return correlate(source='wazuh', synthetic=False, asset=ASSET,
                     wazuh_context=wazuh(), now=NOW, **sources)


class CrossSourcePatternTests(unittest.TestCase):
    def test_valid_signals_no_causality_claim(self):
        out = run(wazuh_indexer=indexer(), telemetry=prometheus(),
                  logs_timeline=loki())
        self.assertEqual(out['status'], 'ok')
        self.assertEqual(set(out['sources_validated']), {
            'wazuh_webhook', 'wazuh_indexer', 'prometheus', 'loki_timeline'})
        self.assertEqual([v['kind'] for v in out['signals']], [
            'wazuh_rule_repeated_15m', 'wazuh_multiple_rules_observed_15m',
            'prometheus_scrape_unavailable', 'loki_observed_log_volume_increase',
            'loki_ssh_service_log_volume_increase',
        ])
        self.assertEqual(out['signal_count'], 5)
        self.assertFalse(out['changes_triage'])
        self.assertFalse(out['changes_notifications'])
        self.assertFalse(out['sent_to_ai'])
        output = json.dumps(out)
        self.assertNotIn(ASSET['name'], output)
        self.assertNotIn('005', output)
        self.assertNotIn('5763', output)
        self.assertNotIn('journald', output)
        self.assertNotIn('authentication_failed', output)

    def test_only_webhook_no_signals(self):
        out = run()
        self.assertEqual(out['status'], 'ok')
        self.assertEqual(out['sources_validated'], ['wazuh_webhook'])
        self.assertEqual(out['signal_count'], 0)

    def test_synthetic_grafana_and_mismatched_webhook_rejected(self):
        for source, synthetic, context in (
                ('grafana', False, wazuh()), ('wazuh', True, wazuh()),
                ('wazuh', False, {**wazuh(), 'status': 'unavailable'})):
            out = correlate(source=source, synthetic=synthetic, asset=ASSET,
                            wazuh_context=context, wazuh_indexer=indexer(),
                            telemetry=prometheus(), logs_timeline=loki(), now=NOW)
            self.assertEqual(out['status'], 'insufficient_data')
            self.assertEqual(out['signals'], [])

    def test_indexer_wrong_agent_rule_or_time_rejected(self):
        for change in (
                {'agent_id': '006'}, {'rule_id': '9999'},
                {'time_window_utc': {'start': _utc(NOW - 1900), 'end': _utc(NOW - 1000)}},
                {'raw_alerts_stored': True},
                {'alerts_same_rule_agent_15m': 999},
                {'top_rules': [{'id': '5763', 'count': 7},
                               {'id': '5763', 'count': 7}]},
                {'status': 'unavailable'},
        ):
            with self.subTest(change=change):
                self.assertEqual(run(wazuh_indexer={**indexer(), **change})['signal_count'], 0)

    def test_repetition_threshold(self):
        data = indexer()
        data['alerts_same_rule_agent_15m'] = 2
        data['top_rules'] = [{'id': '5763', 'count': 2}]
        out = run(wazuh_indexer=data)
        self.assertEqual(out['signal_count'], 0)
        self.assertIn('wazuh_indexer', out['sources_validated'])

    def test_prometheus_no_host_shutdown_claim_and_identity_must_match(self):
        out = run(telemetry=prometheus())
        self.assertEqual([x['kind'] for x in out['signals']], ['prometheus_scrape_unavailable'])
        out = run(telemetry=prometheus('up'))
        self.assertEqual(out['signal_count'], 0)
        wrong = prometheus()
        wrong['target']['nodename'] = 'different_host'
        out = run(telemetry=wrong)
        self.assertNotIn('prometheus', out['sources_validated'])
        self.assertEqual(out['signal_count'], 0)

    def test_loki_ssh_volume_is_not_authentication_failure(self):
        out = run(logs_timeline=loki(anchor_type='reception_time'))
        self.assertEqual(out['signal_count'], 2)
        self.assertEqual(out['signals'][0]['anchor_type'], 'reception_time')
        self.assertNotIn('attack', json.dumps(out))
        out = run(logs_timeline=loki(counts=(10, 15, 16)))
        self.assertEqual(out['signal_count'], 0)

    def test_loki_broken_time_ownership_and_counts_fail_closed(self):
        for key, value in (
            ('observed_entries_15m', 900),
            ('scope', 'all_hosts'),
            ('selector', {'host': 'different_host', 'departamento': 'Sistemas'}),
            ('excludes_collector_health', False),
        ):
            with self.subTest(key=key):
                corrupted = loki()
                corrupted[key] = value
                self.assertNotIn('loki_timeline', run(logs_timeline=corrupted)['sources_validated'])

    def test_missing_sensor_not_inferred_down_or_no_attack(self):
        out = run(wazuh_indexer={'status': 'unavailable'},
                  telemetry={'status': 'unavailable'},
                  logs_timeline={'status': 'no_logs'})
        self.assertEqual(out['sources_validated'], ['wazuh_webhook'])
        self.assertEqual(out['signals'], [])

    def test_main_integration_is_opt_in_and_does_not_change_policy(self):
        from app import main
        with tempfile.TemporaryDirectory() as tmp:
            flags = dict(DB=Path(tmp) / 'test.db', AI_ENABLED=False,
                         GEMINI_KEY='', CROSS_SOURCE_CORRELATION_ENABLED=True,
                         WAZUH_METADATA_ENABLED=True, WAZUH_INDEXER_ENABLED=True,
                         WAZUH_AGENT_MONITORING_ENABLED=False,
                         PROMETHEUS_ENRICH_ENABLED=True,
                         PROMETHEUS_URL='http://prometheus.invalid',
                         LOKI_TIMELINE_ENABLED=True, LOKI_URL='http://10.1.1.1:3100',
                         LOKI_ENRICH_ENABLED=False,
                         AI_PROMETHEUS_CONTEXT_ENABLED=False,
                         AI_LOKI_CONTEXT_ENABLED=False,
                         AI_LOKI_TIMELINE_CONTEXT_ENABLED=False,
                         AI_WAZUH_METADATA_CONTEXT_ENABLED=False)
            with patch.multiple(main, **flags), \
                 patch.object(main, 'wazuh_indexer_collect', return_value=indexer()), \
                 patch.object(main, 'prometheus_collect', return_value=prometheus()), \
                 patch.object(main, 'loki_timeline_collect', return_value=loki()), \
                 patch.object(main.time, 'time', return_value=NOW):
                main.setup()
                first = main.store('wazuh', 'SSH brute force', '15',
                                   'Wazuh rule 5763', False, 'block5-a',
                                   asset=ASSET, wazuh_rule=RULE, wazuh_agent=AGENT)
                self.assertTrue(first['analysis']['cross_source_patterns']['signal_count'] >= 3)
                self.assertEqual(first['analysis']['triage']['decision'], 'notify')
                main.CROSS_SOURCE_CORRELATION_ENABLED = False
                second = main.store('wazuh', 'SSH brute force', '15',
                                    'Wazuh rule 5763', False, 'block5-b',
                                    asset=ASSET, wazuh_rule=RULE, wazuh_agent=AGENT)
                self.assertNotIn('cross_source_patterns', second['analysis'])
                self.assertEqual(first['analysis']['triage']['decision'],
                                 second['analysis']['triage']['decision'])
                self.assertEqual(first['mode'], second['mode'])
                with main.conn() as db:
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM ai_requests').fetchone()[0], 0)


if __name__ == '__main__':
    unittest.main()
