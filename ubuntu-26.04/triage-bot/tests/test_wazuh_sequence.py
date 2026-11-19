"""Block 7: verified single-agent receipt timeline, read-only and opt-in."""
import json
from contextlib import contextmanager
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.wazuh_sequence import summarize, VERSION, CANDIDATE_LIMIT
from app.wazuh_enrichment import collect as wazuh_collect

NOW = 1_794_483_600
ASSET = {'name': 'PRIVATE_AGENT_1', 'agent_id': '005', 'rule_id': '5763',
         'department': 'Sistemas', 'job': 'inventario-Sistemas'}
RULE = {'id': '5763', 'level': 15, 'groups': ['sshd']}
AGENT = {'id': '005'}


def context(rule_id='5763', agent_id='005', host=None):
    asset = {**ASSET, 'rule_id': rule_id, 'agent_id': agent_id}
    if host is not None: asset['name'] = host
    return wazuh_collect({'id': rule_id, 'level': 15}, {'id': agent_id}, asset, 0)


@contextmanager
def database():
    db = sqlite3.connect(':memory:')
    db.executescript('''
        CREATE TABLE incidents(id INTEGER PRIMARY KEY, source TEXT,
              synthetic INTEGER, analysis TEXT);
        CREATE TABLE triage_context(incident_id INTEGER, created_ts INTEGER,
              source TEXT, host TEXT, rule_key TEXT);
    ''')
    try:
        yield db
    finally:
        db.close()


def previous(db, ident, ts, rule='5763', agent='005', host=ASSET['name'],
             synthetic=False, meta=None, source='wazuh'):
    if meta is None: meta = context(rule, agent, host)
    db.execute('INSERT INTO incidents VALUES(?,?,?,?)',
               (ident, source, int(synthetic), json.dumps({'wazuh_context':meta})))
    db.execute('INSERT INTO triage_context VALUES(?,?,?,?,?)',
               (ident, ts, source, host, rule))


def run(db, **extra):
    args = dict(source='wazuh', synthetic=False, asset=ASSET,
                wazuh_context=context(), now=NOW)
    args.update(extra)
    return summarize(db, **args)


class WazuhSequenceTests(unittest.TestCase):
    def test_no_previous_is_valid_empty_sequence(self):
        with database() as db:
            out = run(db)
        self.assertEqual(out['status'], 'ok')
        self.assertEqual(out['previous_verified_incidents'], 0)
        self.assertEqual(out['timeline'], [{'incident_id':None,'rule_id':'5763','age_seconds':0}])
        self.assertEqual(out['observations'], [])
        self.assertEqual(out['version'], VERSION)
        for key in ('changes_triage','changes_notifications','sent_to_ai','raw_logs_stored'):
            self.assertIs(out[key], False)

    def test_chronology_repetition_distinct_rules_and_five_min_burst(self):
        with database() as db:
            previous(db, 1, NOW - 240, '5763')
            previous(db, 2, NOW - 120, '5760')
            previous(db, 3, NOW - 60, '5763')
            out = run(db)
        self.assertEqual(out['previous_verified_incidents'], 3)
        self.assertEqual(out['prior_same_rule'], 2)
        self.assertEqual(out['distinct_rule_count_including_current'], 2)
        self.assertEqual(out['observations'], [
            'same_rule_received_at_least_3_times_30m',
            'different_wazuh_rules_received_30m',
            'at_least_3_webhooks_received_5m'])
        self.assertEqual([r['age_seconds'] for r in out['timeline']], [240,120,60,0])
        self.assertEqual([r['incident_id'] for r in out['timeline']], [1,2,3,None])
        self.assertNotIn(ASSET['name'], json.dumps(out))
        self.assertNotIn('005', json.dumps(out))

    def test_only_real_exact_agent_verified_previous(self):
        with database() as db:
            previous(db, 1, NOW - 5, '5763', '006')
            previous(db, 2, NOW - 6, '5760', '005', 'OTHER_HOST')
            previous(db, 3, NOW - 7, '5760', '005', synthetic=True)
            previous(db, 4, NOW - 8, '5760', '005', meta={'status':'ok'})
            previous(db, 5, NOW - 9, '5760', '005', source='grafana')
            previous(db, 6, NOW - 1801, '5763')
            previous(db, 7, NOW + 1, '5763')
            previous(db, 8, NOW - 10, '5763')
            out = run(db)
        self.assertEqual(out['previous_verified_incidents'], 1)
        self.assertEqual([r['incident_id'] for r in out['timeline']], [8,None])
        self.assertEqual(out['observations'], [])

    def test_invalid_current_source_synthetic_or_identity_fail_closed(self):
        with database() as db:
            previous(db, 1, NOW - 10)
            for override in [
                    {'source':'grafana'}, {'synthetic':True},
                    {'asset':{'name':'OTHER_HOST'}},
                    {'wazuh_context':{'status':'ok'}},
                    {'now':float(NOW)},
                    {'now':NOW-1_800_000_000}]:
                with self.subTest(override=override):
                    out = run(db, **override)
                    self.assertEqual(out['status'], 'insufficient_data')
                    self.assertEqual(out['timeline'], [])

    def test_invalid_previous_metadata_and_malformed_json_are_skipped(self):
        with database() as db:
            previous(db, 1, NOW - 10)
            # Same agent ID but wrong host inside verified metadata: excluded.
            previous(db, 2, NOW - 20, meta=context(host='OTHER_HOST'))
            db.execute("INSERT INTO incidents VALUES(3,'wazuh',0,'not-json')")
            db.execute("INSERT INTO triage_context VALUES(3,?, 'wazuh', ?, '5763')", (NOW-30,ASSET['name']))
            out = run(db)
        self.assertEqual(out['previous_verified_incidents'], 1)
        self.assertEqual(out['prior_same_rule'], 1)

    def test_bounded_output_and_truncation(self):
        with database() as db:
            for i in range(1,CANDIDATE_LIMIT+3):
                previous(db, i, NOW-300+i, '5763')
            out = run(db)
        self.assertEqual(out['previous_verified_incidents'], CANDIDATE_LIMIT)
        self.assertTrue(out['truncated'])
        self.assertEqual(len(out['timeline']), 6)
        self.assertEqual(out['timeline'][-1]['incident_id'], None)

    def test_main_feature_flag_integrates_after_triage_no_new_ai_call(self):
        from app import main
        with tempfile.TemporaryDirectory() as folder:
            flags = dict(DB=Path(folder)/'incident_test.db', AI_ENABLED=False,
                         GEMINI_KEY='', WAZUH_METADATA_ENABLED=True,
                         WAZUH_TEMPORAL_SEQUENCE_ENABLED=True,
                         CROSS_SOURCE_CORRELATION_ENABLED=False,
                         WAZUH_INDEXER_ENABLED=False,
                         WAZUH_AGENT_MONITORING_ENABLED=False,
                         PROMETHEUS_ENRICH_ENABLED=False,
                         LOKI_ENRICH_ENABLED=False,
                         LOKI_TIMELINE_ENABLED=False,
                         AI_PROMETHEUS_CONTEXT_ENABLED=False,
                         AI_LOKI_CONTEXT_ENABLED=False,
                         AI_LOKI_TIMELINE_CONTEXT_ENABLED=False,
                         AI_WAZUH_METADATA_CONTEXT_ENABLED=False)
            with patch.multiple(main, **flags),patch.object(main.time,'time',return_value=NOW):
                main.setup()
                results=[]
                for i in range(3):
                    results.append(main.store('wazuh','SSH brute force','15','rule 5763',
                                              False,f'block7-{i}',asset=ASSET,
                                              wazuh_rule=RULE,wazuh_agent=AGENT,
                                              context={'host':ASSET['name'],'rule_key':'5763','category':'security'}))
                self.assertEqual(results[2]['analysis']['temporal_sequence']['previous_verified_incidents'],2)
                self.assertEqual(results[2]['analysis']['temporal_sequence']['observations'],[
                    'same_rule_received_at_least_3_times_30m',
                    'at_least_3_webhooks_received_5m'])
                self.assertEqual(results[2]['analysis']['triage']['decision'], 'notify')
                main.WAZUH_TEMPORAL_SEQUENCE_ENABLED=False
                off=main.store('wazuh','SSH brute force','15','rule 5763',False,'block7-off',
                               asset=ASSET,wazuh_rule=RULE,wazuh_agent=AGENT,
                               context={'host':ASSET['name'],'rule_key':'5763','category':'security'})
                self.assertNotIn('temporal_sequence',off['analysis'])
                self.assertEqual(off['analysis']['triage']['decision'],'notify')
                with main.conn() as c:
                    self.assertEqual(c.execute('SELECT COUNT(*) FROM ai_requests').fetchone()[0],0)

    def test_dashboard_bridge_and_internal_view_remain_authenticated(self):
        root = Path(__file__).resolve().parents[1]
        bridge = (root/'access/bridge.py').read_text(encoding='utf8')
        self.assertIn('if not authorized(',bridge)
        for name in ('app/dashboard.html','access/dashboard.html'):
            html = (root/name).read_text(encoding='utf8')
            self.assertIn('renderTemporalSequence(i,area)',html)
            self.assertIn('Secuencia temporal de Wazuh',html)
            self.assertIn('Orden por recepción del bot',html)
            self.assertNotIn('.innerHTML',html)
            self.assertNotIn('localStorage',html)
        self.assertIn("fetch('/api/incidents'", (root/'access/dashboard.html').read_text())


if __name__ == '__main__':
    unittest.main()
