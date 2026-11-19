"""Block 8: deterministic read-only grouping of verified Wazuh incidents."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
import copy
import json
import tempfile
import unittest

from app.incident_groups import annotate, VERSION
from app.wazuh_enrichment import collect as wazuh_collect

START = datetime(2026, 11, 12, 14, 0, tzinfo=timezone.utc)


def event(ident, seconds=0, *, agent='005', host='PC_SISTEMAS_1',
          rule='5763', level=10, department='Sistemas', synthetic=False,
          source='wazuh'):
    asset = {'name': host, 'agent_id': agent, 'rule_id': rule,
             'department': department, 'job': 'inventario-Sistemas'}
    meta = wazuh_collect({'id': rule, 'level': level, 'groups': ['sshd']},
                         {'id': agent}, asset, 0)
    return {
        'id': ident, 'source': source, 'synthetic': synthetic,
        'received_at': (START + timedelta(seconds=seconds)).isoformat(),
        'title': 'Evento', 'severity': str(level), 'mode': 'rules_only',
        'analysis': {'asset': asset, 'wazuh_context': meta, 'priority': 'low',
                     'triage': {'decision': 'notify'}}
    }


class IncidentGroupingTests(unittest.TestCase):
    def test_same_agent_30min_group_is_annotated_without_mutating_rows(self):
        rows = [event(3, 240, rule='5760', level=7),
                event(2, 120, rule='5763', level=15),event(1)]
        before = copy.deepcopy(rows)
        out = annotate(rows)
        self.assertEqual(rows, before)
        self.assertEqual([r['id'] for r in out], [3, 2, 1])
        for r in out:
            g = r['incident_group']
            self.assertEqual(g['status'], 'grouped')
            self.assertEqual(g['group_id'], 'wazuh-window-1')
            self.assertEqual(g['member_ids'], [1, 2, 3])
            self.assertEqual(g['member_count'], 3)
            self.assertEqual(g['rule_ids'], ['5760', '5763'])
            self.assertEqual(g['max_rule_level'], 15)
            self.assertEqual(g['max_priority'], 'critical')
            self.assertEqual(g['observations'], ['repeated_rule','multiple_rules','burst_5m'])
            for field in ('changes_triage', 'changes_notifications',
                          'sent_to_ai', 'automatic_actions'):
                self.assertIs(g[field], False)
            self.assertTrue(g['limited_history'])
        self.assertEqual(out[0]['analysis']['triage']['decision'], 'notify')
        self.assertNotIn('PC_SISTEMAS_1', json.dumps(out[0]['incident_group']))
        self.assertNotIn('005', json.dumps(out[0]['incident_group']))

    def test_distinct_agents_and_hosts_and_departments_never_merge(self):
        rows = [event(1), event(2, 1, agent='006'),
                event(3, 2, host='PC_DEV_1'),
                event(4, 3, department='Devs')]
        self.assertEqual([r['incident_group']['status'] for r in annotate(rows)],
                         ['single'] * 4)

    def test_fuzzy_host_not_merged(self):
        rows = [event(1, host='HOST_1'), event(2, 10, host='host_1')]
        self.assertEqual([r['incident_group']['status'] for r in annotate(rows)],
                         ['single', 'single'])

    def test_anchored_window_prevents_transitive_chain(self):
        rows = [event(1),event(2, 1700),event(3, 3400)]
        groups = [r['incident_group'] for r in annotate(rows)]
        self.assertEqual([g['status'] for g in groups], ['grouped','grouped','single'])
        self.assertEqual(groups[0]['member_ids'], [1,2])

    def test_exact_30_min_boundary(self):
        rows = [event(1), event(2, 1800)]
        self.assertEqual(annotate(rows)[0]['incident_group']['member_count'],2)
        rows = [event(1), event(2, 1801)]
        self.assertEqual(annotate(rows)[0]['incident_group']['status'],'single')

    def test_missing_mismatched_or_unauthenticated_metadata_excluded(self):
        rows = [event(1),event(2,10),event(3,20),event(4,30)]
        rows[1]['analysis']['wazuh_context']['status']='unavailable'
        rows[2]['analysis']['asset']['agent_id']='006'
        rows[3]['analysis']['wazuh_context']['selector']['host']='FORGED'
        out = annotate(rows)
        self.assertEqual(out[0]['incident_group']['status'],'single')
        for r in out[1:]:
            self.assertEqual(r['incident_group']['status'],'insufficient_data')

    def test_no_synthetic_grafana_or_other_source(self):
        rows = [event(1),event(2,1,synthetic=True),event(3,2,source='grafana'),
                event(4,3,source='loki')]
        out = annotate(rows)
        self.assertEqual([r['incident_group']['status'] for r in out],
                         ['single','not_applicable','not_applicable','not_applicable'])

    def test_missing_bad_time_or_bad_id_are_fail_closed(self):
        invalid = [event(i, i) for i in range(1,7)]
        invalid[0]['received_at']='not a timestamp'
        invalid[1]['received_at']='2026-11-12T14:00:00'  # timezone required
        invalid[2]['id']=True
        invalid[3]['analysis']={}
        invalid[4]['received_at']=None
        invalid[5]['id']=-5
        self.assertTrue(all(row['incident_group']['status']=='insufficient_data'
                            for row in annotate(invalid)))

    def test_limits_50_records_and_marks_partial_history(self):
        rows = [event(i, i*3) for i in range(1,60)]
        out = annotate(rows)
        self.assertEqual(len(out),50)
        self.assertEqual(out[0]['incident_group']['member_count'],50)
        self.assertTrue(out[0]['incident_group']['limited_history'])
        self.assertEqual(len(out[0]['incident_group']['member_ids']),50)

    def test_priority_uses_rule_level_not_gemini(self):
        out = annotate([event(1,level=15),event(2,1,level=2)])
        self.assertEqual(out[0]['incident_group']['max_priority'],'critical')
        self.assertEqual(out[0]['analysis']['priority'],'low')

    def test_three_in_5m_rolling_burst(self):
        rows = [event(1,0),event(2,600),event(3,650),event(4,700)]
        self.assertIn('burst_5m',annotate(rows)[0]['incident_group']['observations'])
        rows = [event(1,0),event(2,350),event(3,700)]
        self.assertNotIn('burst_5m',annotate(rows)[0]['incident_group']['observations'])

    def test_distinct_source_rule_and_no_inferred_attack(self):
        result = annotate([event(1),event(2,10,rule='5760')])
        group = result[0]['incident_group']
        self.assertEqual(group['distinct_rule_count'],2)
        self.assertEqual(group['observations'],['multiple_rules'])
        self.assertNotIn('attack',json.dumps(group))
        self.assertEqual(group['version'], VERSION)

    def test_main_opt_in_is_read_only_and_preserves_incidents(self):
        from app import main
        with tempfile.TemporaryDirectory() as temp:
            flags = dict(DB=Path(temp)/'grouping.sqlite', AI_ENABLED=False,
                         WAZUH_METADATA_ENABLED=True, INCIDENT_GROUPING_ENABLED=True)
            with patch.multiple(main, **flags):
                main.setup()
                for num in (1,2):
                    kwargs = event(num)['analysis']
                    main.store('wazuh', 'SSH test', '15', 'desc', False, f'block8-{num}',
                               asset=kwargs['asset'],
                               wazuh_rule={'id':'5763','level':15},
                               wazuh_agent={'id':'005'},
                               context={'host':'PC_SISTEMAS_1','rule_key':'5763','category':'security'})
                with patch.object(main,'authorize', return_value=None):
                    actual = main.incidents(authorization='test')
                    self.assertEqual(len(actual),2)
                    self.assertEqual(actual[0]['incident_group']['status'],'grouped')
                    main.INCIDENT_GROUPING_ENABLED=False
                    off = main.incidents(authorization='test')
                    self.assertNotIn('incident_group',off[0])
                with main.conn() as c:
                    self.assertEqual(c.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],2)
                    self.assertEqual(c.execute('SELECT COUNT(*) FROM ai_requests').fetchone()[0],0)
                self.assertEqual(actual[0]['analysis']['triage'],off[0]['analysis']['triage'])

    def test_endpoint_stays_authenticated(self):
        from app import main
        with patch.object(main,'TOKEN','random-test-token'):
            with self.assertRaises(Exception) as ctx:
                main.incidents(authorization='Bearer incorrect')
        self.assertEqual(getattr(ctx.exception,'status_code',None),401)

    def test_duplicate_ids_are_not_grouped(self):
        rows = [event(1), event(1,10), event(2,20)]
        self.assertEqual([r['incident_group']['status'] for r in annotate(rows)],
                         ['insufficient_data','insufficient_data','single'])

    def test_invalid_input_no_data_leak(self):
        self.assertEqual(annotate(None),[])
        self.assertEqual(annotate([]),[])
        self.assertEqual(annotate([None,42]),[])
        bad = event(1); bad['id'] = []
        self.assertEqual(annotate([bad])[0]['incident_group']['status'],
                         'insufficient_data')


if __name__ == '__main__':
    unittest.main()
