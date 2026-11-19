"""Block 9: group evolution is view-only, fail-closed, and opt-in."""
from pathlib import Path
from unittest.mock import patch
import copy
import tempfile
import unittest

from app.group_evolution import annotate as evolve, VERSION
from app.incident_groups import annotate as group
from test_incident_groups import event


def run(rows):
    return evolve(group(rows))


class GroupEvolutionTests(unittest.TestCase):
    def test_verified_peak_increase_and_rule_introduction(self):
        rows = [event(3, 240, rule='5760', level=15),
                event(1, 0, rule='5710', level=6),
                event(2, 120, rule='5763', level=10)]
        original = copy.deepcopy(rows)
        result = run(rows)
        self.assertEqual(rows, original)
        self.assertEqual([row['id'] for row in result], [3, 1, 2])
        for row in result:
            e = row['group_evolution']
            self.assertEqual(e['version'], VERSION)
            self.assertEqual(e['status'], 'observed')
            self.assertEqual(e['member_count'], 3)
            self.assertEqual(e['group_id'], 'wazuh-window-1')
            self.assertEqual((e['first_rule_level'], e['latest_rule_level'], e['max_rule_level']),
                             (6, 15, 15))
            self.assertTrue(e['peak_increased_after_first'])
            self.assertEqual(e['introduced_rule_ids'], ['5760', '5763'])
            self.assertEqual(e['review_priority'], 'critical')
            self.assertEqual(e['priority_source'], 'max_verified_wazuh_rule_level')
            self.assertEqual(e['review_indicators'],
                             ['later_higher_rule_level','new_rule_ids','burst_5m'])
            self.assertEqual(row['analysis']['priority'], 'low')
            self.assertEqual(row['analysis']['triage']['decision'], 'notify')
            for flag in ('changes_triage','changes_notifications','sent_to_ai','automatic_actions'):
                self.assertIs(e[flag], False)
        self.assertEqual(result[0]['incident_group']['max_rule_level'], 15)

    def test_last_lower_level_is_not_recovery_and_peak_remains(self):
        result = run([event(1, 0, rule='5760', level=7),
                      event(2, 40, rule='5763', level=15),
                      event(3, 80, rule='5763', level=4)])
        e = result[0]['group_evolution']
        self.assertEqual((e['first_rule_level'],e['latest_rule_level'],e['max_rule_level']),
                         (7,4,15))
        self.assertTrue(e['peak_increased_after_first'])
        self.assertEqual(e['review_priority'],'critical')
        self.assertNotIn('recovered',str(e))

    def test_no_increase_repeated_rule_keeps_verified_priority(self):
        result = run([event(1,0,level=12),event(2,80,level=7)])
        e = result[0]['group_evolution']
        self.assertFalse(e['peak_increased_after_first'])
        self.assertEqual(e['review_priority'],'high')
        self.assertEqual(e['review_indicators'],[])
        self.assertEqual(e['introduced_rule_ids'],[])

    def test_distinct_verified_identity_never_joins(self):
        result = run([event(1),event(2,10,agent='006'),
                      event(3,20,host='OTHER'),event(4,30,department='Devs')])
        self.assertEqual([x['group_evolution']['status'] for x in result],['single']*4)

    def test_invalid_metadata_synthetic_grafana_and_unavailable(self):
        rows = [event(1),event(2,1,synthetic=True),
                event(3,2,source='grafana'),event(4,3)]
        rows[-1]['analysis']['wazuh_context']['status']='unavailable'
        result = run(rows)
        self.assertEqual([x['group_evolution']['status'] for x in result],
                         ['single','not_applicable','not_applicable','insufficient_data'])

    def test_anchored_window_and_incomplete_sample(self):
        rows = [event(1),event(2,1700),event(3,3400)]
        result = run(rows)
        self.assertEqual([x['group_evolution']['status'] for x in result],
                         ['observed','observed','single'])
        self.assertTrue(result[0]['group_evolution']['limited_history'])
        result = run([event(i,i*5) for i in range(1,60)])
        self.assertEqual(len(result),50)
        self.assertEqual(result[0]['group_evolution']['member_count'],50)

    def test_corrupted_group_contract_rejected_and_not_mutated(self):
        grouped = group([event(1),event(2,10)])
        grouped[0]['incident_group']['member_ids'] = [1,3]
        original = copy.deepcopy(grouped)
        result = evolve(grouped)
        self.assertEqual(grouped, original)
        self.assertEqual([r['group_evolution']['status'] for r in result],
                         ['insufficient_data']*2)

    def test_tampered_identity_and_mismatched_priority_rejected(self):
        grouped = group([event(1),event(2,1)])
        grouped[1]['analysis']['asset']['agent_id'] = '999'
        result = evolve(grouped)
        self.assertEqual([r['group_evolution']['status'] for r in result],
                         ['insufficient_data']*2)
        grouped = group([event(1),event(2,1)])
        grouped[0]['incident_group']['max_priority'] = 'critical'
        self.assertEqual(evolve(grouped)[0]['group_evolution']['status'],'insufficient_data')

    def test_duplicate_ids_fail_closed_and_invalid_input(self):
        result = run([event(1),event(1,10),event(2,20)])
        self.assertTrue(all(r['group_evolution']['status'] in
                            ('insufficient_data','single') for r in result))
        self.assertEqual(evolve(None),[])
        self.assertEqual(evolve([]),[])
        self.assertEqual(evolve([None,42]),[])
        self.assertEqual(evolve([{'id': []}])[0]['group_evolution']['status'],
                         'insufficient_data')

    def test_opt_in_endpoint_and_no_persistent_changes(self):
        from app import main
        with tempfile.TemporaryDirectory() as tmp:
            with patch.multiple(main, DB=Path(tmp)/'evolution.sqlite',
                                AI_ENABLED=False,WAZUH_METADATA_ENABLED=True,
                                INCIDENT_GROUPING_ENABLED=True,GROUP_EVOLUTION_ENABLED=True):
                main.setup()
                for ident,level in ((1,7),(2,15)):
                    row = event(ident,level=level)
                    main.store('wazuh','SSH','15','desc',False,f'block9-{ident}',
                               asset=row['analysis']['asset'],
                               wazuh_rule={'id':'5763','level':level},
                               wazuh_agent={'id':'005'},
                               context={'host':'PC_SISTEMAS_1','rule_key':'5763','category':'security'})
                with patch.object(main,'authorize',return_value=None):
                    observed = main.incidents(authorization='test')
                    self.assertEqual(len(observed),2)
                    self.assertEqual(observed[0]['group_evolution']['status'],'observed')
                    with patch.object(main,'GROUP_EVOLUTION_ENABLED',False):
                        disabled = main.incidents(authorization='test')
                        self.assertNotIn('group_evolution',disabled[0])
                    with patch.object(main,'INCIDENT_GROUPING_ENABLED',False):
                        disabled = main.incidents(authorization='test')
                        self.assertNotIn('incident_group',disabled[0])
                        self.assertNotIn('group_evolution',disabled[0])
                with main.conn() as connection:
                    self.assertEqual(connection.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],2)
                    self.assertEqual(connection.execute('SELECT COUNT(*) FROM ai_requests').fetchone()[0],0)
                self.assertEqual(observed[0]['analysis'],disabled[0]['analysis'])

    def test_endpoint_authentication_unchanged(self):
        from app import main
        with patch.object(main,'TOKEN','test-block9-token'):
            with self.assertRaises(Exception) as caught:
                main.incidents(authorization='Bearer invalid')
        self.assertEqual(getattr(caught.exception,'status_code',None),401)


if __name__ == '__main__':
    unittest.main()
