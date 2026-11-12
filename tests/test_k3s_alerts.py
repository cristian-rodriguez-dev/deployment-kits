import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'monitorizacion' / 'files'))
import grafana_k3s_rules as m

ANCHOR={"uid":"old","title":m.ANCHOR,"folderUID":"infra123","ruleGroup":"Infrastructure","orgID":1}

class Client:
    def __init__(self, current=None):
        self.current = current if current is not None else [ANCHOR]
        self.created = []
    def request(self, path, method='GET', payload=None):
        if path == '/api/datasources/uid/prometheus':
            return {'uid':'prometheus','type':'prometheus'}
        if path == '/api/v1/provisioning/alert-rules':
            if method == 'POST':
                self.created.append(payload)
                return {'uid':payload['uid'],'isPaused':payload['isPaused']}
            return self.current
        if path.startswith('/api/datasources/proxy/'):
            return {'status':'success','data':{'result':[{'value':[1,'2']} ]}}
        raise AssertionError(path)

class Tests(unittest.TestCase):
    def test_plan_readonly(self):
        c=Client(); x=m.execute(c,'plan'); self.assertEqual(x['pending'],2); self.assertEqual(c.created,[])
    def test_apply_creates_paused(self):
        c=Client(); x=m.execute(c,'apply'); self.assertEqual(x['created_paused'],2)
        self.assertTrue(all(x['isPaused'] for x in c.created))
    def test_protect_collision(self):
        c=Client([ANCHOR, {'title':m.RULES[0]['title'],'uid':'other'}]);
        with self.assertRaises(m.SafeError):m.execute(c,'apply')
    def test_idempotent(self):
        planned=[m.build_payload(r,ANCHOR) for r in m.RULES]
        c=Client([ANCHOR]+planned); x=m.execute(c,'apply')
        self.assertEqual(x['existing'],2); self.assertEqual(len(c.created),0)
    def test_metric_missing_stops(self):
        class Missing(Client):
            def request(self,*a,**kw):
                if '/proxy/' in a[0]: return {'status':'success','data':{'result':[]}}
                return super().request(*a,**kw)
        c=Missing();
        with self.assertRaises(m.SafeError):m.execute(c,'apply')
        self.assertEqual(c.created,[])
    def test_protected_models(self):
        for rule in m.RULES:
            p=m.build_payload(rule,ANCHOR)
            self.assertEqual(p['condition'],'B')
            self.assertEqual(p['noDataState'],'OK')
            self.assertEqual(p['data'][1]['model']['conditions'][0]['evaluator']['params'],[0])
    def test_anchor_required(self):
        c=Client([])
        with self.assertRaises(m.SafeError):m.execute(c,'plan')
    def test_no_unexpected_yaml_options(self):
        import yaml
        p=Path(__file__).resolve().parents[1]/'monitorizacion'/'playbooks'/'crear_alertas_k3s_grafana.yml'
        doc=yaml.safe_load(p.read_text())
        self.assertEqual(doc[0]['hosts'],'grafana-servers')
        copies=[task for task in doc[0]['tasks'] if 'ansible.builtin.copy' in task]
        self.assertEqual(len(copies),1)
        self.assertNotIn('diff',copies[0]['ansible.builtin.copy'])
