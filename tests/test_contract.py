"""Pruebas estáticas: ni grafana ni AWX se modifican."""
from pathlib import Path
import json
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
MON = ROOT / "monitorizacion"

class ContractTests(unittest.TestCase):
    def test_yaml_parses(self):
        for path in MON.rglob("*.yml"):
            with self.subTest(path=path.name):
                yaml.safe_load(path.read_text(encoding="utf-8"))

    def test_auditor_is_read_only(self):
        data = yaml.safe_load((MON/'playbooks'/'auditar_grafana.yml').read_text())[0]
        self.assertFalse(data['become'])
        self.assertFalse(data['gather_facts'])
        self.assertEqual(data['hosts'],'grafana-servers')
        source=(MON/'playbooks'/'auditar_grafana.yml').read_text()
        self.assertNotIn('method: PUT',source)
        self.assertNotIn('method: POST',source)
        self.assertNotIn('method: DELETE',source)
        self.assertIn('var_grafana_missing_settings',source)
        self.assertIn('VAR_GRAFANA_ADMIN_PASSWORD',source)

    def test_management_forbids_apply(self):
        source=(MON/'playbooks'/'configurar_dashboards_grafana.yml').read_text()
        self.assertIn('Impedir escrituras durante la fase',source)
        self.assertIn('not (var_grafana_dashboards_apply | default(false) | bool)',source)
        flags=yaml.safe_load((MON/'examples'/'variables_dashboards_grafana.yml').read_text())
        self.assertFalse(flags['var_grafana_dashboards_apply'])
        self.assertFalse(flags['var_grafana_dashboards_allow_updates'])

    def test_imported_jsons_are_exactly_sixteen_v2_with_376_panels(self):
        dashboards=[]
        for p in (MON/'dashboards').glob('*.json'):
            with self.subTest(path=p.name):
                data=json.loads(p.read_text(encoding='utf-8'))
                self.assertEqual(data['kind'],'Dashboard')
                self.assertEqual(data['apiVersion'],'dashboard.grafana.app/v2')
                self.assertEqual(data['metadata']['namespace'],'default')
                self.assertTrue(data['metadata']['name'])
                dashboards.append(data)
        self.assertEqual(len(dashboards),16)
        self.assertEqual(len(set(x['metadata']['name'] for x in dashboards)),16)
        self.assertEqual(sum(sum(1 for e in x['spec']['elements'].values() if e.get('kind')=='Panel') for x in dashboards),376)
        triage = [x for x in dashboards
                  if x['metadata']['name'] == 'security-triage-observabilidad']
        self.assertEqual(len(triage), 1)
        self.assertEqual(triage[0]['spec']['title'], 'Security Triage — Observabilidad del Bot')
        self.assertEqual(sum(e.get('kind') == 'Panel'
                             for e in triage[0]['spec']['elements'].values()), 25)

if __name__=='__main__': unittest.main()
