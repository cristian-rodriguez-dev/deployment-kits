"""Pruebas estáticas, sin conectar a AWX ni Grafana."""
from pathlib import Path
import unittest

try:
    import yaml
except ImportError as exc:
    raise RuntimeError('Instala PyYAML para ejecutar estas pruebas: pip install pyyaml') from exc

ROOT = Path(__file__).resolve().parents[1]
MONITOR = ROOT / 'monitorizacion'


class GrafanaContractTests(unittest.TestCase):
    def test_all_playbooks_and_taskfiles_are_valid_yaml(self):
        for file in sorted(MONITOR.rglob('*.yml')):
            with self.subTest(file=str(file.relative_to(ROOT))):
                obj = yaml.safe_load(file.read_text(encoding='utf-8'))
                self.assertIsInstance(obj, (list, dict))

    def test_awx_playbooks_target_existing_group(self):
        for name in ['auditar_grafana.yml', 'configurar_dashboards_grafana.yml']:
            playbook = yaml.safe_load((MONITOR / 'playbooks' / name).read_text())
            self.assertEqual(playbook[0]['hosts'], 'grafana-servers')
            self.assertTrue(playbook[0]['become'])

    def test_apply_flags_default_to_false(self):
        examples = yaml.safe_load(
            (MONITOR / 'examples' / 'variables_dashboards_grafana.yml').read_text()
        )
        self.assertIs(examples['var_grafana_dashboards_apply'], False)
        self.assertIs(examples['var_grafana_dashboards_allow_updates'], False)

    def test_no_delete_or_container_reconfiguration(self):
        contents = '\n'.join(
            f.read_text() for f in (MONITOR / 'playbooks').glob('*.yml')
        ) + '\n' + '\n'.join(
            f.read_text() for f in (MONITOR / 'tasks' / 'grafana').glob('*.yml')
        )
        self.assertNotIn('method: DELETE', contents)
        self.assertNotIn('docker_compose_v2', contents)
        self.assertNotIn('docker_container', contents)
        self.assertIn('dashboard.grafana.app/v2', contents)
        self.assertIn('status_code: 201', contents)

    def test_json_path_is_empty_until_user_exports(self):
        self.assertEqual(list((MONITOR / 'dashboards').glob('*.json')), [])


if __name__ == '__main__':
    unittest.main()
