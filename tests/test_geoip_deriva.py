import unittest
from pathlib import Path
import yaml
from jinja2 import Environment
import re

ROOT = Path(__file__).resolve().parents[1]
PLAY = ROOT / 'monitorizacion/playbooks/auditar_deriva_geoip_wazuh.yml'

class TestGeoipDrift(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = PLAY.read_text(encoding='utf-8')
        cls.document = yaml.safe_load(cls.content)[0]
        cls.tasks = cls.document['pre_tasks'] + cls.document['tasks']

    def test_yaml_and_target(self):
        self.assertEqual(self.document['hosts'], 'wazuh-servers')
        self.assertFalse(self.document['gather_facts'])

    def test_no_writing_tasks(self):
        prohibited = ['ansible.builtin.copy', 'ansible.builtin.file',
                      'ansible.builtin.template', 'ansible.builtin.command',
                      'ansible.builtin.shell', 'ansible.builtin.service',
                      'ansible.builtin.systemd']
        for task in self.tasks:
            for key in prohibited:
                self.assertNotIn(key, task)
        for task in self.tasks:
            if 'ansible.builtin.uri' in task:
                self.assertEqual(task['ansible.builtin.uri']['method'], 'GET')

    def test_verify_sha256_before_read(self):
        names = [task['name'] for task in self.tasks]
        self.assertLess(names.index('Exigir respaldo privado e inalterado'),
                        names.index('Leer el snapshot validado sin mostrar su definicion'))
        self.assertIn('checksum_algorithm: sha256', self.content)
        self.assertIn('var_geoip_reference_sha256', self.content)

    def test_semantic_comparison_and_reporting(self):
        self.assertIn('var_geoip_definitions_equal', self.content)
        self.assertIn('DERIVA DETECTADA', self.content)
        self.assertIn('SIN CAMBIOS', self.content)
        self.assertIn('var_geoip_effective_fail_on_drift', self.content)

    def test_secret_protection(self):
        self.assertIn("VAR_WAZUH_ADMIN_PASSWORD", self.content)
        self.assertIn('no_log: true', self.content)
        self.assertNotIn('debug: var_geoip_current_definition', self.content)

    def test_regex_matches_actual_reference_filename(self):
        expr = self.document["pre_tasks"][0]["ansible.builtin.assert"]["that"][7]
        regex_literal = expr.split("match(", 1)[1].rsplit(")", 1)[0]
        pattern = Environment().from_string("{{ " + regex_literal + " }}").render()
        self.assertTrue(re.match(pattern, "/var/backups/wazuh-geoip/filebeat-7.10.2-wazuh-alerts-pipeline-8a24edf01dabfd0.json"))

    def test_example_is_valid(self):
        example = yaml.safe_load((ROOT/'monitorizacion/examples/variables_geoip_deriva.yml').read_text(encoding='utf-8'))
        self.assertEqual(len(example['var_geoip_reference_sha256']), 64)
        self.assertTrue(example['var_geoip_reference_file'].startswith('/'))

if __name__ == '__main__':
    unittest.main()
