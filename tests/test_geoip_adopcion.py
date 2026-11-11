from pathlib import Path
import unittest
import yaml

BASE = Path(__file__).resolve().parents[1]
PLAYBOOK = BASE / 'monitorizacion/playbooks/adoptar_geoip_wazuh.yml'

class GeoipAdopcionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = PLAYBOOK.read_text(encoding='utf-8')
        cls.play = yaml.safe_load(cls.text)[0]
        cls.tasks = cls.play.get('tasks', [])
        cls.pre = cls.play.get('pre_tasks', [])

    def test_yaml_and_target(self):
        self.assertEqual(self.play['hosts'], 'wazuh-servers')
        self.assertTrue(self.play['become'])
        self.assertFalse(self.play['gather_facts'])

    def test_no_writes_to_indexer(self):
        for task in self.tasks:
            uri = task.get('ansible.builtin.uri')
            if uri:
                self.assertIn(uri['method'], ['GET', 'POST'])
                self.assertTrue('simulate' in str(uri['url']).lower() or uri['method'] == 'GET')
                self.assertTrue(task.get('no_log'))
                self.assertFalse(task.get('changed_when'))

    def test_snapshot_gated(self):
        for task in self.tasks:
            if 'ansible.builtin.copy' in task or 'ansible.builtin.file' in task:
                self.assertIn('var_geoip_effective_save', str(task['when']))

    def test_no_shells(self):
        self.assertNotIn('ansible.builtin.shell:', self.text)
        self.assertNotIn('ansible.builtin.command:', self.text)
        self.assertNotIn('docker compose', self.text)
        self.assertNotIn('method: PUT', self.text)
        self.assertNotIn('method: DELETE', self.text)

    def test_secret_handling(self):
        self.assertIn("VAR_WAZUH_ADMIN_PASSWORD", self.text)
        for task in self.tasks:
            if task.get('ansible.builtin.copy'):
                self.assertTrue(task.get('no_log'))
                self.assertFalse(task.get('diff'))

    def test_unique_backup_and_hash(self):
        self.assertIn("| hash('sha256')", self.text)
        self.assertIn('force: false', self.text)
        self.assertIn("mode: '0600'", self.text)
        self.assertIn("mode: '0700'", self.text)

    def test_simulation_matches_wazuh_message_json(self):
        self.assertIn("message: \"{{ var_geoip_sample_alert | to_json }}\"", self.text)
        self.assertIn("srcip: '8.8.8.8'", self.text)
        self.assertNotIn('''            - _source:\n                data:\n                  srcip: 8.8.8.8''', self.text)

    def test_simulation_diagnostic_exposes_no_document(self):
        diagnostic = next(t for t in self.tasks if t['name'] == 'Mostrar diagnostico de simulacion sin datos sensibles')
        self.assertNotIn('var_geoip_sim_source }}', str(diagnostic))
        self.assertNotIn('var_geoip_sim_result.json }}', str(diagnostic))
        self.assertIn('Error de procesamiento', str(diagnostic))

    def test_default_audit(self):
        self.assertIn('var_geoip_save_snapshot | default(false) | bool', self.text)
        self.assertIn('var_geoip_simulate | default(false) | bool', self.text)

if __name__ == '__main__':
    unittest.main()
