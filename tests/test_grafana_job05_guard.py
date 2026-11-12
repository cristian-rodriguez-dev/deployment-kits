"""Static regression checks for the protected legacy Grafana installer.

Run with: python -m unittest discover -s tests -p test_grafana_job05_guard.py -v
No Docker / Ansible environment is required.
"""
import json
import unittest
from pathlib import Path

import yaml
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / 'monitorizacion/playbooks/instalar_grafana.yml'
TEMPLATE = ROOT / 'monitorizacion/templates/grafana/docker-compose.yml.j2'

class Job05Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.play = yaml.safe_load(PLAYBOOK.read_text(encoding='utf8'))[0]
        cls.pre = cls.play['pre_tasks']
        cls.tasks = cls.play['tasks']
        cls.template = TEMPLATE.read_text(encoding='utf8')

    def _render(self, smtp):
        j = Environment(undefined=StrictUndefined, keep_trailing_newline=True)
        j.filters['to_json'] = lambda value: json.dumps(value, ensure_ascii=False)
        j.filters['bool'] = bool
        data = dict(
            var_grafana_image='grafana/grafana:13.2.3',
            var_grafana_admin_user='admin',
            var_grafana_admin_email='admin@localhost',
            var_grafana_port=3000,
            var_grafana_install_dir='/srv/grafana',
            var_monitorizacion_network='monitorizacion',
            var_grafana_smtp_enabled=smtp,
        )
        return yaml.safe_load(j.from_string(self.template).render(**data))

    def test_01_valid_yaml(self):
        self.assertEqual(self.play['hosts'], 'grafana-servers')

    def test_02_guard_is_before_first_mutating_task(self):
        names = [t['name'] for t in self.pre]
        self.assertLess(names.index('Bloquear sobreescritura de instalaciones operativas'),
                        names.index('Comprobar sistema operativo'))
        self.assertTrue(any(t.get('ansible.builtin.meta') == 'end_play' for t in self.pre))
        self.assertIn('not var_grafana_existing_compose.stat.exists',
                      str(self.pre))
        self.assertIn('not var_grafana_existing_database.stat.exists',
                      str(self.pre))

    def test_03_no_write_in_inspect(self):
        names = [t['name'] for t in self.pre]
        self.assertLess(names.index('Terminar inspeccion sin ejecutar tareas de despliegue'),
                        names.index('Bloquear sobreescritura de instalaciones operativas'))
        self.assertTrue(any(t.get('ansible.builtin.slurp') for t in self.pre))

    def test_04_template_smtp_opt_in(self):
        env = self._render(True)['services']['grafana']['environment']
        self.assertEqual(env['GF_SMTP_ENABLED'], 'true')
        self.assertEqual(env['GF_SMTP_HOST'], '${GRAFANA_SMTP_HOST}')
        self.assertEqual(env['GF_SMTP_USER'], '${GRAFANA_SMTP_USER}')
        self.assertEqual(env['GF_SMTP_PASSWORD'], '${GRAFANA_SMTP_PASSWORD}')
        self.assertEqual(env['GF_SMTP_FROM_ADDRESS'], '${GRAFANA_SMTP_FROM_ADDRESS}')
        self.assertEqual(env['GF_SMTP_SKIP_VERIFY'], 'false')

    def test_05_template_no_smtp_by_default(self):
        env = self._render(False)['services']['grafana']['environment']
        self.assertNotIn('GF_SMTP_ENABLED', env)
        self.assertNotIn('GF_SMTP_PASSWORD', env)

    def test_06_persistent_mounts_unchanged(self):
        for smtp in (True, False):
            compose = self._render(smtp)
            svc = compose['services']['grafana']
            self.assertIn('/srv/grafana/data:/var/lib/grafana', svc['volumes'])
            self.assertIn('/srv/grafana/provisioning:/etc/grafana/provisioning:ro', svc['volumes'])
            self.assertIn('/srv/grafana/secrets/admin_password:/run/secrets/grafana_admin_password:ro', svc['volumes'])
            self.assertEqual(compose['networks']['red_monitorizacion']['name'], 'monitorizacion')

    def test_07_no_inline_smtp_secrets_in_playbook(self):
        self.assertNotIn('TU_CONTRASEÑA', self.template)
        self.assertNotIn('GF_SMTP_PASSWORD: "hardcoded', self.template)
        self.assertIn('GF_SMTP_PASSWORD: "${GRAFANA_SMTP_PASSWORD}"', self.template)

    def test_08_no_secret_output_in_preflight(self):
        smtp_tasks = [t for t in self.pre if 'SMTP' in t['name']]
        sensitive_tasks = [t for t in smtp_tasks if 'ansible.builtin.slurp' in t or
                           'Rechazar credenciales' in t['name']]
        self.assertTrue(sensitive_tasks)
        self.assertTrue(all(t.get('no_log') is True for t in sensitive_tasks))

    def test_09_smtp_compose_validation_uses_private_env(self):
        task = next(t for t in self.tasks if t['name'] == 'Generar y validar Docker Compose')
        validate = task['ansible.builtin.template']['validate']
        self.assertIn('--env-file {{ var_grafana_install_dir }}/.env', validate)
        self.assertIn('-f %s config --quiet', validate)

    def test_10_no_service_image_upgrade_or_prune(self):
        text = PLAYBOOK.read_text(encoding='utf8')
        self.assertNotIn('docker system prune', text)
        self.assertNotIn('pull: always', text)

if __name__ == '__main__':
    unittest.main()
