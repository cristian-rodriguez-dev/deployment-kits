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

    # Nuevas pruebas para el cierre seguro del Job 05 (sin AWX ni Docker).
    def test_11_default_mode_never_installs(self):
        from jinja2 import Environment
        env = Environment()
        mode = env.compile_expression("var_grafana_job05_mode | default('inspect')")
        self.assertEqual(mode(), 'inspect')
        names = [task['name'] for task in self.pre]
        end_idx = names.index('Terminar inspeccion sin ejecutar tareas de despliegue')
        self.assertEqual(self.pre[end_idx]['ansible.builtin.meta'], 'end_play')
        self.assertEqual(self.pre[end_idx]['when'],
                         "(var_grafana_job05_mode | default('inspect')) == 'inspect'")
        for task in self.pre[:end_idx + 1]:
            self.assertTrue(set(task).intersection({'ansible.builtin.assert',
                'ansible.builtin.stat', 'ansible.builtin.slurp',
                'ansible.builtin.debug', 'ansible.builtin.meta'}), task['name'])
            self.assertNotIn("default('install')", str(task))
        self.assertNotIn("default('install')", PLAYBOOK.read_text(encoding='utf8'))

    def test_12_explicit_confirmation_and_project_collision(self):
        from jinja2 import Environment
        names = [t['name'] for t in self.pre]
        approval = self.pre[names.index('Exigir confirmacion explicita para instalar Grafana nuevo')]
        expr = Environment().compile_expression(approval['ansible.builtin.assert']['that'][0])
        self.assertFalse(expr())
        self.assertFalse(expr(var_grafana_job05_confirm='INVALID'))
        self.assertTrue(expr(var_grafana_job05_confirm='INSTALL_NEW_GRAFANA'))
        self.assertEqual(approval['when'],
                         "(var_grafana_job05_mode | default('inspect')) == 'install'")
        cmd = self.pre[names.index('Detectar contenedores del proyecto Compose de Grafana')]
        self.assertEqual(cmd['ansible.builtin.command']['argv'][:4],
                         ['docker', 'ps', '-aq', '--filter'])
        self.assertFalse(cmd.get('changed_when', True))
        collision = self.pre[names.index('Bloquear un proyecto Compose de Grafana preexistente')]
        self.assertIn("== ''", collision['ansible.builtin.assert']['that'][0])
        self.assertLess(names.index('Bloquear un proyecto Compose de Grafana preexistente'),
                        names.index('Comprobar si AWX ya preparó esta instalación'))

    def test_13_install_guard_matrix(self):
        from jinja2 import Environment
        from pathlib import PurePosixPath
        env = Environment()
        env.filters['basename'] = lambda value: PurePosixPath(value).name
        env.filters['bool'] = bool
        names = [t['name'] for t in self.pre]
        guard = self.pre[names.index('Bloquear sobreescritura de instalaciones operativas')]
        expr = env.compile_expression(guard['ansible.builtin.assert']['that'][0])

        def allowed(existing, entries=(), smtp=False, isdir=True,
                    islnk=False):
            kw = {
                'var_grafana_existing_dir': {'stat': {'exists': existing,
                                         'isdir': isdir, 'islnk': islnk}},
                'var_grafana_existing_entries': {'files': [
                    {'path': '/srv/grafana/' + v} for v in entries]},
                'var_grafana_smtp_enabled': smtp,
            }
            return bool(expr(**kw))

        self.assertTrue(allowed(False))
        self.assertTrue(allowed(True, []))
        self.assertTrue(allowed(True, ['.env'], smtp=True))
        self.assertFalse(allowed(True, ['.env'], smtp=False))
        self.assertFalse(allowed(True, ['data']))
        self.assertFalse(allowed(True, ['.env', 'other'], smtp=True))
        self.assertFalse(allowed(True, [], isdir=False))
        self.assertFalse(allowed(True, [], islnk=True))

        full_text = ' '.join(guard['ansible.builtin.assert']['that'])
        for field in ['var_grafana_existing_compose', 'var_grafana_existing_data',
                      'var_grafana_existing_database', 'var_grafana_existing_provisioning',
                      'var_grafana_existing_secrets', 'var_grafana_existing_state']:
            self.assertIn('not ' + field + '.stat.exists', full_text)
        finder = self.pre[names.index('Inventariar contenido previo del directorio objetivo')]
        self.assertTrue(finder['ansible.builtin.find']['hidden'])
        self.assertEqual(finder['ansible.builtin.find']['file_type'], 'any')

    def test_14_smtp_preprovision_is_private_and_no_symlink(self):
        names = [t['name'] for t in self.pre]
        task = self.pre[names.index('Exigir .env protegido para instalacion limpia con SMTP')]
        statements = ' '.join(task['ansible.builtin.assert']['that'])
        self.assertIn('isreg', statements)
        self.assertIn('islnk', statements)
        self.assertIn('uid', statements)
        self.assertIn("'0600'", statements)
        self.assertTrue(self.pre[names.index('Comprobar claves SMTP sin revelar sus valores')]['no_log'])
        self.assertTrue(self.pre[names.index('Rechazar credenciales SMTP ausentes o vacias')]['no_log'])

    def test_15_guard_precedes_mutating_tasks_and_checks_installer_vars_late(self):
        names = [task['name'] for task in self.pre]
        self.assertEqual(self.pre[0]['name'], 'Validar modo seguro del Job 05 y ruta objetivo')
        self.assertLess(names.index('Terminar inspeccion sin ejecutar tareas de despliegue'),
                        names.index('Comprobar que AWX proporciona las variables de instalacion'))
        self.assertLess(names.index('Bloquear sobreescritura de instalaciones operativas'),
                        names.index('Comprobar que AWX proporciona las variables de instalacion'))
        self.assertLess(names.index('Bloquear un proyecto Compose de Grafana preexistente'),
                        len(names))
        self.assertEqual(self.tasks[0]['name'], 'Instalar dependencia de los módulos Docker')
        self.assertTrue(all('ansible.builtin.apt' not in t and
                            'community.docker.docker_compose_v2' not in t and
                            'ansible.builtin.template' not in t and
                            'ansible.builtin.copy' not in t for t in self.pre))

if __name__ == '__main__':
    unittest.main()
