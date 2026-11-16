"""Offline contract checks for 19H. Never imports Ansible or calls systemctl."""
from pathlib import Path
import unittest

import yaml
from jinja2 import Environment

HERE = Path(__file__).resolve().parents[1]
PLAYBOOK = HERE / 'playbooks' / 'recuperar_alloy_host_post_aprobacion.yml'


class AlloyRecoveryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = PLAYBOOK.read_text(encoding='utf-8')
        cls.play = yaml.safe_load(cls.text)[0]
        cls.tasks = cls.play['tasks']
        cls.pre = cls.play['pre_tasks']
        cls.env = Environment(autoescape=False)

    def get_task(self, label):
        return next(t for t in self.tasks if label in t.get('name', ''))

    def test_yaml_valid(self):
        self.assertEqual(len(yaml.safe_load(self.text)), 1)

    def test_project_scope(self):
        self.assertIn('deployment-kits / Bloque 19H', self.text)
        self.assertEqual(self.play['hosts'], 'prometheus-servers')

    def test_strict_single_host(self):
        guards = '\n'.join(self.pre[0]['ansible.builtin.assert']['that'])
        self.assertIn("inventory_hostname == 'ansible_server'", guards)
        self.assertIn('ansible_play_hosts_all | length == 1', guards)

    def test_default_audit(self):
        self.assertIn("default('audit')", self.play['vars']['var_alloy_recovery_mode_effective'])

    def test_apply_requires_confirmation(self):
        guard = '\n'.join(self.pre[0]['ansible.builtin.assert']['that'])
        self.assertIn('START_ALLOY_ONLY_AFTER_AWX_APPROVAL', guard)
        self.assertIn("['audit', 'apply']", guard)

    def test_reject_check_mode(self):
        self.assertIn('not ansible_check_mode', self.pre[0]['ansible.builtin.assert']['that'])

    def test_only_one_systemd_mutation(self):
        mutations = [t['ansible.builtin.systemd_service'] for t in self.tasks
                     if 'ansible.builtin.systemd_service' in t]
        self.assertEqual(mutations, [{'name': 'alloy.service', 'state': 'started'}])
        self.assertNotIn('state: restarted', self.text)
        self.assertNotIn('state: stopped', self.text)

    def test_mutation_requires_apply_inactive_recheck(self):
        job = self.get_task('Iniciar exclusivamente Alloy')
        conditions = '\n'.join(job['when'])
        self.assertIn("var_alloy_recovery_mode_effective == 'apply'", conditions)
        self.assertIn("var_alloy_recovery_active == 'inactive'", conditions)
        self.assertIn("ActiveState=inactive", conditions)

    def test_no_shell_or_unbounded_modifications(self):
        forbidden = {'ansible.builtin.shell', 'ansible.builtin.script', 'ansible.builtin.apt',
                     'ansible.builtin.file', 'ansible.builtin.copy', 'ansible.builtin.template'}
        self.assertTrue(all(not (set(task) & forbidden) for task in self.tasks + self.pre))
        self.assertNotIn('daemon_reload: true', self.text)

    def test_only_fixed_commands(self):
        commands = [t['ansible.builtin.command']['argv'] for t in self.tasks
                    if 'ansible.builtin.command' in t]
        self.assertTrue(commands)
        allowed = {'systemctl', 'kubectl', 'alloy', 'runuser'}
        self.assertTrue(all(c[0] in allowed for c in commands))
        self.assertTrue(all(not any('{{' in token for token in c) for c in commands))

    def test_failed_service_blocked(self):
        task = self.get_task('Rechazar reinicio')
        self.assertIn("var_alloy_recovery_active != 'failed'", task['ansible.builtin.assert']['that'])

    def test_requires_hardened_user_group(self):
        task = self.get_task('Verificar que es el servicio esperado')
        guards = '\n'.join(task['ansible.builtin.assert']['that'])
        for v in ('User=alloy', 'Group=alloy', 'CanStart=yes', 'NeedDaemonReload=no'):
            self.assertIn(v, guards)

    def test_requires_configuration_validation(self):
        task = self.get_task('Validar configuracion Alloy')
        self.assertEqual(task['ansible.builtin.command']['argv'],
                         ['alloy', 'validate', '/etc/alloy/config.alloy'])
        self.assertTrue(task['no_log'])

    def test_existing_positions_fail_closed(self):
        self.assertIn('positions.yml', self.text)
        self.assertIn('runuser', self.text)
        self.assertIn('var_alloy_recovery_positions_write.rc == 0', self.text)
        self.assertIn("pw_name | default('') == 'alloy'", self.text)

    def test_independent_k3s_storage_required(self):
        task = self.get_task('Exigir separacion de almacenamiento')
        guards = '\n'.join(task['ansible.builtin.assert']['that'])
        self.assertIn('/var/lib/alloy-k3s', guards)
        self.assertIn("^/var/lib/alloy(/|$)", guards)

    def test_only_known_k3s_resource(self):
        job = self.get_task('Consultar Deployment Alloy')
        self.assertEqual(job['ansible.builtin.command']['argv'],
                         ['kubectl', '--request-timeout=10s', '-n', 'logging',
                          'get', 'deployment', 'alloy', '-o', 'json'])

    def test_apply_checks_active_after(self):
        self.assertIn('var_alloy_recovery_final.stdout | trim == \'ActiveState=active\'',
                      '\n'.join(self.get_task('Exigir servicio activo')['ansible.builtin.assert']['that']))

    def test_report_no_false_provenance(self):
        msg = self.get_task('Mostrar solo resultado protegido')['ansible.builtin.debug']['msg']
        self.assertFalse(msg['approval_verified'])
        self.assertTrue(msg['requires_external_workflow_validation'])
        self.assertFalse(msg['changes_k3s'])
        self.assertFalse(msg['changes_notifications'])
        self.assertFalse(msg['changes_triage'])

    def test_audit_status_rendering(self):
        template = self.env.from_string(self.get_task('Mostrar solo resultado protegido')
                                        ['ansible.builtin.debug']['msg']['status'])
        self.assertEqual(template.render(var_alloy_recovery_active='active',
                                         var_alloy_recovery_mode_effective='audit').strip(),
                         'no_action')
        self.assertEqual(template.render(var_alloy_recovery_active='inactive',
                                         var_alloy_recovery_mode_effective='audit').strip(),
                         'ready_for_manual_approval')
        self.assertEqual(template.render(var_alloy_recovery_active='inactive',
                                         var_alloy_recovery_mode_effective='apply',
                                         var_alloy_recovery_start={'changed': True}).strip(),
                         'started_and_verified')

    def test_docs_exist(self):
        doc = (HERE / 'docs' / 'BLOQUE19H_ALLOY_RECUPERACION_AWX.md')
        self.assertTrue(doc.exists())
        self.assertIn('workflow', doc.read_text(encoding='utf-8').lower())


if __name__ == '__main__':
    unittest.main()
