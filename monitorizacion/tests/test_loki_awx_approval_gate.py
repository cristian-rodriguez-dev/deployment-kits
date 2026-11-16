"""Pilas Observabilidad / Bloque 19F. Solo pruebas offline, sin AWX/K3s.

Verifica el contrato del playbook posterior a una APROBACION AWX.
La aprobacion misma solo puede acreditarla la configuracion real del Workflow AWX.
"""
from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "playbooks" / "revalidar_loki_k3s_post_aprobacion.yml"
DIAGNOSTIC = ROOT / "playbooks" / "auditar_loki_k3s_remediacion.yml"

try:
    import yaml
    from jinja2.nativetypes import NativeEnvironment
except ImportError:
    yaml = None
    NativeEnvironment = None


class StaticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = PLAYBOOK.read_text(encoding="utf-8")

    def test_reuses_existing_19c_without_reimplementing_kubectl(self):
        self.assertIn("- import_playbook: auditar_loki_k3s_remediacion.yml", self.content)
        self.assertTrue(DIAGNOSTIC.exists(), "Instalar primero el Bloque 19C")
        self.assertNotIn("ansible.builtin.command:", self.content)

    def test_no_mutating_ansible_modules(self):
        forbidden = ("ansible.builtin.shell:", "ansible.builtin.raw:",
                     "ansible.builtin.service:", "ansible.builtin.systemd:",
                     "ansible.builtin.copy:", "ansible.builtin.file:",
                     "ansible.builtin.script:", "ansible.builtin.uri:",
                     "kubernetes.core.k8s:", "ansible.builtin.reboot:")
        for term in forbidden:
            with self.subTest(term=term):
                self.assertNotIn(term, self.content)

    def test_single_host_is_enforced(self):
        self.assertIn("ansible_play_hosts_all | length == 1", self.content)
        self.assertIn("inventory_hostname == 'ansible_server'", self.content)
        self.assertIn("hosts: prometheus-servers", self.content)

    def test_no_explicit_action_or_trust(self):
        for clause in ("execution_allowed: false", "action_executed: false",
                       "changes_kubernetes: false", "changes_triage: false",
                       "changes_notifications: false", "approval_verified: false",
                       "requires_external_workflow_validation: true"):
            with self.subTest(clause=clause):
                self.assertIn(clause, self.content)

    def test_fails_closed_on_identity_and_unknown_readiness(self):
        for phrase in ("'logging'", "'loki-0'", "'loki'", "'kubernetes_api'",
                       "get('ready') is none", "get('ready') is boolean"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.content)
        self.assertIn("status: >-", self.content)
        self.assertIn("loki_readiness_unknown", self.content)

    def test_does_not_claim_workflow_approval_via_playbook(self):
        self.assertNotIn("approval_verified: true", self.content)


@unittest.skipUnless(yaml is not None and NativeEnvironment is not None,
                     "Se requieren PyYAML y Jinja2 para pruebas estructurales")
class ParsedPlaybookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = yaml.safe_load(PLAYBOOK.read_text(encoding="utf-8"))
        cls.play = cls.doc[1]
        cls.tasks = cls.play['tasks']
        cls.assertions = cls.tasks[0]['ansible.builtin.assert']['that']
        cls.report = cls.tasks[1]['ansible.builtin.debug']['msg']
        cls.env = NativeEnvironment()

    def render(self, key: str, ready):
        observation = {
            'source': 'kubernetes_api', 'namespace': 'logging',
            'pod': 'loki-0', 'container': 'loki',
            'pod_found': True, 'container_found': True,
            'ready': ready, 'observed_at_utc': '2026-11-16T12:15:09Z'
        }
        return self.env.from_string(self.report[key]).render(var_loki_diag_observation=observation)

    def test_yaml_has_one_exact_import_and_one_play(self):
        self.assertEqual(len(self.doc), 2)
        self.assertEqual(self.doc[0], {'import_playbook': 'auditar_loki_k3s_remediacion.yml'})

    def test_play_fixed_target(self):
        self.assertEqual(self.play['hosts'], 'prometheus-servers')
        self.assertIs(self.play['gather_facts'], False)
        self.assertIs(self.play['become'], False)
        self.assertIs(self.play['any_errors_fatal'], True)

    def test_only_assert_and_debug_tasks(self):
        self.assertEqual(len(self.tasks), 2)
        self.assertEqual({k for k in self.tasks[0] if k.startswith('ansible.builtin.')},
                         {'ansible.builtin.assert'})
        self.assertEqual({k for k in self.tasks[1] if k.startswith('ansible.builtin.')},
                         {'ansible.builtin.debug'})
        self.assertIs(self.tasks[0]['no_log'], True)

    def test_contract_has_exact_fixed_target(self):
        self.assertEqual(self.report['target'], {'namespace':'logging','pod':'loki-0','container':'loki'})

    def test_healthy_ready_leads_to_no_action(self):
        self.assertEqual(self.render('status', True), 'no_action')
        self.assertEqual(self.render('reason_code', True), 'loki_ready')

    def test_not_ready_requires_investigation_not_restart(self):
        self.assertEqual(self.render('status', False), 'investigate')
        self.assertEqual(self.render('reason_code', False), 'loki_not_ready_requires_investigation')

    def test_unknown_requires_investigation(self):
        self.assertEqual(self.render('status', None), 'investigate')
        self.assertEqual(self.render('reason_code', None), 'loki_readiness_unknown')

    def test_nonready_never_authorizes_execution(self):
        self.assertIs(self.report['execution_allowed'], False)
        self.assertIs(self.report['action_executed'], False)
        self.assertIs(self.report['approval_verified'], False)

    def test_no_restoration_path_or_mutation(self):
        keys = set(self.report)
        self.assertNotIn('remediation_command', keys)
        self.assertNotIn('restart_service', keys)
        self.assertNotIn('kubectl_action', keys)

    def test_assert_enforces_core_observation_schema(self):
        text = ' '.join(self.assertions)
        for key in ('source', 'namespace', 'pod', 'container', 'pod_found',
                    'container_found', 'ready', 'observed_at_utc'):
            self.assertIn(key, text)

    def test_has_no_template_overrides_in_playbook(self):
        forbidden = ('vars_prompt', 'extra_vars', 'add_host', 'include_vars', 'delegate_to')
        for k in forbidden:
            self.assertNotIn(k, self.play)


if __name__ == '__main__':
    unittest.main()
