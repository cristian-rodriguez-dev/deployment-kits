"""Pruebas OFFLINE del Job AWX 19C, sin Kubernetes ni red.

Con PyYAML/Jinja2 instalados añade pruebas de interpretación de contenedores.
"""
from __future__ import annotations

from pathlib import Path
import unittest

PLAYBOOK = Path(__file__).resolve().parents[1] / "playbooks" / "auditar_loki_k3s_remediacion.yml"

try:
    import yaml
    from jinja2.nativetypes import NativeEnvironment
except ImportError:
    yaml = None
    NativeEnvironment = None


class StaticSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = PLAYBOOK.read_text(encoding="utf-8")

    def test_uses_existing_inventory_group(self):
        self.assertIn("hosts: prometheus-servers", self.content)
        self.assertIn("inventory_hostname == 'ansible_server'", self.content)
        self.assertIn("ansible_play_hosts_all | length == 1", self.content)

    def test_read_only_modules(self):
        for forbidden in ("ansible.builtin.shell:", "ansible.builtin.copy:",
                          "ansible.builtin.service:", "ansible.builtin.systemd:",
                          "ansible.builtin.k8s:", "ansible.builtin.file:",
                          "ansible.builtin.uri:", "ansible.builtin.script:"):
            self.assertNotIn(forbidden, self.content)
        self.assertEqual(self.content.count("ansible.builtin.command:"), 2)
        self.assertEqual(self.content.count("changed_when: false"), 2)

    def test_fixed_kubernetes_target(self):
        self.assertIn("- logging\n", self.content)
        self.assertIn("- loki-0\n", self.content)
        self.assertIn("'name', 'equalto', 'loki'", self.content)
        self.assertIn("--ignore-not-found", self.content)

    def test_unknown_readiness_is_not_false(self):
        self.assertIn("else none", self.content)
        self.assertIn("is boolean", self.content)

    def test_scope_checked_after_api(self):
        self.assertIn("var_loki_diag_pod.get('kind') == 'Pod'", self.content)
        self.assertIn("get('namespace') == 'logging'", self.content)

    def test_never_claims_authentic_provenance(self):
        self.assertIn("verified_provenance: false", self.content)
        self.assertIn("requires_external_job_validation: true", self.content)
        self.assertNotIn("observation_trusted: true", self.content)

    def test_no_execution_or_triage_changes(self):
        for field in ("execution_allowed: false", "changes_triage: false",
                      "changes_notifications: false", "changes_kubernetes: false"):
            self.assertIn(field, self.content)

    def test_raw_responses_hidden(self):
        self.assertIn("register: var_loki_diag_pod_raw", self.content)
        self.assertGreaterEqual(self.content.count("no_log: true"), 6)

    def test_failure_does_not_mean_not_ready(self):
        self.assertIn("var_loki_diag_pod_raw.rc == 0", self.content)
        self.assertIn("var_loki_diag_api.rc == 0", self.content)
        self.assertIn("var_loki_diag_api.stdout | trim == 'ok'", self.content)


@unittest.skipUnless(yaml is not None and NativeEnvironment is not None,
                     "Instalar PyYAML y Jinja2 para validar el parseo completo")
class ObservationTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = yaml.safe_load(PLAYBOOK.read_text(encoding="utf-8"))[0]
        cls.facts = next(t["ansible.builtin.set_fact"] for t in cls.data["tasks"]
                         if "var_loki_diag_declared" in t.get("ansible.builtin.set_fact", {}))
        cls.ready_tmpl = next(t["ansible.builtin.set_fact"]["var_loki_diag_observation"]["ready"]
                              for t in cls.data["tasks"]
                              if "var_loki_diag_observation" in t.get("ansible.builtin.set_fact", {}))
        cls.env = NativeEnvironment()

    def parse(self, pod):
        declared = self.env.from_string(self.facts["var_loki_diag_declared"]).render(var_loki_diag_pod=pod)
        statuses = self.env.from_string(self.facts["var_loki_diag_statuses"]).render(var_loki_diag_pod=pod)
        ready = self.env.from_string(self.ready_tmpl).render(
            var_loki_diag_declared=declared, var_loki_diag_statuses=statuses)
        return declared, statuses, ready

    def test_yaml_is_valid_and_targets_single_play(self):
        self.assertEqual(len(yaml.safe_load(PLAYBOOK.read_text(encoding="utf-8"))), 1)

    def test_healthy_loki(self):
        pod = {"spec": {"containers": [{"name": "sidecar"}, {"name": "loki"}]},
               "status": {"containerStatuses": [{"name": "sidecar", "ready": False},
                                                 {"name": "loki", "ready": True}]}}
        declared, statuses, ready = self.parse(pod)
        self.assertEqual(len(declared), 1)
        self.assertEqual(len(statuses), 1)
        self.assertIs(ready, True)

    def test_not_ready_loki(self):
        pod = {"spec": {"containers": [{"name": "loki"}]},
               "status": {"containerStatuses": [{"name": "loki", "ready": False}]}}
        _declared, _statuses, ready = self.parse(pod)
        self.assertIs(ready, False)

    def test_not_yet_reported_is_unknown(self):
        pod = {"spec": {"containers": [{"name": "loki"}]}, "status": {}}
        _declared, statuses, ready = self.parse(pod)
        self.assertEqual(statuses, [])
        self.assertIsNone(ready)

    def test_missing_pod_is_unknown(self):
        declared, statuses, ready = self.parse({})
        self.assertEqual(declared, [])
        self.assertEqual(statuses, [])
        self.assertIsNone(ready)


if __name__ == "__main__":
    unittest.main()
