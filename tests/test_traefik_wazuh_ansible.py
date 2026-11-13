"""Portable offline guard tests; no Ansible/Kubernetes/Docker or PyYAML required."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "monitorizacion/roles/traefik_loki_wazuh"
PLAYBOOKS = ROOT / "monitorizacion/playbooks"


def read(path):
    return path.read_text(encoding="utf-8")


class TraefikWazuhAdoptionTests(unittest.TestCase):
    def test_expected_files_present(self):
        for name in ("defaults/main.yml", "tasks/main.yml", "tasks/audit.yml",
                     "tasks/adopt.yml", "handlers/main.yml"):
            with self.subTest(name=name):
                self.assertTrue((ROLE / name).is_file())
        self.assertTrue((PLAYBOOKS / "auditar_traefik_loki_wazuh.yml").is_file())
        self.assertTrue((PLAYBOOKS / "adoptar_traefik_loki_wazuh.yml").is_file())

    def test_default_is_read_only(self):
        defaults = read(ROLE / "defaults/main.yml")
        self.assertRegex(defaults, r"(?m)^var_tlw_mode: audit\s")
        self.assertRegex(defaults, r"(?m)^var_tlw_apply: false\s")
        for flag in ("allow_bridge_file_update", "allow_loki_url_update",
                     "allow_service_restart", "allow_traefik_update",
                     "ack_traefik_rollout"):
            self.assertRegex(defaults, rf"(?m)^var_tlw_{flag}: false\s")

    def test_manager_never_mutated(self):
        tasks = "\n".join(read(p) for p in (ROLE / "tasks").glob("*.yml"))
        # All Docker calls use read-only command argv; never invoke Docker via shell.
        self.assertNotIn("ansible.builtin.shell:", tasks)
        self.assertNotIn("ansible.builtin.raw:", tasks)
        self.assertNotRegex(tasks, r"(?m)^\s*-\s*(?:up|down|rm|restart|prune|cp)\s*$")
        self.assertNotIn("/var/lib/docker/volumes/", tasks)
        self.assertIn("_tlw_rules_match", tasks)
        self.assertIn("_tlw_manager_localfile_ok", tasks)

    def test_docker_project_is_explicit(self):
        defaults = read(ROLE / "defaults/main.yml")
        audit = read(ROLE / "tasks/audit.yml")
        self.assertIn("var_tlw_compose_project: wazuh", defaults)
        self.assertIn("_tlw_compose_project_ok", audit)
        self.assertIn("wazuh_wazuh_etc", audit)
        self.assertIn("wazuh_wazuh_logs", audit)
        self.assertIn("wazuh_wazuh_active_response", audit)
        self.assertIn("read_only", audit)

    def test_preserves_state_and_event_content(self):
        adopt = read(ROLE / "tasks/adopt.yml")
        self.assertIn("var_tlw_state_path", adopt)
        self.assertIn("var_tlw_output_path", adopt)
        self.assertIn("state: file", adopt)
        for forbidden in ("state: absent", "recurse: true", "force: true", "truncate(",
                          "rm -rf", "CREATE TABLE", "sqlite3.connect"):
            self.assertNotIn(forbidden, adopt)
        # Only the config may be rewritten, never the database or JSONL.
        self.assertEqual(adopt.count("ansible.builtin.copy:"), 4)

    def test_checksum_preserves_final_newline(self):
        audit = read(ROLE / "tasks/audit.yml")
        self.assertGreaterEqual(audit.count("rstrip=False"), 3)
        self.assertIn('hash("sha1")', audit)
        self.assertIn('hash("sha256")', audit)

    def test_traefik_changes_require_two_approvals(self):
        adopt = read(ROLE / "tasks/adopt.yml")
        self.assertIn("var_tlw_allow_traefik_update | bool", adopt)
        self.assertIn("var_tlw_ack_traefik_rollout | bool", adopt)
        self.assertIn("backup: true", adopt)
        self.assertIn("when: not (_tlw_helm_matches | bool)", adopt)

    def test_script_changes_require_restart_approval(self):
        adopt = read(ROLE / "tasks/adopt.yml")
        self.assertIn("var_tlw_allow_bridge_file_update | bool", adopt)
        self.assertIn("var_tlw_allow_service_restart | bool", adopt)
        self.assertIn("notify: Reiniciar puente tras cambio autorizado", adopt)
        self.assertIn("_tlw_config | combine", adopt)

    def test_awx_host_is_restricted(self):
        audit = read(PLAYBOOKS / "auditar_traefik_loki_wazuh.yml")
        adopt = read(PLAYBOOKS / "adoptar_traefik_loki_wazuh.yml")
        for text in (audit, adopt):
            self.assertRegex(text, r"(?m)^  hosts: ansible_server\s*$")
            self.assertRegex(text, r"(?m)^  become: true\s*$")
        self.assertIn("var_tlw_mode: adopt", adopt)
        self.assertIn("serial: 1", adopt)
        self.assertIn("inventory_hostname in var_tlw_authorized_hosts", read(ROLE / "tasks/main.yml"))

    def test_internal_loki_is_resolved_without_hardcoding_cluster_ip(self):
        defaults = read(ROLE / "defaults/main.yml")
        audit = read(ROLE / "tasks/audit.yml")
        self.assertNotIn("10.43.213.25", defaults + audit)
        self.assertIn("get\n      - svc", audit)
        self.assertIn("_tlw_expected_loki_url", audit)

    def test_documents_do_not_claim_end_to_end_correlations(self):
        doc = read(ROOT / "monitorizacion/docs/TRAEFIK_WAZUH_AWX.md")
        self.assertIn("100601", doc)
        self.assertIn("100603", doc)
        self.assertIn("100605", doc)
        self.assertIn("No hay Active Response web", doc)
        self.assertIn("no se han validado E2E".lower(), doc.lower())


if __name__ == "__main__":
    unittest.main()
