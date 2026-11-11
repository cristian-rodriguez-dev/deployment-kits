from pathlib import Path
import re
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "monitorizacion/playbooks/auditar_geoip_wazuh.yml"


class TestGeoIPAWX(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = PLAYBOOK.read_text(encoding="utf-8")
        cls.play = yaml.safe_load(cls.text)[0]
        cls.tasks = cls.play["tasks"]

    def test_inventory_contract(self):
        self.assertEqual(self.play["hosts"], "wazuh-servers")
        self.assertFalse(self.play["become"])
        self.assertFalse(self.play["gather_facts"])

    def test_no_persistent_mutation_modules(self):
        for task in self.play["pre_tasks"] + self.tasks:
            self.assertNotIn("ansible.builtin.command", task)
            for module in ["copy", "template", "file", "shell", "lineinfile", "replace", "service", "systemd", "apt"]:
                self.assertNotIn("ansible.builtin." + module, task)

    def test_all_http_operations_target_local_indexer(self):
        operations = [t for t in self.tasks if "ansible.builtin.uri" in t]
        self.assertGreaterEqual(len(operations), 3)
        for t in operations:
            self.assertIn("{{ var_geoip_api_base }}", t["ansible.builtin.uri"]["url"])
            self.assertTrue(t.get("no_log"))
            self.assertFalse(t.get("changed_when"))
        self.assertIn("https://127.0.0.1:", self.play["vars"]["var_geoip_api_base"])

    def test_no_put_delete_or_patch(self):
        for task in self.tasks:
            if "ansible.builtin.uri" in task:
                self.assertIn(task["ansible.builtin.uri"].get("method", "GET"), {"GET", "POST"})
                self.assertTrue(
                    task["ansible.builtin.uri"]["method"] == "GET"
                    or any(x in task["ansible.builtin.uri"]["url"] for x in ("_count", "_simulate"))
                )

    def test_test_simulation_is_opt_in(self):
        sim = next(t for t in self.tasks if "Simular" in t["name"])
        self.assertEqual(sim["when"], "var_geoip_effective_simulate")
        self.assertIn("default(false)", self.play["vars"]["var_geoip_effective_simulate"])

    def test_pipeline_guard(self):
        self.assertIn("data.srcip", self.text)
        self.assertIn("GeoLocation", self.text)
        self.assertIn("VAR_WAZUH_ADMIN_PASSWORD", self.text)


if __name__ == "__main__":
    unittest.main()
