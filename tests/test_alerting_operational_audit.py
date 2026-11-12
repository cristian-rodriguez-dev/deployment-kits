import importlib.util
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1] / "monitorizacion" / "files"
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("auditor", ROOT / "grafana_alerting_operational_audit.py")
auditor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auditor)
from grafana_k3s_rules import RULES as K3S
from grafana_critical_services_rules import RULES as CRITICAL


def make_rule(rule):
    return {
        "uid": rule["uid"], "title": rule["title"], "isPaused": False,
        "for": rule["duration"], "condition": "B",
        "data": [
            {"refId": "A", "datasourceUid": "prometheus", "model": {"expr": rule["expr"]}},
            {"refId": "B", "model": {"conditions": [{"evaluator": {"type": "gt", "params": [0]}}]}}
        ],
        **({"notification_settings": {"receiver": "Infraestructura - Emergencias"}}
           if rule["uid"] == auditor.EMERGENCY_BOT_RULE_UID else {}),
    }


class Client:
    def __init__(self):
        self.paths = []
        self.rules = [make_rule(r) for r in K3S + CRITICAL]
        self.rules += [{"uid": f"legacy-{i}"} for i in range(5)]
        self.contacts = [
            {"name": "Preexisting Webhook", "type": "webhook", "settings": {"url": "secret"}},
            {"name": "Infraestructura - Emergencias", "type": "telegram", "settings": {"bottoken": "secret"}},
            {"name": "Infraestructura - Emergencias", "type": "email", "settings": {"addresses": "private"}},
        ]

    def get(self, path):
        self.paths.append(path)
        return {
            "/api/health": {"database": "ok"},
            "/api/v1/provisioning/alert-rules": self.rules,
            "/api/v1/provisioning/contact-points": self.contacts,
        }[path]


class Tests(unittest.TestCase):
    def test_operational(self):
        c = Client()
        r = auditor.audit(c)
        self.assertEqual(r["state"], "OK")
        self.assertEqual(r["bot_route"], "DIRECT_OK")
        self.assertEqual(r["original_rules_unmanaged"], 5)
        self.assertEqual(len(c.paths), 3)
        self.assertTrue(all("/api/" in x for x in c.paths))
        self.assertNotIn("secret", json.dumps(r))

    def test_pause_drift(self):
        c = Client()
        c.rules[0]["isPaused"] = True
        self.assertIn("DRIFT_awx-k3s-deploy-unavail", auditor.audit(c)["issues"])

    def test_promql_drift(self):
        c = Client()
        c.rules[1]["data"][0]["model"]["expr"] = "vector(1)"
        r = auditor.audit(c)
        self.assertIn("promql", r["details"][1]["fields"])

    def test_invalid_threshold(self):
        c = Client()
        c.rules[2]["data"][1]["model"]["conditions"][0]["evaluator"]["params"] = [1]
        self.assertEqual(auditor.audit(c)["state"], "DRIFT")

    def test_missing_rule(self):
        c = Client()
        c.rules.pop(0)
        r = auditor.audit(c)
        self.assertIn("MISSING_awx-k3s-deploy-unavail", r["issues"])

    def test_wrong_contact(self):
        c = Client()
        c.contacts = c.contacts[:2]
        r = auditor.audit(c)
        self.assertIn("EMERGENCY_CHANNELS_MISSING", r["issues"])

    def test_wrong_route(self):
        c = Client()
        next(r for r in c.rules if r.get("uid") == auditor.EMERGENCY_BOT_RULE_UID)["notification_settings"] = {"receiver": "Preexisting Webhook"}
        self.assertIn("BOT_DIRECT_ROUTE_MISMATCH", auditor.audit(c)["issues"])

    def test_route_unexposed_is_not_falsely_verified(self):
        c = Client()
        next(r for r in c.rules if r.get("uid") == auditor.EMERGENCY_BOT_RULE_UID).pop("notification_settings")
        r = auditor.audit(c)
        self.assertEqual(r["bot_route"], "NOT_EXPOSED_IN_API")
        self.assertEqual(r["state"], "OK")

    def test_original_rules_not_modified(self):
        c = Client()
        rules_before = json.dumps(c.rules)
        auditor.audit(c)
        self.assertEqual(json.dumps(c.rules), rules_before)

    def test_yaml_copy_diff_keyword_level(self):
        playbook = (ROOT.parent / "playbooks" / "auditar_alerting_operativo_grafana.yml").read_text()
        blocks = playbook.split("    - name: ")
        copies = [part for part in blocks if "ansible.builtin.copy:" in part]
        self.assertEqual(len(copies), 2)
        for block in copies:
            self.assertIn("\n      diff: false", block)
            for line in block.splitlines():
                if line.strip() == "diff: false":
                    self.assertEqual(len(line) - len(line.lstrip()), 6)
        self.assertIn("changed_when: false", playbook)



if __name__ == "__main__":
    unittest.main()
