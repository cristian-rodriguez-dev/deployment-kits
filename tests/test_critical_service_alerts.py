"""Regression tests for the reusable AWX Grafana critical-alert manager."""
import json
import sys
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitorizacion" / "files"))
import grafana_critical_services_rules as c
import grafana_k3s_rules as k3s

ANCHOR = {"uid": "anchor-host", "title": c.ANCHOR, "folderUID": "infra", "ruleGroup": "Infrastructure", "orgID": 1}


class Client:
    def __init__(self, current=None, sources=None, baseline=None):
        self.current = current if current is not None else [ANCHOR]
        self.sources = sources or {}
        self.baseline = baseline or {}
        self.created = []
        self.calls = []

    def request(self, path, method="GET", payload=None):
        self.calls.append((path, method))
        if path == "/api/datasources/uid/prometheus":
            return {"uid": "prometheus", "type": "prometheus"}
        if path == "/api/v1/provisioning/alert-rules":
            if method == "POST":
                self.created.append(payload)
                return {"uid": payload["uid"], "isPaused": payload["isPaused"]}
            return self.current
        if path.startswith("/api/datasources/proxy/uid/prometheus/api/v1/query?query="):
            query = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)["query"][0]
            for job in c.SOURCE_JOBS:
                if query == f'min(up{{job="{job}"}})':
                    value = self.sources.get(job, 1)
                    if value is None:
                        return {"status": "success", "data": {"result": []}}
                    return {"status": "success", "data": {"result": [{"value": [1, str(value)]}]}}
            for r in c.RULES:
                if query == r["expr"]:
                    value = self.baseline.get(r["uid"], 0)
                    if value is None:
                        return {"status": "success", "data": {"result": []}}
                    return {"status": "success", "data": {"result": [{"value": [1, str(value)]}]}}
            raise AssertionError("Unknown query " + query)
        raise AssertionError(f"Unexpected API call: {method} {path}")


class CriticalTests(unittest.TestCase):
    def test_plan_read_only_for_grafana(self):
        client = Client()
        report = c.execute(client, "plan")
        self.assertEqual(report["pending"], 3)
        self.assertEqual(report["sources_up"], 3)
        self.assertEqual(client.created, [])
        self.assertTrue(all(method == "GET" for _, method in client.calls))

    def test_apply_creates_only_three_paused_rules(self):
        client = Client()
        report = c.execute(client, "apply")
        self.assertEqual(report["created_paused"], 3)
        self.assertEqual(len(client.created), 3)
        self.assertTrue(all(x["isPaused"] is True for x in client.created))
        self.assertTrue(all(x["condition"] == "B" for x in client.created))
        self.assertTrue(all(x["data"][1]["model"]["conditions"][0]["evaluator"]["params"] == [0] for x in client.created))
        self.assertTrue(all(method in ("GET", "POST") for _, method in client.calls))

    def test_uid_collision_blocks_all_writes(self):
        client = Client([ANCHOR, {"uid": c.RULES[2]["uid"], "title": "OTRA"}])
        with self.assertRaises(c.SafeError):
            c.execute(client, "apply")
        self.assertEqual(client.created, [])

    def test_title_collision_blocks_all_writes(self):
        client = Client([ANCHOR, {"uid": "other", "title": c.RULES[1]["title"]}])
        with self.assertRaises(c.SafeError):
            c.execute(client, "apply")
        self.assertEqual(client.created, [])

    def test_reexecution_is_idempotent_even_if_resumed(self):
        existing = [c.build_payload(x, ANCHOR) for x in c.RULES]
        for item in existing:
            item["isPaused"] = False
        client = Client([ANCHOR, *existing])
        report = c.execute(client, "apply")
        self.assertEqual(report["existing"], 3)
        self.assertEqual(report["created_paused"], 0)
        self.assertEqual(client.created, [])

    def test_preflight_sources_not_up(self):
        client = Client(sources={c.CADVISOR: 0})
        with self.assertRaisesRegex(c.SafeError, "SOURCE_NOT_UP"):
            c.execute(client, "apply")
        self.assertEqual(client.created, [])

    def test_source_missing(self):
        client = Client(sources={c.KSM: None})
        with self.assertRaisesRegex(c.SafeError, "PROM_RESULT_UNEXPECTED"):
            c.execute(client, "apply")
        self.assertEqual(client.created, [])

    def test_wazuh_baseline_positive(self):
        client = Client(baseline={c.RULES[1]["uid"]: 1})
        with self.assertRaisesRegex(c.SafeError, "BASELINE_NOT_ZERO"):
            c.execute(client, "apply")
        self.assertEqual(client.created, [])

    def test_loki_no_data(self):
        client = Client(baseline={c.RULES[2]["uid"]: None})
        with self.assertRaisesRegex(c.SafeError, "PROM_RESULT_UNEXPECTED"):
            c.execute(client, "apply")
        self.assertEqual(client.created, [])

    def test_bad_anchor(self):
        client = Client([])
        with self.assertRaisesRegex(c.SafeError, "ANCHOR_MISSING"):
            c.execute(client, "plan")

    def test_payload_loki_excludes_helm(self):
        expr = c.RULES[2]["expr"]
        self.assertIn('pod="loki-0"', expr)
        self.assertNotIn('helm', expr)
        self.assertIn('or vector(0)', expr)

    def test_no_secrets_in_payload(self):
        for rule in c.RULES:
            payload = c.build_payload(rule, ANCHOR)
            self.assertNotIn("password", json.dumps(payload).lower())
            self.assertEqual(payload["noDataState"], "OK")

    def test_k3s_crashloop_is_synced_to_manual_query(self):
        rule = next(x for x in k3s.RULES if x["uid"] == "awx-k3s-crashloop")
        self.assertEqual(rule["expr"], 'max by (namespace, pod, container) (kube_pod_container_status_waiting_reason{reason="CrashLoopBackOff"}) or vector(0)')

    def test_ansible_copy_diff_at_task_level(self):
        import yaml
        path = Path(__file__).resolve().parents[1] / "monitorizacion" / "playbooks" / "crear_alertas_servicios_criticos_grafana.yml"
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        tasks = document[0]["tasks"]
        copies = [t for t in tasks if "ansible.builtin.copy" in t]
        self.assertEqual(len(copies), 1)
        self.assertNotIn("diff", copies[0]["ansible.builtin.copy"])
        self.assertFalse(copies[0]["diff"])
        self.assertEqual(document[0]["hosts"], "grafana-servers")


if __name__ == "__main__":
    unittest.main()
