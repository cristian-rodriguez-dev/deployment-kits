#!/usr/bin/env python3
"""Plan or safely create two *paused* Grafana-managed K3s alerts.

This script never updates/deletes existing rules, contact points, routes or folders.
"""
import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


ANCHOR = "Host Down - Sistemas y Devs"
DATASOURCE_UID = "prometheus"
RULES = [
    {
        "uid": "awx-k3s-deploy-unavail",
        "title": "K3s - Deployment sin replicas disponibles",
        "expr": (
            'clamp_min(max by (namespace, deployment) (kube_deployment_spec_replicas) '
            '- on (namespace, deployment) '
            'max by (namespace, deployment) (kube_deployment_status_replicas_available), 0)'
        ),
        "duration": "5m",
        "summary": "Deployment K3s con replicas deseadas sin disponibilidad durante 5 minutos",
        "description": "Revisar el Deployment, sus Pods, eventos y disponibilidad de nodos.",
    },
    {
        "uid": "awx-k3s-crashloop",
        "title": "K3s - Contenedor en CrashLoopBackOff",
        "expr": 'max by (namespace, pod, container) (kube_pod_container_status_waiting_reason{reason="CrashLoopBackOff"})',
        "duration": "5m",
        "summary": "Contenedor K3s en CrashLoopBackOff durante 5 minutos",
        "description": "Revisar logs del contenedor, eventos del Pod y reinicios.",
    },
]


class SafeError(RuntimeError):
    pass


class GrafanaClient:
    def __init__(self, base_url, username, password):
        if not (username and password):
            raise SafeError("CREDENTIALS_MISSING")
        self.base_url = base_url.rstrip("/")
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}

    def request(self, path, method="GET", payload=None):
        headers = dict(self.headers)
        body = None
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
            headers["Content-Type"] = "application/json"
            headers["X-Disable-Provenance"] = "true"
        req = urllib.request.Request(self.base_url + path, method=method, data=body, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                raw = response.read(3_000_001)
                if len(raw) > 3_000_000:
                    raise SafeError("OVERSIZED_RESPONSE")
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            raise SafeError(f"HTTP_{e.code}") from None
        except (urllib.error.URLError, TimeoutError):
            raise SafeError("CONNECTION_ERROR") from None
        except (ValueError, UnicodeError):
            raise SafeError("INVALID_JSON") from None


def ensure_metrics(client):
    # The probe uses Grafana's existing Prometheus datasource, not a guessed port.
    for metric in ("kube_deployment_spec_replicas", "kube_deployment_status_replicas_available", "kube_pod_info"):
        q = urllib.parse.quote(f"count({metric})", safe="")
        data = client.request(f"/api/datasources/proxy/uid/{DATASOURCE_UID}/api/v1/query?query={q}")
        if data.get("status") != "success":
            raise SafeError(f"PROM_QUERY_FAILED_{metric}")
        values = data.get("data", {}).get("result", [])
        if not values or not values[0].get("value"):
            raise SafeError(f"METRIC_MISSING_{metric}")
        try:
            count = float(values[0]["value"][1])
        except (ValueError, IndexError, TypeError):
            raise SafeError(f"METRIC_INVALID_{metric}") from None
        if count < 1:
            raise SafeError(f"METRIC_EMPTY_{metric}")


def build_payload(rule, anchor):
    folder = anchor.get("folderUID")
    group = anchor.get("ruleGroup")
    org_id = anchor.get("orgID", anchor.get("orgId", 1))
    if not folder or not group or not isinstance(org_id, int):
        raise SafeError("ANCHOR_INVALID")
    return {
        "uid": rule["uid"],
        "title": rule["title"],
        "folderUID": folder,
        "ruleGroup": group,
        "orgId": org_id,
        "condition": "B",
        "for": rule["duration"],
        "noDataState": "OK",
        "execErrState": "Error",
        "isPaused": True,
        "labels": {"component": "k3s", "severity": "warning", "managed_by": "awx"},
        "annotations": {"summary": rule["summary"], "description": rule["description"]},
        "data": [
            {
                "refId": "A", "queryType": "", "datasourceUid": DATASOURCE_UID,
                "relativeTimeRange": {"from": 300, "to": 0},
                "model": {
                    "datasource": {"type": "prometheus", "uid": DATASOURCE_UID},
                    "editorMode": "code", "expr": rule["expr"], "instant": True, "range": False,
                    "intervalMs": 1000, "maxDataPoints": 43200, "refId": "A",
                },
            },
            {
                "refId": "B", "queryType": "", "datasourceUid": "__expr__",
                "relativeTimeRange": {"from": 0, "to": 0},
                "model": {
                    "datasource": {"type": "__expr__", "uid": "__expr__"},
                    "expression": "A", "refId": "B", "type": "threshold",
                    "conditions": [{
                        "evaluator": {"type": "gt", "params": [0]},
                        "operator": {"type": "and"},
                        "query": {"params": ["B"]},
                        "reducer": {"params": [], "type": "last"},
                        "type": "query",
                    }],
                    "intervalMs": 1000, "maxDataPoints": 43200,
                },
            },
        ],
    }


def is_existing_equivalent(actual, intended):
    data = actual.get("data") or []
    a_expr = next((d.get("model", {}).get("expr") for d in data if d.get("refId") == "A"), None)
    return (
        actual.get("uid") == intended["uid"]
        and actual.get("title") == intended["title"]
        and a_expr == intended["data"][0]["model"]["expr"]
        and actual.get("condition") == "B"
        and actual.get("folderUID") == intended["folderUID"]
    )


def execute(client, mode):
    datasource = client.request(f"/api/datasources/uid/{DATASOURCE_UID}")
    if datasource.get("uid") != DATASOURCE_UID or datasource.get("type") != "prometheus":
        raise SafeError("DATASOURCE_MISMATCH")
    current = client.request("/api/v1/provisioning/alert-rules")
    if not isinstance(current, list):
        raise SafeError("RULES_RESPONSE_INVALID")
    anchor = next((r for r in current if r.get("title") == ANCHOR), None)
    if not anchor:
        raise SafeError("ANCHOR_RULE_MISSING")
    ensure_metrics(client)
    created = 0
    existing = 0
    pending = 0
    for rule in RULES:
        payload = build_payload(rule, anchor)
        collisions = [r for r in current if r.get("uid") == rule["uid"] or r.get("title") == rule["title"]]
        if collisions:
            if len(collisions) != 1 or not is_existing_equivalent(collisions[0], payload):
                raise SafeError("RULE_COLLISION_OR_DRIFT")
            existing += 1
            continue
        if mode == "apply":
            returned = client.request("/api/v1/provisioning/alert-rules", method="POST", payload=payload)
            if returned.get("uid") != rule["uid"] or not returned.get("isPaused", False):
                raise SafeError("CREATED_BUT_NOT_VERIFIED_PAUSED")
            created += 1
        else:
            pending += 1
    return {"mode": mode.upper(), "metrics": "OK", "anchor": "FOUND",
            "existing": existing, "pending": pending, "created_paused": created,
            "mutated_existing": False, "modified_policies": False}


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["plan", "apply"], default="plan")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--confirm", default="")
    args = p.parse_args(argv)
    if not 1 <= args.port <= 65535:
        raise SafeError("PORT_INVALID")
    if args.mode == "apply" and args.confirm != "CREATE_PAUSED_ONLY":
        raise SafeError("APPLY_NOT_AUTHORIZED")
    client = GrafanaClient(f"http://127.0.0.1:{args.port}",
                           os.environ.get("GRAFANA_ALERTING_USERNAME", ""),
                           os.environ.get("GRAFANA_ALERTING_PASSWORD", ""))
    print(json.dumps(execute(client, args.mode), ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except SafeError as e:
        print(f"ERROR_SEGURO:{e}", file=sys.stderr)
        sys.exit(2)
