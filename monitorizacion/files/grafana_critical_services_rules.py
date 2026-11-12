#!/usr/bin/env python3
"""Plan or create three paused Grafana rules for critical services.

No updates/deletes of existing rules, alert policies or contact points.
All checks use the already configured Prometheus datasource through Grafana.
"""
import argparse
import base64
import json
import math
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

ANCHOR = "Host Down - Sistemas y Devs"
DATASOURCE_UID = "prometheus"
BOT = "security-triage-bot"
CADVISOR = "docker-cadvisor"
KSM = "kube-state-metrics"
WAZUH_SERVICE_RE = r'wazuh[.](manager|indexer|dashboard)'

RULES = [
    {
        "uid": "awx-critical-triage-down",
        "title": "Critico - Bot de triaje IA no disponible",
        "expr": '1 - (min(up{job="security-triage-bot"}) or vector(0))',
        "duration": "2m",
        "component": "security-triage-bot",
        "summary": "El endpoint de metricas del bot de triaje no esta disponible",
        "description": "Notificar DIRECTAMENTE desde Grafana por un canal independiente del bot; verificar tambien salud funcional del bot.",
    },
    {
        "uid": "awx-critical-wazuh-containers",
        "title": "Critico - Wazuh con contenedores ausentes",
        "expr": (
            '3 - (count(count by (container_label_com_docker_compose_service) ('
            'container_last_seen{job="docker-cadvisor",'
            'container_label_com_docker_compose_project="wazuh",'
            'container_label_com_docker_compose_service=~"wazuh[.](manager|indexer|dashboard)"}'
            ' > time() - 120)) or vector(0))'
        ),
        "duration": "3m",
        "component": "wazuh",
        "summary": "Falta la observacion reciente de uno o mas contenedores Wazuh",
        "description": "Esperados: manager, indexer y dashboard; revisar Docker y cAdvisor. No es un healthcheck funcional de Wazuh.",
    },
    {
        "uid": "awx-critical-loki-notready",
        "title": "Critico - Loki no disponible",
        "expr": (
            '1 - (max(kube_pod_container_status_ready{'
            'job="kube-state-metrics",namespace="logging",pod="loki-0",container="loki"'
            '}) or vector(0))'
        ),
        "duration": "5m",
        "component": "loki",
        "summary": "El contenedor principal loki-0 no esta Ready",
        "description": "Revisar Loki en namespace logging; excluir pods efimeros helm-install-loki; no comprueba la API de Loki.",
    },
]

SOURCE_JOBS = (BOT, CADVISOR, KSM)


class SafeError(RuntimeError):
    pass


class GrafanaClient:
    def __init__(self, base_url, username, password):
        if not username or not password:
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
        request = urllib.request.Request(self.base_url + path, method=method, data=body, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                raw = response.read(3_000_001)
                if len(raw) > 3_000_000:
                    raise SafeError("OVERSIZED_RESPONSE")
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            raise SafeError(f"HTTP_{exc.code}") from None
        except (urllib.error.URLError, TimeoutError):
            raise SafeError("CONNECTION_ERROR") from None
        except (ValueError, UnicodeError):
            raise SafeError("INVALID_JSON") from None


def query_values(client, expression, context):
    quoted = urllib.parse.quote(expression, safe="")
    response = client.request(f"/api/datasources/proxy/uid/{DATASOURCE_UID}/api/v1/query?query={quoted}")
    if not isinstance(response, dict) or response.get("status") != "success":
        raise SafeError(f"PROM_QUERY_FAILED_{context}")
    results = response.get("data", {}).get("result", [])
    if not isinstance(results, list) or len(results) != 1:
        raise SafeError(f"PROM_RESULT_UNEXPECTED_{context}")
    try:
        value = float(results[0]["value"][1])
    except (KeyError, IndexError, TypeError, ValueError):
        raise SafeError(f"PROM_RESULT_INVALID_{context}") from None
    if not math.isfinite(value):
        raise SafeError(f"PROM_RESULT_NONFINITE_{context}")
    return value


def assert_healthy_baseline(client):
    # Every source must be actively scraped; `or vector(0)` can otherwise hide telemetry loss.
    for job in SOURCE_JOBS:
        result = query_values(client, f'min(up{{job="{job}"}})', "SOURCE_" + job)
        if result != 1:
            raise SafeError("SOURCE_NOT_UP_" + job)
    # Fail closed before POST if any actual rule would currently fire.
    for rule in RULES:
        result = query_values(client, rule["expr"], "RULE_" + rule["uid"])
        if result != 0:
            raise SafeError("BASELINE_NOT_ZERO_" + rule["uid"])


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
        "noDataState": "OK",  # Reporter: separate monitoring of telemetry is mandatory.
        "execErrState": "Error",
        "isPaused": True,
        "labels": {"component": rule["component"], "severity": "warning", "managed_by": "awx"},
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


def equivalent_existing(existing, intended):
    """Allow pause/resume via UI; flag accidental config drift and never overwrite it."""
    actual_data = existing.get("data") or []
    actual_expr = next(
        (x.get("model", {}).get("expr") for x in actual_data if x.get("refId") == "A"), None
    )
    actual_b = next(
        (x.get("model", {}) for x in actual_data if x.get("refId") == "B"), {}
    )
    cond = actual_b.get("conditions", [{}])
    return all((
        existing.get("uid") == intended["uid"],
        existing.get("title") == intended["title"],
        existing.get("folderUID") == intended["folderUID"],
        existing.get("ruleGroup") == intended["ruleGroup"],
        existing.get("condition") == "B",
        existing.get("for") == intended["for"],
        actual_expr == intended["data"][0]["model"]["expr"],
        isinstance(cond, list) and bool(cond)
        and cond[0].get("evaluator", {}).get("type") == "gt"
        and cond[0].get("evaluator", {}).get("params") == [0],
    ))


def execute(client, mode):
    if mode not in ("plan", "apply"):
        raise SafeError("MODE_INVALID")
    ds = client.request(f"/api/datasources/uid/{DATASOURCE_UID}")
    if ds.get("uid") != DATASOURCE_UID or ds.get("type") != "prometheus":
        raise SafeError("DATASOURCE_MISMATCH")
    current = client.request("/api/v1/provisioning/alert-rules")
    if not isinstance(current, list):
        raise SafeError("RULE_LIST_INVALID")
    anchor = next((rule for rule in current if rule.get("title") == ANCHOR), None)
    if not anchor:
        raise SafeError("ANCHOR_MISSING")

    # Check collisions for ALL rules before making any writes.
    pending = []
    existing = 0
    for rule in RULES:
        payload = build_payload(rule, anchor)
        collisions = [x for x in current if x.get("uid") == rule["uid"] or x.get("title") == rule["title"]]
        if collisions:
            if len(collisions) != 1 or not equivalent_existing(collisions[0], payload):
                raise SafeError("RULE_COLLISION_OR_DRIFT_" + rule["uid"])
            existing += 1
        else:
            pending.append(payload)

    assert_healthy_baseline(client)
    created = 0
    if mode == "apply":
        for payload in pending:
            result = client.request("/api/v1/provisioning/alert-rules", method="POST", payload=payload)
            if result.get("uid") != payload["uid"] or result.get("isPaused") is not True:
                raise SafeError("CREATED_BUT_NOT_VERIFIED_PAUSED_" + payload["uid"])
            created += 1
    return {
        "mode": mode.upper(),
        "datasource": "OK", "sources_up": len(SOURCE_JOBS), "baseline": "ZERO",
        "anchor": "FOUND", "existing": existing,
        "pending": len(pending) if mode == "plan" else 0,
        "created_paused": created,
        "modified_existing": False, "modified_routes": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("plan", "apply"), default="plan")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--confirm", default="")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        raise SafeError("PORT_INVALID")
    if args.mode == "apply" and args.confirm != "CREATE_PAUSED_ONLY":
        raise SafeError("APPLY_NOT_AUTHORIZED")
    client = GrafanaClient(
        f"http://127.0.0.1:{args.port}",
        os.environ.get("GRAFANA_ALERTING_USERNAME", ""),
        os.environ.get("GRAFANA_ALERTING_PASSWORD", ""),
    )
    print(json.dumps(execute(client, args.mode), ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except SafeError as exc:
        print("ERROR_SEGURO:" + str(exc), file=sys.stderr)
        sys.exit(2)
