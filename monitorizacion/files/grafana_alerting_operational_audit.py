#!/usr/bin/env python3
"""Read-only Grafana Alerting operational drift check (lab 2026-11-12).

Never prints contact settings, secret values, raw API response, or authorization.
The five original legacy rules remain outside declarative management.
"""
import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request

from grafana_k3s_rules import RULES as K3S_RULES
from grafana_critical_services_rules import RULES as CRITICAL_RULES

EMERGENCY_BOT_RULE_UID = "awx-critical-triage-down"


class AuditError(RuntimeError):
    pass


class GrafanaReadOnlyClient:
    def __init__(self, base_url, username, password):
        if not username or not password:
            raise AuditError("AUTH_MISSING")
        self.base_url = base_url.rstrip("/")
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.headers = {
            "Authorization": "Basic " + token,
            "Accept": "application/json",
        }

    def get(self, path):
        req = urllib.request.Request(self.base_url + path, method="GET", headers=self.headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                data = response.read(3_000_001)
                if len(data) > 3_000_000:
                    raise AuditError("API_RESPONSE_TOO_BIG")
                return json.loads(data)
        except urllib.error.HTTPError as error:
            raise AuditError(f"API_HTTP_{error.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise AuditError("API_UNREACHABLE") from None
        except (UnicodeError, ValueError):
            raise AuditError("API_INVALID_JSON") from None


# Compare PromQL tokens, not presentation whitespace. Grafana's editor may
# reformat a correct expression on save (including newlines / indentation).
# Quoted and raw string literals stay intact, including interior whitespace.
# Token boundaries ensure `sum by` is never mistaken for `sumby`.
_PROMQL_TOKEN = re.compile(
    r'"(?:\\.|[^"\\])*"|'
    r"'(?:\\.|[^'\\])*'|"
    r'`[^`]*`|'
    r'[A-Za-z_:][A-Za-z0-9_:]*|'
    r'\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|'
    r'!=|=~|!~|==|<=|>=|'
    r'[^\s]'
)


def norm_expr(text):
    if not isinstance(text, str):
        return None
    return tuple(_PROMQL_TOKEN.findall(text))


def validate_rule(actual, spec):
    """Return safe names of drifted fields, never raw expressions."""
    errors = []
    if actual.get("title") != spec["title"]:
        errors.append("title")
    if actual.get("isPaused") is not False:
        errors.append("paused")
    if actual.get("for") != spec["duration"]:
        errors.append("pending")
    if actual.get("condition") != "B":
        errors.append("condition")
    data = actual.get("data") or []
    if not isinstance(data, list):
        return errors + ["queries"]
    a = next((d for d in data if d.get("refId") == "A"), {})
    b = next((d for d in data if d.get("refId") == "B"), {})
    if a.get("datasourceUid") != "prometheus":
        errors.append("datasource")
    if norm_expr((a.get("model") or {}).get("expr")) != norm_expr(spec["expr"]):
        errors.append("promql")
    conditions = (b.get("model") or {}).get("conditions", [])
    if (
        not isinstance(conditions, list) or not conditions
        or conditions[0].get("evaluator", {}).get("type") != "gt"
        or conditions[0].get("evaluator", {}).get("params") != [0]
    ):
        errors.append("threshold")
    return errors


def audit(client, expected_rules=10, expected_integrations=3,
          emergency_contact="Infraestructura - Emergencias"):
    health = client.get("/api/health")
    if not isinstance(health, dict) or health.get("database") != "ok":
        raise AuditError("GRAFANA_DB_UNHEALTHY")

    rules = client.get("/api/v1/provisioning/alert-rules")
    contacts = client.get("/api/v1/provisioning/contact-points")
    if not isinstance(rules, list) or not isinstance(contacts, list):
        raise AuditError("UNEXPECTED_API_SCHEMA")

    errors = []
    if len(rules) != expected_rules:
        errors.append("TOTAL_RULES_CHANGED")
    if len(contacts) != expected_integrations:
        errors.append("CONTACT_INTEGRATIONS_CHANGED")
    specs = K3S_RULES + CRITICAL_RULES
    if len(specs) != 5 or len({r["uid"] for r in specs}) != 5:
        raise AuditError("INVALID_LOCAL_MANIFEST")

    by_uid = {}
    for rule in rules:
        uid = rule.get("uid")
        if uid in by_uid:
            errors.append("DUPLICATE_RULE_UID")
        by_uid[uid] = rule
    details = []
    for spec in specs:
        item = by_uid.get(spec["uid"])
        if item is None:
            errors.append(f"MISSING_{spec['uid']}")
            details.append({"uid": spec["uid"], "status": "MISSING"})
            continue
        fields = validate_rule(item, spec)
        if fields:
            errors.append(f"DRIFT_{spec['uid']}")
        details.append({"uid": spec["uid"], "status": "OK" if not fields else "DRIFT", "fields": fields})

    # The legacy API returns each integration as an independent record, even
    # if the UI groups multiple integrations under one named contact point.
    emergency_types = {
        str(contact.get("type", "")).lower()
        for contact in contacts
        if contact.get("name") == emergency_contact
    }
    missing_types = sorted({"email", "telegram"} - emergency_types)
    if missing_types:
        errors.append("EMERGENCY_CHANNELS_MISSING")

    bot = by_uid.get(EMERGENCY_BOT_RULE_UID, {})
    direct = bot.get("notification_settings", bot.get("notificationSettings"))
    if isinstance(direct, dict):
        receiver = direct.get("receiver")
        route_state = "DIRECT_OK" if receiver == emergency_contact else "DIRECT_MISMATCH"
        if route_state == "DIRECT_MISMATCH":
            errors.append("BOT_DIRECT_ROUTE_MISMATCH")
    else:
        # Some API versions/instances do not expose this field. Report as
        # unverified rather than pretending a routing check was performed.
        route_state = "NOT_EXPOSED_IN_API"

    return {
        "state": "OK" if not errors else "DRIFT",
        "rules_total": len(rules),
        "contact_integrations_total": len(contacts),
        "known_rules_checked": len(specs),
        "original_rules_unmanaged": sum(1 for item in rules if item.get("uid") not in {spec["uid"] for spec in specs}),
        "emergency_types": sorted(emergency_types & {"email", "telegram"}),
        "bot_route": route_state,
        "details": details,
        "issues": sorted(set(errors)),
        "read_only": True,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--expected-rules", type=int, default=10)
    parser.add_argument("--expected-integrations", type=int, default=3)
    parser.add_argument("--emergency-contact", default="Infraestructura - Emergencias")
    args = parser.parse_args(argv)
    if not (1 <= args.port <= 65535) or args.expected_rules < 5 or args.expected_integrations < 2:
        raise AuditError("INVALID_ARGUMENTS")
    if not args.emergency_contact.strip():
        raise AuditError("INVALID_EMERGENCY_CONTACT")
    client = GrafanaReadOnlyClient(
        f"http://127.0.0.1:{args.port}",
        os.environ.get("GRAFANA_ALERTING_USERNAME", ""),
        os.environ.get("GRAFANA_ALERTING_PASSWORD", ""),
    )
    result = audit(client, args.expected_rules, args.expected_integrations, args.emergency_contact)
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    # Exit zero for DRIFT so AWX can show a safe, actionable summary.
    # The Ansible assertion below turns drift into a failed job.


if __name__ == "__main__":
    try:
        main()
    except AuditError as exc:
        print("AUDIT_ERROR:" + str(exc), file=sys.stderr)
        sys.exit(2)
