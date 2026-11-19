#!/usr/bin/env python3
"""Preparar alerting real 24.04 en Grafana 26.04: reglas pausadas por defecto.

Solo se comunica con Grafana en loopback. No imprime cuerpos de respuesta ni secretos.
"""
from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import ipaddress
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPHandler, HTTPRedirectHandler, Request, build_opener


class SafeError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SafeError("Redirección inesperada de Grafana")


class Grafana:
    def __init__(self, port: int, user: str, password: str, host: str = "127.0.0.1"):
        if not 1 <= port <= 65535 or not user or not password:
            raise SafeError("Puerto o credencial Grafana inválidos")
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            raise SafeError("Host Grafana debe ser una IP local, sin DNS") from None
        if addr.is_multicast or addr.is_unspecified or addr.is_link_local or not (addr.is_private or addr.is_loopback):
            raise SafeError("IP Grafana debe ser local o privada")
        self.base = f"http://[{host}]:{port}" if addr.version == 6 else f"http://{host}:{port}"
        auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {"Authorization": "Basic " + auth, "Accept": "application/json",
                        "Content-Type": "application/json", "X-Disable-Provenance": "true"}
        self.opener = build_opener(HTTPHandler(), NoRedirect())

    def request(self, method: str, path: str, payload=None, missing_ok=False):
        if not path.startswith("/api/") or "//" in path:
            raise SafeError("Ruta de API inválida")
        content = None if payload is None else json.dumps(payload, ensure_ascii=False).encode()
        req = Request(self.base + path, data=content, headers=self.headers, method=method)
        try:
            with self.opener.open(req, timeout=20) as response:
                raw = response.read(3_000_001)
                if len(raw) > 3_000_000:
                    raise SafeError("Respuesta API demasiado grande")
                return json.loads(raw) if raw else {}
        except HTTPError as exc:
            if exc.code == 404 and missing_ok:
                return None
            raise SafeError(f"Grafana HTTP {exc.code} en {method} {path}") from None
        except URLError:
            raise SafeError("No se puede conectar con Grafana en loopback") from None
        except (UnicodeError, json.JSONDecodeError):
            raise SafeError("Respuesta no JSON de Grafana") from None


def load_source(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    rules = data["alert_rules"]
    contacts = data["contact_points"]
    policy = data["policies"]
    if len(rules) != 10 or len(contacts) != 3:
        raise SafeError("El respaldo debe incluir exactamente 10 reglas y 3 integraciones")
    if len({r["uid"] for r in rules}) != 10 or len({c["uid"] for c in contacts}) != 3:
        raise SafeError("UID duplicado en el respaldo")
    if len({r["folderUID"] for r in rules}) != 1:
        raise SafeError("El respaldo contiene varias carpetas; revisar la migración")
    if any("settings" in c or "secureSettings" in c for c in contacts):
        raise SafeError("Se esperaban contactos saneados sin valores privados")
    if not any(r["uid"] == "ag3v526avhipsb" and r["labels"].get("environment") == "lab" for r in rules):
        raise SafeError("Falta identificar la alerta de laboratorio")
    if policy.get("routes") != [{"object_matchers": [["triage", "=", "enabled"]],
                                   "receiver": "Security Triage Bot"}]:
        raise SafeError("El árbol de políticas no coincide con la exportación original")
    if {c["type"] for c in contacts} != {"telegram", "email", "webhook"}:
        raise SafeError("Faltan tipos de contacto originales")
    return data


# Only relevant, source-derived fields are sent to the API. Grafana-managed DB IDs are discarded.
RULE_FIELDS = ("uid", "title", "ruleGroup", "folderUID", "condition", "data", "for",
               "noDataState", "execErrState", "labels", "annotations")


def rule_payload(original: dict, active: bool):
    result = {k: copy.deepcopy(original[k]) for k in RULE_FIELDS if k in original}
    result["orgId"] = int(original.get("orgID", 1))
    result["keepFiringFor"] = original.get("keep_firing_for", "0s")
    # Even during activation, a demo alert is deliberately never enabled.
    result["isPaused"] = not active or original["uid"] == "ag3v526avhipsb"
    if active and original.get("notification_settings"):
        result["notification_settings"] = copy.deepcopy(original["notification_settings"])
    return result


def comparable(rule):
    # Grafana can populate generated fields, IDs and defaults. Compare source logic.
    fields = ("uid", "title", "ruleGroup", "folderUID", "condition", "for",
              "noDataState", "execErrState", "labels", "annotations")
    a = {k: rule.get(k) for k in fields}
    a["expressions"] = [r.get("model", {}).get("expr") for r in rule.get("data", [])]
    a["thresholds"] = [r.get("model", {}).get("conditions") for r in rule.get("data", [])]
    return a


def validate_contact_runtime(source, raw):
    if not raw:
        raise SafeError("Para activar faltan los 3 contactos privados en VAR_GRAFANA_ALERTING_CONTACTS_JSON")
    try:
        contacts = json.loads(raw)
    except json.JSONDecodeError:
        raise SafeError("JSON privado de contactos inválido") from None
    if not isinstance(contacts, list) or len(contacts) != 3:
        raise SafeError("Deben aportarse exactamente tres integraciones privadas")
    by_uid = {c.get("uid"): c for c in contacts if isinstance(c, dict)}
    if set(by_uid) != {c["uid"] for c in source["contact_points"]}:
        raise SafeError("Los UID privados no coinciden con los originales")
    for meta in source["contact_points"]:
        cp = by_uid[meta["uid"]]
        if cp.get("name") != meta["name"] or cp.get("type") != meta["type"]:
            raise SafeError("Nombre o tipo de contacto distinto del original")
        settings = cp.get("settings")
        if not isinstance(settings, dict) or set(settings) != set(meta["settings_keys"]):
            raise SafeError("Faltan ajustes originales de una integración")
        required = {"telegram": ("bottoken", "chatid"), "email": ("addresses",),
                    "webhook": ("url",)}[meta["type"]]
        if any(not settings.get(k) for k in required):
            raise SafeError("Falta un destino o credencial obligatoria")
    return contacts


def apply(source, client, mode: str, folder_title: str, contacts_json: str = ""):
    if not folder_title or len(folder_title) > 150:
        raise SafeError("Título de carpeta Grafana obligatorio")
    contacts_private = validate_contact_runtime(source, contacts_json) if mode == "activate" else []
    folder_uid = source["alert_rules"][0]["folderUID"]
    existing = client.request("GET", "/api/v1/provisioning/alert-rules")
    if not isinstance(existing, list):
        raise SafeError("Grafana no devolvió una lista de reglas")
    by_uid = {r["uid"]: r for r in existing}
    # Validate every collision before writing anything.
    for rule in source["alert_rules"]:
        old = by_uid.get(rule["uid"])
        if old is not None and comparable(old) != comparable(rule):
            raise SafeError("Deriva o colisión en regla: " + rule["uid"])
    folder = client.request("GET", "/api/folders/" + quote(folder_uid), missing_ok=True)
    if folder is None:
        client.request("POST", "/api/folders", {"uid": folder_uid, "title": folder_title})
    elif folder.get("uid") != folder_uid:
        raise SafeError("UID de carpeta inesperado")

    created_contacts = 0
    if mode == "activate":
        current_cp = client.request("GET", "/api/v1/provisioning/contact-points")
        if not isinstance(current_cp, list):
            raise SafeError("Grafana no devolvió contactos válidos")
        indexed_cp = {c.get("uid"): c for c in current_cp}
        for cp in contacts_private:
            old = indexed_cp.get(cp["uid"])
            if old is None:
                client.request("POST", "/api/v1/provisioning/contact-points", cp)
                created_contacts += 1
            elif (old.get("name"), old.get("type")) != (cp["name"], cp["type"]):
                raise SafeError("Colisión de contacto " + cp["uid"])
        # Replaces Grafana's one notification policy tree; activate is explicit.
        current_policy = client.request("GET", "/api/v1/provisioning/policies")
        orig = source["policies"]
        if ({k: current_policy.get(k) for k in ("receiver", "group_by", "routes")}
                != {k: orig.get(k) for k in ("receiver", "group_by", "routes")}):
            client.request("PUT", "/api/v1/provisioning/policies", orig)

    created, updated, untouched = 0, 0, 0
    for rule in source["alert_rules"]:
        want = rule_payload(rule, mode == "activate")
        old = by_uid.get(rule["uid"])
        if old is None:
            result = client.request("POST", "/api/v1/provisioning/alert-rules", want)
            if result.get("uid") != want["uid"]:
                raise SafeError("Grafana no confirmó UID " + want["uid"])
            created += 1
        elif mode == "activate" and (
            old.get("isPaused") != want["isPaused"] or
            old.get("notification_settings") != want.get("notification_settings")
        ):
            result = client.request("PUT", "/api/v1/provisioning/alert-rules/" + quote(want["uid"]), want)
            if result.get("uid") != want["uid"]:
                raise SafeError("No se verificó actualización " + want["uid"])
            updated += 1
        else:
            untouched += 1

    final = client.request("GET", "/api/v1/provisioning/alert-rules")
    check = {r["uid"]: r for r in final}
    if any(r["uid"] not in check for r in source["alert_rules"]):
        raise SafeError("No aparecen las 10 reglas en Grafana")
    if any((check[r["uid"]].get("isPaused") is not True)
           for r in source["alert_rules"] if r["uid"] == "ag3v526avhipsb"):
        raise SafeError("La alerta de laboratorio debe seguir pausada")
    return {"mode": mode, "rules_total": 10, "created": created,
            "updated": updated, "unchanged": untouched, "contacts_created": created_contacts,
            "lab_paused": True, "policies_applied": mode == "activate"}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--mode", choices=("plan", "stage", "activate"), default="plan")
    parser.add_argument("--port", type=int, default=3000)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--folder-title", default="Infrastructure")
    args = parser.parse_args(argv)
    try:
        source = load_source(args.source)
        if args.mode == "plan":
            result = {"mode": "plan", "rules": len(source["alert_rules"]),
                      "contacts_metadata": len(source["contact_points"]),
                      "policies": 1, "lab_rule": "always paused",
                      "writes": 0}
        else:
            client = Grafana(args.port, os.getenv("GRAFANA_ALERTING_USERNAME", ""),
                             os.getenv("GRAFANA_ALERTING_PASSWORD", ""), args.host)
            result = apply(source, client, args.mode, args.folder_title,
                           os.getenv("VAR_GRAFANA_ALERTING_CONTACTS_JSON", ""))
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except (SafeError, OSError, ValueError, KeyError, TypeError) as exc:
        print("ERROR SEGURO: " + (str(exc) if isinstance(exc, SafeError) else "fuente o API inválida"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
