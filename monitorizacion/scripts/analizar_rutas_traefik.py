#!/usr/bin/env python3
"""Analiza recursos Kubernetes del Job 19 sin emitir nombres, hosts ni IPs.

Entrada: JSON por stdin. Salida: solo contadores y estados no sensibles.
No modifica archivos ni recursos Kubernetes.
"""

import json
import sys
from collections import defaultdict


def items(document):
    if not isinstance(document, dict):
        return []
    val = document.get("items", [])
    return val if isinstance(val, list) else []


def analyze(payload):
    routes = items(payload.get("routes"))
    service_doc = payload.get("services")
    services = items(service_doc)
    slices_enabled = bool(payload.get("slices_available", False))
    slices = items(payload.get("slices")) if slices_enabled else []

    svc_idx = {}
    for service in services:
        meta = service.get("metadata") or {}
        svc_idx[(meta.get("namespace", "default"), meta.get("name"))] = service

    ready_slices = defaultdict(int)
    for piece in slices:
        meta = piece.get("metadata") or {}
        service_name = (meta.get("labels") or {}).get("kubernetes.io/service-name")
        if not service_name:
            continue
        key = (meta.get("namespace", "default"), service_name)
        for endpoint in piece.get("endpoints") or []:
            conditions = endpoint.get("conditions") or {}
            if conditions.get("ready", True) is not False and endpoint.get("addresses"):
                ready_slices[key] += 1

    summary = {
        "ingress_routes": len(routes),
        "http_route_rules": 0,
        "service_refs": 0,
        "service_refs_valid": 0,
        "service_refs_missing": 0,
        "service_refs_port_missing": 0,
        "service_refs_without_ready_endpoints": 0,
        "service_refs_endpoints_not_checked": 0,
        "traefik_service_refs_not_checked": 0,
        "other_backend_refs_not_checked": 0,
        "routes_using_tls": 0,
        "routes_with_middlewares": 0,
        "routes_without_explicit_entrypoints": 0,
        "service_type": (payload.get("traefik_service") or {}).get("spec", {}).get("type", "NO ENCONTRADO"),
        "service_ports": [],
        "endpointslices_available": slices_enabled,
        "helmchartconfig_status": payload.get("helmchartconfig_status", "NO CONSULTADO"),
    }
    summary["service_ports"] = sorted({
        f"{p.get('port')}/{p.get('protocol', 'TCP')}"
        for p in ((payload.get("traefik_service") or {}).get("spec", {}).get("ports") or [])
        if isinstance(p, dict) and p.get("port") is not None
    })

    for obj in routes:
        meta = obj.get("metadata") or {}
        ns = meta.get("namespace", "default")
        spec = obj.get("spec") or {}
        if spec.get("tls") is not None:
            summary["routes_using_tls"] += 1
        if not spec.get("entryPoints"):
            summary["routes_without_explicit_entrypoints"] += 1
        for rule in spec.get("routes") or []:
            summary["http_route_rules"] += 1
            if rule.get("middlewares"):
                summary["routes_with_middlewares"] += 1
            for backend in rule.get("services") or []:
                kind = backend.get("kind") or "Service"
                if kind == "TraefikService":
                    summary["traefik_service_refs_not_checked"] += 1
                    continue
                if kind != "Service":
                    summary["other_backend_refs_not_checked"] += 1
                    continue
                summary["service_refs"] += 1
                target_key = (backend.get("namespace") or ns, backend.get("name"))
                svc = svc_idx.get(target_key)
                if not svc:
                    summary["service_refs_missing"] += 1
                    continue
                port = backend.get("port")
                ports = (svc.get("spec") or {}).get("ports") or []
                if not any(str(port) in (str(p.get("port")), str(p.get("name"))) for p in ports):
                    summary["service_refs_port_missing"] += 1
                    continue
                summary["service_refs_valid"] += 1
                if (svc.get("spec") or {}).get("type") == "ExternalName":
                    summary["service_refs_endpoints_not_checked"] += 1
                elif not slices_enabled:
                    summary["service_refs_endpoints_not_checked"] += 1
                elif ready_slices.get(target_key, 0) == 0:
                    summary["service_refs_without_ready_endpoints"] += 1

    summary["backend_references_consistent"] = (
        summary["service_refs_missing"] == 0
        and summary["service_refs_port_missing"] == 0
    )
    return summary


def main():
    payload = json.load(sys.stdin)
    print(json.dumps(analyze(payload), sort_keys=True))


if __name__ == "__main__":
    main()
