#!/usr/bin/env python3
"""Auditoría agregada de TLS y exposición declarada en Traefik/K3s.

Entrada por stdin JSON con recursos ya consultados sin escrituras.
Salida por stdout únicamente resumen agregado, sin hosts, IPs o datos de Secrets.
"""

import ipaddress
import json
import sys


def _items(resource):
    if isinstance(resource, dict) and isinstance(resource.get("items"), list):
        return resource["items"]
    return []


def _secret_index(text):
    result = {}
    if not isinstance(text, str):
        return result
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            namespace, name, kind = (item.strip() for item in parts)
            if namespace and name:
                result[(namespace, name)] = kind
    return result


def analyze(payload):
    routes = _items(payload.get("routes"))
    secrets_available = bool(payload.get("secret_metadata_available"))
    secrets = _secret_index(payload.get("secret_metadata", "")) if secrets_available else {}
    service = payload.get("traefik_service") or {}
    spec = service.get("spec") or {}
    lb = ((service.get("status") or {}).get("loadBalancer") or {}).get("ingress") or []

    summary = {
        "routes": len(routes),
        "routes_with_tls": 0,
        "routes_without_tls": 0,
        "tls_explicit_secret": 0,
        "tls_cert_resolver": 0,
        "tls_default_or_other": 0,
        "tls_secrets_found_correct_type": 0,
        "tls_secrets_missing": 0,
        "tls_secrets_wrong_type": 0,
        "tls_secrets_unchecked": 0,
        "tls_options_references": 0,
        "routes_with_middlewares": 0,
        "service_type": spec.get("type", "NO ENCONTRADO"),
        "service_ports": sorted({f"{x.get('port')}/{x.get('protocol', 'TCP')}" for x in spec.get("ports") or [] if isinstance(x, dict) and x.get("port") is not None}),
        "service_loadbalancer_address_count": 0,
        "service_loadbalancer_private_or_nonglobal": 0,
        "service_loadbalancer_global_ip": 0,
        "service_loadbalancer_hostname": 0,
        "secret_metadata_accessible": secrets_available,
        "certificate_expiry_checked": False,
        "https_reachability_checked": False,
        "http_to_https_redirect_checked": False,
    }

    for route in routes:
        metadata = route.get("metadata") or {}
        namespace = metadata.get("namespace") or "default"
        rspec = route.get("spec") or {}
        tls = rspec.get("tls")
        if tls is None:
            summary["routes_without_tls"] += 1
        else:
            summary["routes_with_tls"] += 1
            if not isinstance(tls, dict):
                tls = {}
            ref = tls.get("secretName")
            resolver = tls.get("certResolver")
            if ref:
                summary["tls_explicit_secret"] += 1
                if not secrets_available:
                    summary["tls_secrets_unchecked"] += 1
                else:
                    secret_type = secrets.get((namespace, ref))
                    if secret_type is None:
                        summary["tls_secrets_missing"] += 1
                    elif secret_type == "kubernetes.io/tls":
                        summary["tls_secrets_found_correct_type"] += 1
                    else:
                        summary["tls_secrets_wrong_type"] += 1
            if resolver:
                summary["tls_cert_resolver"] += 1
            if not ref and not resolver:
                summary["tls_default_or_other"] += 1
            if tls.get("options"):
                summary["tls_options_references"] += 1
        if any((x or {}).get("middlewares") for x in rspec.get("routes") or [] if isinstance(x, dict)):
            summary["routes_with_middlewares"] += 1

    for address in lb:
        if not isinstance(address, dict):
            continue
        if address.get("ip"):
            summary["service_loadbalancer_address_count"] += 1
            try:
                ip = ipaddress.ip_address(address["ip"])
                if ip.is_global:
                    summary["service_loadbalancer_global_ip"] += 1
                else:
                    summary["service_loadbalancer_private_or_nonglobal"] += 1
            except ValueError:
                summary["service_loadbalancer_hostname"] += 1
        elif address.get("hostname"):
            summary["service_loadbalancer_address_count"] += 1
            summary["service_loadbalancer_hostname"] += 1

    summary["tls_secret_references_consistent"] = (
        secrets_available
        and summary["tls_secrets_missing"] == 0
        and summary["tls_secrets_wrong_type"] == 0
        and summary["tls_secrets_unchecked"] == 0
    )
    return summary


def main():
    payload = json.load(sys.stdin)
    print(json.dumps(analyze(payload), sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    main()
