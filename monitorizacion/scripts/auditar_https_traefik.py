#!/usr/bin/env python3
"""Auditoría no destructiva del HTTPS servido por Traefik desde un host interno.

Recibe por stdin el JSON de IngressRoutes + Service obtenido con kubectl.
No imprime nombres de dominio, IPs, certificados ni cabeceras HTTP.
"""
import datetime as dt
import http.client
import ipaddress
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
from urllib.parse import urlsplit

_HOST_RE = re.compile(r"Host\s*\(\s*([`\"'])\s*([A-Za-z0-9.-]+)\s*\1\s*\)")
_SAFE_HOST_RE = re.compile(r"(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$")
_REDIRECT = {301, 302, 303, 307, 308}


def selected_private_address(service):
    """Solo probar una IP no global anunciada por ESTE Service Kubernetes."""
    for item in service.get("status", {}).get("loadBalancer", {}).get("ingress", []):
        value = item.get("ip", "")
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback) and not ip.is_multicast and not ip.is_unspecified:
            return str(ip)
    return None


def candidate_route_hosts(routes):
    hosts = set()
    for item in routes.get("items", []):
        for route in item.get("spec", {}).get("routes", []):
            for match in _HOST_RE.findall(route.get("match", "")):
                h = match[1].lower().rstrip(".")
                if _SAFE_HOST_RE.fullmatch(h):
                    hosts.add(h)
    return sorted(hosts)


def openssl_cert_check(cert_der, host, days):
    """Valida caducidad y coincidencia de hostname sin leer claves privadas."""
    if not shutil.which("openssl"):
        return {"cert_metadata": "OPENSSL_NO_DISPONIBLE"}
    base = ["openssl", "x509", "-inform", "DER", "-noout"]
    try:
        expiry = subprocess.run(base + ["-checkend", str(days * 86400)], input=cert_der,
                                capture_output=True, timeout=5, check=False)
        hostmatch = subprocess.run(base + ["-checkhost", host], input=cert_der,
                                   capture_output=True, timeout=5, check=False)
        date = subprocess.run(base + ["-enddate"], input=cert_der,
                              capture_output=True, timeout=5, check=False)
        remaining = None
        if date.returncode == 0 and date.stdout.startswith(b"notAfter="):
            expires = dt.datetime.strptime(date.stdout.decode("ascii").strip().split("=", 1)[1],
                                           "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
            remaining = int((expires - dt.datetime.now(dt.timezone.utc)).total_seconds() // 86400)
        return {
            "cert_metadata": "OK" if date.returncode == 0 else "NO_EVALUABLE",
            "cert_valid_beyond_warning_days": expiry.returncode == 0,
            "cert_hostname_matches": hostmatch.returncode == 0,
            "cert_days_remaining": remaining,
        }
    except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError):
        return {"cert_metadata": "NO_EVALUABLE"}


def tls_probe(ip, hostname, timeout, days):
    out = {"tls_connection": "NO_EVALUADO", "trusted_by_host": "NO_EVALUADO"}
    try:
        # Primera conexión: lectura del certificado aunque sea autofirmado.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=timeout) as tcp:
            with ctx.wrap_socket(tcp, server_hostname=hostname) as tls:
                der = tls.getpeercert(binary_form=True)
                out["tls_connection"] = "OK"
                out["tls_version"] = tls.version() or "DESCONOCIDA"
        if der:
            out.update(openssl_cert_check(der, hostname, days))
        else:
            out["cert_metadata"] = "CERTIFICADO_NO_DISPONIBLE"
        # Segunda conexión: comprobar confianza y hostname desde el host que ejecuta AWX.
        try:
            with socket.create_connection((ip, 443), timeout=timeout) as tcp:
                with ssl.create_default_context().wrap_socket(tcp, server_hostname=hostname):
                    pass
            out["trusted_by_host"] = "SI"
        except ssl.SSLCertVerificationError:
            out["trusted_by_host"] = "NO"
        except (OSError, ssl.SSLError):
            out["trusted_by_host"] = "NO_EVALUABLE"
    except (OSError, ssl.SSLError):
        out["tls_connection"] = "ERROR_CONEXION_O_TLS"
    return out


def http_probe(ip, hostname, timeout):
    try:
        conn = http.client.HTTPConnection(ip, 80, timeout=timeout)
        try:
            # HEAD no sigue redirecciones ni recupera el contenido de la aplicación.
            conn.request("HEAD", "/", headers={"Host": hostname, "Connection": "close",
                                               "User-Agent": "awx-traefik-audit/1.0"})
            response = conn.getresponse()
            status = response.status
            location = response.getheader("Location", "")
        finally:
            conn.close()
        if status in _REDIRECT:
            target = urlsplit(location)
            if target.scheme.lower() == "https":
                redirect = "HTTPS_OBSERVADO"
            elif not target.scheme and location.startswith("/"):
                redirect = "RELATIVO_NO_CONCLUYENTE"
            else:
                redirect = "OTRO_DESTINO"
        else:
            redirect = "NO_OBSERVADO_EN_HEAD_RAIZ"
        return {"http_status": status, "http_redirect": redirect}
    except (OSError, http.client.HTTPException, ValueError):
        return {"http_status": None, "http_redirect": "NO_EVALUABLE"}


def analyse(payload):
    routes = payload.get("routes", {})
    service = payload.get("service", {})
    hosts = candidate_route_hosts(routes)
    override = str(payload.get("hostname", "")).strip().lower().rstrip(".")
    timeout = float(payload.get("timeout", 4))
    days = int(payload.get("warn_days", 30))
    if not 1 <= timeout <= 10 or not 1 <= days <= 365:
        raise ValueError("Parámetros de auditoría fuera de límites")
    summary = {
        "mode": "AUDITORIA",
        "routes": len(routes.get("items", [])),
        "route_host_count": len(hosts),
        "http_redirect": "NO_EVALUADO",
        "tls_connection": "NO_EVALUADO",
        "trusted_by_host": "NO_EVALUADO",
        "cert_metadata": "NO_EVALUADO",
        "reason": "",
    }
    address = selected_private_address(service)
    if not address:
        summary["reason"] = "SIN_IP_INTERNA_EN_LOADBALANCER"
        return summary
    if override:
        if not _SAFE_HOST_RE.fullmatch(override):
            summary["reason"] = "HOSTNAME_INVALIDO"
            return summary
        # No se admiten hosts arbitrarios: el SNI debe figurar en una IngressRoute.
        if override not in hosts:
            summary["reason"] = "HOSTNAME_NO_PRESENTE_EN_INGRESSROUTE"
            return summary
        host = override
    elif len(hosts) == 1:
        host = hosts[0]
    else:
        summary["reason"] = "HOST_AMBIGUO_O_NO_EXTRAIBLE"
        return summary
    summary["reason"] = "PROBADO_DESDE_HOST_ANSIBLE"
    summary.update(tls_probe(address, host, timeout, days))
    summary.update(http_probe(address, host, timeout))
    return summary


def main():
    try:
        payload = json.load(sys.stdin)
        print(json.dumps(analyse(payload), sort_keys=True, separators=(",", ":")))
    except (ValueError, TypeError, json.JSONDecodeError):
        # No imprimir valores de entrada ni infraestructura interna.
        print(json.dumps({"error": "ENTRADA_INVALIDA"}))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
