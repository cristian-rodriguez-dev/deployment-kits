#!/usr/bin/env python3
import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import sys
import time

from workflow.manage_workflow import AwxApi, ProvisionError

GROUPS = ("docker_servers", "wazuh-servers", "prometheus-servers", "grafana-servers", "k3s-servers")
INVENTORY = "Ubuntu 26.04 - Instalacion limpia"
PROJECT = "deployment-kits"


def main():
    parser = argparse.ArgumentParser(description="Preparar proyecto, inventario y grupos AWX en instalación limpia")
    parser.add_argument("--url", required=True)
    parser.add_argument("--scm-url", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--host", required=True, help="Hostname lógico del servidor")
    parser.add_argument("--host-ip", required=True, help="IP del host por SSH")
    parser.add_argument("--vars-file", required=True, type=Path, help="YAML de inventario local SIN secretos")
    parser.add_argument("--scm-credential", help="Nombre de credencial SCM ya creada, si el repo es privado")
    parser.add_argument("--apply", action="store_true", help="Crear recursos y sincronizar proyecto")
    args = parser.parse_args()
    try:
        ipaddress.IPv4Address(args.host_ip)
    except ipaddress.AddressValueError as e:
        raise ProvisionError("--host-ip no es IPv4 válida") from e
    if not args.scm_url.startswith(("https://", "ssh://", "git@")):
        raise ProvisionError("SCM URL debe ser Git HTTPS o SSH")
    if "@" in args.scm_url.split("//")[-1] and args.scm_url.startswith("https://"):
        raise ProvisionError("Nunca incluyas tokens o usuarios en --scm-url")
    text = args.vars_file.read_text(encoding="utf-8")
    if len(text) < 50 or any(secret in text for secret in ("VAR_WAZUH_ADMIN_PASSWORD:", "VAR_WAZUH_API_PASSWORD:", "VAR_GRAFANA_ADMIN_PASSWORD:")):
        raise ProvisionError("Archivo de variables ausente, demasiado corto o contiene credenciales")
    if "REEMPLAZAR_HOSTNAME_REAL_K3S" in text:
        raise ProvisionError("Rellena var_ubuntu26_k3s_node_name antes de continuar")
    if not args.apply:
        print(f"PLAN: proyecto {PROJECT}; inventario {INVENTORY}; host {args.host}; grupos {GROUPS}; rama {args.branch}")
        print("No se han creado recursos. Añade --apply cuando estén listas las credenciales AWX.")
        return
    token = os.environ.get("AWX_TOKEN") or getpass.getpass("Token AWX: ")
    api = AwxApi(args.url, token)
    org = api.one_by_name("organizations", "Default")
    inventory = api.one_by_name("inventories", INVENTORY, required=False)
    if inventory is None:
        inventory = api.request("POST", "/api/v2/inventories/", {"name": INVENTORY, "organization": org["id"], "variables": text})
    elif inventory["organization"] != org["id"] or inventory.get("variables", "").strip() != text.strip():
        raise ProvisionError("Inventario ya existe con variables/organización distintas: revisión manual")
    host = api.one_by_name("hosts", args.host, required=False)
    hostvars = json.dumps({"ansible_host": args.host_ip})
    if host is None:
        host = api.request("POST", f"/api/v2/inventories/{inventory['id']}/hosts/", {"name": args.host, "variables": hostvars})
    elif host.get("inventory") != inventory["id"] or json.loads(host.get("variables") or "{}") != json.loads(hostvars):
        raise ProvisionError("Host existente distinto; no sustituir ni duplicar")
    for name in (*GROUPS, "monitoring-agents"):
        group = next((g for g in api.all(f"/api/v2/inventories/{inventory['id']}/groups/?page_size=200") if g["name"] == name), None)
        if group is None:
            group = api.request("POST", f"/api/v2/inventories/{inventory['id']}/groups/", {"name": name})
        if name in GROUPS:
            current = api.all(f"/api/v2/groups/{group['id']}/hosts/?page_size=200")
            if any(h["id"] != host["id"] for h in current):
                raise ProvisionError(f"Grupo {name} contiene hosts distintos")
            if not any(h["id"] == host["id"] for h in current):
                api.request("POST", f"/api/v2/groups/{group['id']}/hosts/", {"id": host["id"]})
    scm = api.one_by_name("credentials", args.scm_credential) if args.scm_credential else None
    project = api.one_by_name("projects", PROJECT, required=False)
    if project is None:
        payload = {"name": PROJECT, "organization": org["id"], "scm_type": "git", "scm_url": args.scm_url,
                   "scm_branch": args.branch, "scm_update_on_launch": False}
        if scm:
            payload["credential"] = scm["id"]
        project = api.request("POST", "/api/v2/projects/", payload)
    elif project.get("scm_url") != args.scm_url or project.get("scm_branch") != args.branch or project.get("organization") != org["id"]:
        raise ProvisionError("Proyecto existe con rama/URL distintas; no modificar")
    if project.get("status") != "successful":
        res = api.request("POST", f"/api/v2/projects/{project['id']}/update/", {})
        update_id = res.get("id")
        if not update_id:
            raise ProvisionError("AWX no devolvió ID de sincronización de proyecto")
        for _ in range(90):
            update = api.request("GET", f"/api/v2/project_updates/{update_id}/")
            if update["status"] == "successful":
                break
            if update["status"] in ("failed", "error", "canceled"):
                raise ProvisionError("Fallo en sincronización SCM: revisa log AWX y credencial Git")
            time.sleep(5)
        else:
            raise ProvisionError("Tiempo agotado sincronizando Git")
    print("AWX preparado: proyecto sincronizado, inventario, host único y grupos centrales. Credenciales de ejecución siguen en AWX.")


if __name__ == "__main__":
    try:
        main()
    except (ProvisionError, ValueError, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)
