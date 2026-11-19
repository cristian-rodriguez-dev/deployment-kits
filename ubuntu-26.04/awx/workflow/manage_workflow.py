#!/usr/bin/env python3

"""Fase 11 · Preparar, inspeccionar e IMPORTAR (sin lanzar) AWX 26.04.

Solo Python estándar. Por defecto trabaja completamente offline. No crea
inventarios, credenciales ni hosts y nunca llama a endpoints /launch/.
"""

from __future__ import annotations



import argparse

import getpass

import ipaddress

import json

import os

from pathlib import Path

import re

import ssl

import sys

from urllib.error import HTTPError, URLError

from urllib.parse import urlsplit

from urllib.request import HTTPRedirectHandler, Request, build_opener, HTTPSHandler, HTTPHandler



ROOT = Path(__file__).resolve().parent

MANIFEST = ROOT / "workflow.json"

MARKER = "[managed-by:deployment-kits-26.04-fast]"

VALID_GROUPS = (

    "docker_servers", "wazuh-servers", "prometheus-servers",

    "grafana-servers", "monitoring-agents", "k3s-servers",

)





class ProvisionError(Exception):

    pass





def require(condition: bool, message: str) -> None:

    if not condition:

        raise ProvisionError(message)





def validate_manifest(data: dict) -> list[str]:

    """Solo validación estructural del orden; sin aprobaciones artificiales."""

    require(data.get("schema_version") == 1, "Esquema de manifiesto desconocido")

    require(data.get("target_os") == "Ubuntu 26.04 LTS", "SO incorrecto")

    require(bool(data.get("inventory")), "Falta nombre de inventario")

    nodes = data["nodes"]

    chain = ['00', '01', '02', '03', '04', '05', '08', '08B', '09A', '09B', '09D', '09C', '09E', '10', '11', '12', '13', '14', '15', '16', '18']

    require([n.get("id") for n in nodes] == chain, "Orden de Jobs de un único host incorrecto")

    for i, n in enumerate(nodes):

        require(n.get("type") == "job", "No se usan nodos de aprobación en el instalador rápido")

        require(n.get("after", []) == ([chain[i-1]] if i else []), "Dependencia incorrecta")

        require(n.get("playbook", "").startswith("ubuntu-26.04/playbooks/") and

                n["playbook"].endswith(".yml"), "Ruta de playbook inválida")

        require(isinstance(n.get("extra_data"), dict), "extra_data debe ser un objeto")

        require(all(key in data["credentials"] for key in n.get("credentials", [])), "Credencial desconocida")

    return chain





class NoRedirect(HTTPRedirectHandler):

    def redirect_request(self, req, fp, code, msg, headers, newurl):

        raise ProvisionError("AWX devolvió una redirección inesperada; revisa --url (no seguir para proteger el token)")





class AwxApi:

    def __init__(self, url: str, token: str):

        url = url.rstrip("/")

        parsed = urlsplit(url)

        loopback = parsed.hostname in ("localhost", "127.0.0.1", "::1")

        require(parsed.scheme == "https" or (parsed.scheme == "http" and loopback),

                "AWX requiere HTTPS, excepto túnel SSH a localhost/127.0.0.1")

        require(parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment,

                "URL inválida: no incluir usuario/contraseña/parámetros")

        require(parsed.path in ("", "/"), "Usa la URL base del servidor AWX sin /api/v2")

        require(bool(token), "Se requiere token AWX; nunca se guarda en disco")

        self.url = url

        self.token = token

        self.opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), HTTPHandler(), NoRedirect())



    def request(self, method: str, path: str, data: dict | None = None):

        require(path.startswith("/api/v2/"), f"Ruta API inesperada: {path}")

        require("/launch/" not in path and "/cancel/" not in path and "/schedules/" not in path,

                "Operación de ejecución o programación prohibida")

        payload = None if data is None else json.dumps(data, separators=(",", ":")).encode("utf-8")

        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json"}

        if payload is not None:

            headers["Content-Type"] = "application/json"

        req = Request(self.url + path, data=payload, headers=headers, method=method)

        try:

            with self.opener.open(req, timeout=25) as r:

                content = r.read()

                return json.loads(content) if content else {}

        except HTTPError as exc:

                                                                                    

            raise ProvisionError(f"AWX HTTP {exc.code} en {method} {path}; revisa token, permisos y campos") from exc

        except URLError as exc:

            raise ProvisionError(f"No se puede acceder a AWX en {self.url}; revisa el túnel y TLS") from exc



    def all(self, path: str) -> list[dict]:

        results = []

        current = path

        for _ in range(100):

            obj = self.request("GET", current)

            require(isinstance(obj, dict) and "results" in obj, f"Respuesta paginada inesperada: {current}")

            results.extend(obj["results"])

            nxt = obj.get("next")

            if not nxt:

                return results

                                                                     

            parts = urlsplit(nxt)

            if parts.scheme or parts.netloc:

                require(nxt.startswith(self.url + "/api/v2/"), "Paginación fuera del servidor AWX")

                nxt = nxt[len(self.url):]

            require(nxt.startswith("/api/v2/"), "Paginación de API inválida")

            current = nxt

        raise ProvisionError("Demasiadas páginas de AWX")



    def one_by_name(self, collection: str, name: str, required: bool = True) -> dict | None:

        rows = [r for r in self.all(f"/api/v2/{collection}/?page_size=200") if r.get("name") == name]

        require(len(rows) <= 1, f"Recurso ambiguo '{name}' en {collection}")

        require(bool(rows) or not required, f"No existe {collection}: {name}")

        return rows[0] if rows else None





def review_inventory(api: AwxApi, inventory: dict):

    """Revisar que el inventario exista; no imponer topología ni IP de laboratorio."""

    inventory_id = inventory["id"]

    all_groups = api.all(f"/api/v2/inventories/{inventory_id}/groups/?page_size=200")

    group_names = {g.get("name") for g in all_groups}

                                                                           

    required = {"docker_servers", "wazuh-servers", "prometheus-servers", "grafana-servers", "k3s-servers"}

    missing = required - group_names

    require(not missing, "Faltan grupos de instalación: " + ", ".join(sorted(missing)))

    groups = {}

    for g in all_groups:

        if g.get("name") in VALID_GROUPS:

            groups[g["name"]] = {h["name"] for h in api.all(f"/api/v2/groups/{g['id']}/hosts/?page_size=200")}

    core_hosts = [groups[name] for name in sorted(required)]

    require(all(len(hosts) == 1 for hosts in core_hosts) and

            len(set.union(*core_hosts)) == 1,

            "Los cinco grupos principales deben apuntar a un mismo host")

    return groups





def awx_context(api: AwxApi, manifest: dict):

    org = api.one_by_name("organizations", manifest["organization"])

    project = api.one_by_name("projects", manifest["project"])

    inventory = api.one_by_name("inventories", manifest["inventory"])

    require(inventory["organization"] == org["id"] and project["organization"] == org["id"],

            "Organización del inventario/proyecto no coincide")

    require(project.get("scm_type") == "git", "El proyecto debe proceder de Git")

    require(bool(project.get("scm_url")) and "deployment-kits" in project["scm_url"].lower(),

            "El proyecto Git no apunta a deployment-kits")

    require(project.get("status") == "successful",

            "El proyecto Git debe estar sincronizado correctamente antes de importar Jobs")

    groups = review_inventory(api, inventory)

    credentials = {}

    for key, name in manifest["credentials"].items():

        credential = api.one_by_name("credentials", name)

        credentials[key] = credential["id"]

    print("Inventario revisado (sin cambios):")

    for name in VALID_GROUPS:

        print(f"  {name}: {', '.join(sorted(groups.get(name, set())))}")

    print("Proyecto, organización y credenciales localizados.")

    print("Pendiente de revisar manualmente: sistema operativo real, secreto de credenciales, versiones y variables por grupo.")

    return org, project, inventory, credentials





def _existing_or_create(api: AwxApi, collection: str, name: str, payload: dict, check_fields: tuple[str, ...]):

    existing = api.one_by_name(collection, name, required=False)

    if existing:

        require(MARKER in existing.get("description", ""), f"{collection}/{name} existe sin nuestra marca: no adoptar")

        for key in check_fields:

            require(existing.get(key) == payload.get(key), f"{collection}/{name} difiere en {key}; no actualizar")

        print(f"[CONSERVAR] {collection}: {name}")

        return existing

    created = api.request("POST", f"/api/v2/{collection}/", payload)

    print(f"[CREADO] {collection}: {name} (id={created.get('id')})")

    return created





def _credentials_for_job(api: AwxApi, template: dict, required_ids: list[int]):

    path = f"/api/v2/job_templates/{template['id']}/credentials/"

    actual = {c["id"] for c in api.all(path + "?page_size=200")}

    require(not (actual - set(required_ids)),

            f"Template {template['name']} tiene credenciales ajenas; intervención manual")

    for cred_id in required_ids:

        if cred_id not in actual:

            api.request("POST", path, {"id": cred_id})

            print(f"  Credencial vinculada al template {template['name']} (id={cred_id})")





def import_workflow(api: AwxApi, manifest: dict, order: list[str], org: dict,

                    project: dict, inventory: dict, creds: dict):

    identifiers = {n["id"]: n for n in manifest["nodes"]}

    templates = {}

                                                                             

    for node_id in order:

        node = identifiers[node_id]

        if node["type"] != "job":

            continue

        payload = {

            "name": node["name"],

            "description": MARKER + " Instalación nueva, pendiente de validación · Job " + node_id,

            "job_type": "run", "project": project["id"], "inventory": inventory["id"],

            "playbook": node["playbook"],

            "ask_variables_on_launch": True,

            "ask_inventory_on_launch": False,

            "ask_credential_on_launch": False,

            "allow_simultaneous": False,

            "extra_vars": {},

        }

        jt = _existing_or_create(api, "job_templates", node["name"], payload,

                                 ("name", "job_type", "project", "inventory", "playbook",

                                  "ask_variables_on_launch", "ask_inventory_on_launch",

                                  "ask_credential_on_launch", "allow_simultaneous"))

        _credentials_for_job(api, jt, [creds[c] for c in node["credentials"]])

        templates[node_id] = jt



    workflow_payload = {

        "name": manifest["name"], "description": MARKER + " " + manifest["description"],

        "organization": org["id"], "inventory": inventory["id"],

        "ask_inventory_on_launch": False, "ask_variables_on_launch": False,

        "allow_simultaneous": False, "extra_vars": {},

    }

    wf = _existing_or_create(api, "workflow_job_templates", manifest["name"], workflow_payload,

                             ("name", "organization", "inventory", "ask_inventory_on_launch",

                              "ask_variables_on_launch", "allow_simultaneous"))



                                                                                     

    wpath = f"/api/v2/workflow_job_templates/{wf['id']}/workflow_nodes/"

    existing_nodes = api.all(wpath + "?page_size=200")

    require(all(n.get("identifier") in identifiers for n in existing_nodes),

            "El workflow existente contiene nodos ajenos; no modificar")

    require(len({n.get("identifier") for n in existing_nodes}) == len(existing_nodes),

            "Nodos duplicados en el workflow remoto")

    found = {n["identifier"]: n for n in existing_nodes}

    for node_id in order:

        spec = identifiers[node_id]

        convergence = bool(spec.get("all_parents_must_converge", False))

        if node_id in found:

            actual = found[node_id]

            require(bool(actual.get("all_parents_must_converge")) == convergence,

                    f"Convergencia distinta en {node_id}; no actualizar")

            if spec["type"] == "job":

                require(actual.get("unified_job_template") == templates[node_id]["id"],

                        f"Job Template equivocado en nodo {node_id}")

                value = actual.get("extra_data") or {}

                if isinstance(value, str):

                    value = json.loads(value)

                require(value == spec["extra_data"], f"Variables distintas en nodo {node_id}")

            else:

                require(actual.get("unified_job_template") is not None,

                        f"Nodo de aprobación {node_id} incompleto; revisar antes de reanudar")

            continue

        body = {"identifier": node_id, "all_parents_must_converge": convergence}

        if spec["type"] == "job":

            body.update({"unified_job_template": templates[node_id]["id"],

                         "extra_data": spec["extra_data"]})

        created = api.request("POST", wpath, body)

        if spec["type"] == "approval":

            api.request("POST", f"/api/v2/workflow_job_template_nodes/{created['id']}/create_approval_template/",

                        {"name": spec["name"], "description": spec["description"], "timeout": spec["timeout"]})

        found[node_id] = created

        print(f"[CREADO] Nodo {node_id} ({spec['type']})")



                                                                                    

    for node_id in order:

        for parent_id in identifiers[node_id].get("after", []):

            parent = found[parent_id]["id"]

            child = found[node_id]["id"]

            path = f"/api/v2/workflow_job_template_nodes/{parent}/success_nodes/"

            existing_success = {n["id"] for n in api.all(path + "?page_size=200")}

            if child not in existing_success:

                api.request("POST", path, {"id": child})

                print(f"[ENLACE] {parent_id} --éxito--> {node_id}")



                                                                        

    for node_id in order:

        current = found[node_id]

        base = f"/api/v2/workflow_job_template_nodes/{current['id']}/"

        expected_children = {found[k]["id"] for k in identifiers if node_id in identifiers[k].get("after", [])}

        actual_children = {n["id"] for n in api.all(base + "success_nodes/?page_size=200")}

        require(actual_children == expected_children, f"Enlaces de éxito distintos en {node_id}")

        require(not api.all(base + "failure_nodes/?page_size=200"), f"Enlaces de error inesperados: {node_id}")

        require(not api.all(base + "always_nodes/?page_size=200"), f"Enlaces ALWAYS inesperados: {node_id}")

    print(f"IMPORTACIÓN FINALIZADA · Workflow {wf['id']} · {len(order)} Jobs · NO LANZADO")

    print("Revisar Visualizer, variables/credenciales/grupos, compatibilidad y permisos antes de ejecutar.")





def validate_repo_sources(repo_root: Path, manifest: dict) -> None:

    """Verifica playbooks y dependencias importadas, no solo la existencia del wrapper.

    No ejecuta Ansible ni abre conexiones. Rechaza rutas fuera del repositorio.
    """

    root = repo_root.resolve()

    for node in manifest["nodes"]:

        if node["type"] != "job":

            continue

        source = (root / node["playbook"]).resolve()

        require(source.is_relative_to(root) and source.is_file(),

                f"No se encuentra playbook dentro del repositorio: {node['playbook']}")

        for line in source.read_text(encoding="utf-8").splitlines():

            match = re.match(r"^\s*-\s*import_playbook:\s*([^\s#]+)", line)

            if not match:

                continue

            imported = (source.parent / match.group(1)).resolve()

            require(imported.is_relative_to(root) and imported.is_file(),

                    f"Falta dependencia import_playbook en {node['playbook']}: {match.group(1)}")





def main(argv=None):

    parser = argparse.ArgumentParser(description="AWX 26.04: plan, inspección o importación (sin lanzamiento)")

    mode = parser.add_mutually_exclusive_group(required=True)

    mode.add_argument("--plan", action="store_true", help="Validar DAG y mostrar orden sin acceso AWX")

    mode.add_argument("--inspect", action="store_true", help="Solo lectura de AWX; comprobar recursos/inventario")

    mode.add_argument("--apply", action="store_true", help="Crear templates/workflow sin lanzarlos")

    parser.add_argument("--url", help="URL base de AWX (https://... o http://127.0.0.1:puerto por túnel)")

    parser.add_argument("--confirm", help="Compatibilidad con entregas anteriores; no es obligatorio")

    parser.add_argument("--repo-root", type=Path, help="Validar que los playbooks existen en el repo local")
    parser.add_argument("--resume-from", help="Crear un workflow adicional desde este Job, sin lanzarlo; requiere --apply")

    args = parser.parse_args(argv)

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    order = validate_manifest(manifest)

    if args.resume_from:
        require(args.apply, "--resume-from requiere --apply")
        require(args.resume_from in order, "Job de reanudación desconocido")
        offset = order.index(args.resume_from)
        tail = order[offset:]
        manifest = dict(manifest)
        manifest["name"] += " - Reanudar " + args.resume_from
        manifest["description"] += "; continuación desde Job " + args.resume_from
        manifest["nodes"] = [dict(n, after=[n["after"][0]] if n["after"] and n["after"][0] in tail else []) for n in manifest["nodes"][offset:]]
        order = tail

    if args.repo_root:

        validate_repo_sources(args.repo_root, manifest)

        print("Playbooks locales e importaciones estáticas encontrados.")

    if args.plan:

        print("PLAN OFFLINE · Ubuntu 26.04 · SIN DESPLIEGUE NI ACCESO A AWX")

        for key in order:

            node = next(n for n in manifest["nodes"] if n["id"] == key)

            parents = ", ".join(node.get("after", [])) or "INICIO"

            print(f"  {key:>19}  [{node['type']}]  después de: {parents}")

        print(f"{len(order)} Jobs; secuencia de instalación; únicamente aristas de éxito.")

        return

    require(bool(args.url), "--url es obligatorio para acceder a AWX")

    token = os.environ.get("AWX_TOKEN") or getpass.getpass("Token AWX (no se mostrará): ")

    api = AwxApi(args.url, token)

    org, project, inventory, credentials = awx_context(api, manifest)

    if args.inspect:

        print("INSPECCIÓN FINALIZADA · No se ha modificado ni lanzado nada.")

        return

    import_workflow(api, manifest, order, org, project, inventory, credentials)





if __name__ == "__main__":

    try:

        main()

    except (ProvisionError, ValueError, json.JSONDecodeError) as exc:

        print(f"ERROR: {exc}", file=sys.stderr)

        raise SystemExit(2)


