"""Pruebas offline del Job 01: contrato de instalacion limpia Docker.

No necesita AWX, privilegios, red ni Docker. Ejecutar con PyYAML y Jinja2.
"""
import base64
import json
import unittest
from pathlib import Path

import jinja2
import yaml

ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = ROOT / "monitorizacion/playbooks/instalar_docker.yml"


def env():
    j = jinja2.Environment()
    j.tests["boolean"] = lambda value: isinstance(value, bool)
    j.filters["intersect"] = lambda a, b: list(set(a).intersection(b))
    j.filters["b64decode"] = lambda val: base64.b64decode(val).decode("utf-8")
    j.filters["from_json"] = json.loads
    return j


class DockerCleanInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.play = yaml.safe_load(PLAYBOOK.read_text(encoding="utf-8"))[0]
        cls.text = PLAYBOOK.read_text(encoding="utf-8")
        cls.vars = cls.play["vars"]
        cls.pre = cls.play["pre_tasks"]
        cls.tasks = cls.play["tasks"]
        cls.jinja = env()

    def task(self, title, group=None):
        for task in (group if group is not None else self.pre + self.tasks):
            if task.get("name") == title:
                return task
        self.fail(f"No existe la tarea: {title}")

    def evaluate(self, expr, **kwargs):
        return self.jinja.compile_expression(expr)(**kwargs)

    def test_01_preserves_original_file_and_group(self):
        self.assertEqual(self.play["hosts"], "docker_servers")
        self.assertTrue(self.play["become"])
        self.assertTrue(self.play["gather_facts"])
        self.assertEqual(PLAYBOOK.name, "instalar_docker.yml")

    def test_02_guard_first_before_writes(self):
        self.assertEqual(self.pre[0]["name"], "Validar contrato de instalacion nueva antes de cualquier escritura")
        self.assertEqual(len(self.play.get("handlers", [])), 0)
        self.assertFalse(any("ansible.builtin.copy" in p or "ansible.builtin.apt" in p for p in self.pre))

    def test_03_required_confirmation_off_by_default(self):
        self.assertEqual(self.vars["var_docker_install_mode"], "blocked")
        self.assertEqual(self.vars["var_docker_install_confirm"], "")
        self.assertEqual(self.vars["var_docker_versiones_ubuntu"], ["24.04"])
        self.assertFalse(self.vars["var_docker_agregar_usuario_grupo"])

    def test_04_accepts_only_expected_clean_vm_and_confirmation(self):
        checks = self.pre[0]["ansible.builtin.assert"]["that"]
        defaults = dict(ansible_distribution="Ubuntu", ansible_distribution_version="24.04",
                        ansible_architecture="x86_64",var_docker_versiones_ubuntu=["24.04"],
                        var_docker_install_mode="install",var_docker_install_confirm="INSTALL_NEW_DOCKER_2404",
                        var_docker_agregar_usuario_grupo=False,
                        var_docker_default_address_pools=[{"base":"172.20.0.0/16","size":24}])
        self.assertTrue(all(self.evaluate(c, **defaults) for c in checks))
        for key, value in (
            ("ansible_distribution_version", "26.04"),
            ("ansible_distribution", "Debian"),
            ("var_docker_install_mode", "blocked"),
            ("var_docker_install_confirm", ""),
            ("ansible_architecture", "unsupported"),
            ("var_docker_agregar_usuario_grupo", "false"),
            ("var_docker_default_address_pools", []),
        ):
            with self.subTest(key=key, value=value):
                ctx = {**defaults, key: value}
                self.assertFalse(all(self.evaluate(c, **ctx) for c in checks))

    def test_05_nonmanaged_host_artifacts_fail(self):
        checks = self.task("Rechazar instalacion o datos previos en host no gestionado")["ansible.builtin.assert"]["that"]
        ctx = dict(var_docker_existing_paths={"results":[{"stat":{"exists":False}}]},ansible_facts={"packages":{}})
        self.assertTrue(all(self.evaluate(c, **ctx) for c in checks))
        ctx["var_docker_existing_paths"] = {"results":[{"stat":{"exists":True}}]}
        self.assertFalse(all(self.evaluate(c, **ctx) for c in checks))
        ctx["var_docker_existing_paths"] = {"results":[{"stat":{"exists":False}}]}
        for package in ("docker.io", "docker-ce", "containerd", "runc", "podman-docker"):
            with self.subTest(package=package):
                ctx["ansible_facts"] = {"packages":{package:[{"version":"1"}]}}
                self.assertFalse(all(self.evaluate(c, **ctx) for c in checks))

    def test_06_marker_expected_bytes_only(self):
        conditions = self.task("Rechazar marcas inesperadas o enlaces simbolicos")["ansible.builtin.assert"]["that"]
        ctx = dict(var_docker_marker_stat={"stat":{"isreg":True}},
                   var_docker_marker_bytes={"content":base64.b64encode(b"deployment-kits-docker-clean-v1\n").decode()})
        self.assertTrue(all(self.evaluate(c, **ctx) for c in conditions))
        ctx["var_docker_marker_bytes"]={"content":base64.b64encode(b"foreign\n").decode()}
        self.assertFalse(all(self.evaluate(c, **ctx) for c in conditions))
        ctx["var_docker_marker_stat"]={"stat":{"isreg":False}}
        self.assertFalse(all(self.evaluate(c, **ctx) for c in conditions))

    def test_07_managed_daemon_drift_fails_closed(self):
        conditions = self.task("Rechazar cambios ajenos sobre el daemon gestionado")["ansible.builtin.assert"]["that"]
        expected=[{"base":"172.20.0.0/16", "size":24}]
        ctx = dict(var_docker_daemon_stat={"stat":{"isreg":True}}, var_docker_default_address_pools=expected,
                   var_docker_daemon_bytes={"content":base64.b64encode(json.dumps({"default-address-pools":expected}).encode()).decode()})
        self.assertTrue(all(self.evaluate(c, **ctx) for c in conditions))
        ctx["var_docker_daemon_bytes"]={"content":base64.b64encode(json.dumps({"debug": True}).encode()).decode()}
        self.assertFalse(all(self.evaluate(c, **ctx) for c in conditions))

    def test_08_original_apt_repo_kept(self):
        t=self.task("Configurar el repositorio oficial de Docker")
        self.assertIn("ansible.builtin.apt_repository",t)
        self.assertIn("{{ ansible_distribution_release }} stable",t["ansible.builtin.apt_repository"]["repo"])
        t2=self.task("Instalar Docker y sus componentes")
        self.assertEqual(t2["ansible.builtin.apt"]["state"], "present")
        self.assertNotIn("latest",self.text)

    def test_09_daemon_written_once_before_apt_install(self):
        names=[t["name"] for t in self.tasks]
        self.assertLess(names.index("Configurar pools de red ANTES de instalar Docker"),names.index("Instalar Docker y sus componentes"))
        conf=self.task("Configurar pools de red ANTES de instalar Docker")
        self.assertIn("not var_docker_marker_stat.stat.exists",str(conf["when"]))
        self.assertEqual(conf["ansible.builtin.copy"]["dest"],"/etc/docker/daemon.json")
        self.assertNotIn("notify",conf)
        self.assertLess(names.index("Registrar inicio de instalacion propia para reintentos idempotentes"),names.index("Actualizar la caché de paquetes APT"))

    def test_10_no_implicit_root_equivalent_group(self):
        for name in ("Crear el grupo docker si se ha autorizado acceso no root", "Añadir usuario a docker solo por autorizacion explicita"):
            self.assertEqual(self.task(name)["when"],"var_docker_agregar_usuario_grupo")

    def test_11_no_service_restarts_or_destructive_commands(self):
        self.assertNotIn("state: restarted",self.text)
        for forbidden in ("docker system prune", "docker compose down", "--force-reinstall", "apt-get upgrade", "state: latest"):
            self.assertNotIn(forbidden, self.text)
        service=self.task("Habilitar e iniciar Docker sin reiniciar un servicio activo")
        self.assertEqual(service["ansible.builtin.systemd_service"]["state"],"started")

    def test_12_retry_denies_preexisting_data_without_daemon(self):
        conditions = self.task("Rechazar reintentos sin daemon.json si ya existen datos o binarios")["ansible.builtin.assert"]["that"]
        ctx = dict(var_docker_daemon_stat={"stat":{"exists":False, "isreg":False}},
                   var_docker_retry_paths={"results":[{"stat":{"exists":False}}]})
        self.assertTrue(all(self.evaluate(c, **ctx) for c in conditions))
        ctx["var_docker_retry_paths"]={"results":[{"stat":{"exists":True}}]}
        self.assertFalse(all(self.evaluate(c, **ctx) for c in conditions))
        ctx["var_docker_daemon_stat"]={"stat":{"exists":True, "isreg":True}}
        self.assertTrue(all(self.evaluate(c, **ctx) for c in conditions))
        ctx["var_docker_daemon_stat"]={"stat":{"exists":True, "isreg":False}}
        self.assertFalse(all(self.evaluate(c, **ctx) for c in conditions))

    def test_13_marker_must_precede_all_external_apt_changes(self):
        names=[t["name"] for t in self.tasks]
        self.assertLess(names.index("Registrar inicio de instalacion propia para reintentos idempotentes"),
                        names.index("Actualizar la caché de paquetes APT"))
        self.assertLess(names.index("Registrar inicio de instalacion propia para reintentos idempotentes"),
                        names.index("Configurar el repositorio oficial de Docker"))

    def test_12_health_and_version_checks(self):
        for name in ("Validar la configuracion del daemon", "Comprobar respuesta del daemon de Docker", "Comprobar la versión de Docker", "Comprobar la versión de Docker Compose"):
            self.assertFalse(self.task(name).get("changed_when"))
        self.assertTrue(self.task("Comprobar respuesta del daemon de Docker").get("no_log"))

    def test_13_no_hard_coded_sensitive_data(self):
        for sensitive in ("password:", "private_key", "ansible_ssh_pass", "VAULT_PASSWORD"):
            self.assertNotIn(sensitive,self.text)

    def test_14_yaml_playbook_single_entrypoint(self):
        self.assertEqual(len(yaml.safe_load(PLAYBOOK.read_text(encoding="utf-8"))),1)
        self.assertEqual(len({x["name"] for x in self.tasks + self.pre}),len(self.tasks + self.pre))

    def test_15_docs_and_examples_exist(self):
        self.assertTrue((ROOT/"monitorizacion/docs/DOCKER_INSTALACION_LIMPIA_2404.md").exists())
        example=yaml.safe_load((ROOT/"monitorizacion/examples/variables_docker_clean_2404.yml").read_text())
        self.assertEqual(example["var_docker_install_mode"],"install")
        self.assertEqual(example["var_docker_install_confirm"],"INSTALL_NEW_DOCKER_2404")


if __name__ == "__main__":
    unittest.main()
