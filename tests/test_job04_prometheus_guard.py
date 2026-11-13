import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / "monitorizacion" / "playbooks" / "instalar_prometheus.yml"


class Job04PrometheusSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = PLAYBOOK.read_text(encoding="utf-8")
        cls.document = yaml.safe_load(cls.source)
        cls.play = cls.document[0]
        cls.pre = cls.play["pre_tasks"]
        cls.names = [t.get("name", "") for t in cls.pre]

    def by_name(self, name):
        return self.pre[self.names.index(name)]

    def test_playbook_parses(self):
        self.assertEqual(len(self.document), 1)
        self.assertEqual(self.play["hosts"], "prometheus-servers")

    def test_first_guard_before_original_preflight(self):
        self.assertEqual(self.names[0], "Validar modo seguro del Job 04 y ruta objetivo")
        self.assertLess(self.names.index("Finalizar la inspeccion antes de cualquier operacion de despliegue"),
                        self.names.index("Comprobar las variables necesarias"))

    def test_default_mode_is_inspect(self):
        self.assertIn("default('inspect')", self.source)
        self.assertNotIn("var_prometheus_job04_mode | default('install')", self.source)

    def test_stat_files_before_end_play(self):
        end = self.names.index("Finalizar la inspeccion antes de cualquier operacion de despliegue")
        early = self.pre[:end]
        for short in ["Detectar directorio de instalacion de Prometheus",
                      "Detectar Compose existente de Prometheus",
                      "Detectar configuracion existente de Prometheus",
                      "Detectar almacenamiento persistente de Prometheus"]:
            task = self.by_name(short)
            self.assertLess(self.names.index(short), end)
            self.assertIn("ansible.builtin.stat", task)

    def test_end_play_is_conditional(self):
        task = self.by_name("Finalizar la inspeccion antes de cualquier operacion de despliegue")
        self.assertEqual(task["ansible.builtin.meta"], "end_play")
        self.assertIn("'inspect'", task["when"])

    def test_no_writes_before_end_play(self):
        end = self.names.index("Finalizar la inspeccion antes de cualquier operacion de despliegue")
        for t in self.pre[:end+1]:
            action = [key for key in t if key.startswith("ansible.builtin.")]
            self.assertEqual(len(action), 1)
            self.assertIn(action[0], {"ansible.builtin.assert", "ansible.builtin.stat", "ansible.builtin.debug", "ansible.builtin.meta"})

    def test_install_block_precedes_old_preflight(self):
        self.assertLess(self.names.index("Bloquear instalacion sobre cualquier directorio existente"),
                        self.names.index("Comprobar las variables necesarias"))
        self.assertLess(self.names.index("Exigir confirmacion explicita para instalacion limpia"),
                        self.names.index("Comprobar las variables necesarias"))

    def test_install_requires_confirmation(self):
        task = self.by_name("Exigir confirmacion explicita para instalacion limpia")
        self.assertIn("INSTALL_NEW_PROMETHEUS", str(task))
        self.assertIn("'install'", str(task["when"]))

    def test_install_blocks_existing_directory(self):
        task = self.by_name("Bloquear instalacion sobre cualquier directorio existente")
        self.assertIn("not var_prometheus_existing_dir.stat.exists", task["ansible.builtin.assert"]["that"])
        self.assertIn("not var_prometheus_existing_config.stat.exists", task["ansible.builtin.assert"]["that"])
        self.assertIn("not var_prometheus_existing_data.stat.exists", task["ansible.builtin.assert"]["that"])

    def test_compose_project_detection_read_only(self):
        check = self.by_name("Validar que el proyecto Docker Compose no esta desplegado")
        self.assertFalse(check["changed_when"])
        self.assertEqual(check["ansible.builtin.command"]["argv"][:3], ["docker", "ps", "-aq"])
        self.assertIn("'install'", check["when"])

    def test_compose_project_exists_blocks(self):
        task = self.by_name("Bloquear proyecto Compose existente antes de desplegar")
        self.assertIn("var_prometheus_existing_project_containers.stdout", str(task))
        self.assertIn("'install'", task["when"])

    def test_real_install_tasks_unchanged_in_structure(self):
        names = [t.get("name") for t in self.play["tasks"]]
        self.assertIn("Generar y validar la configuración de Prometheus", names)
        self.assertIn("Generar y validar Docker Compose", names)
        self.assertIn("Arrancar los servicios conservando los datos", names)

if __name__ == "__main__":
    unittest.main()
