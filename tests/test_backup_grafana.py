"""Pruebas autocontenidas; no requieren Docker real ni Grafana."""
import importlib.util
import json
import os
import sqlite3
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


b = load("grafana_full_backup", "monitorizacion/files/grafana_full_backup.py")
v = load("verificar_backup_grafana", "tools/verificar_backup_grafana.py")


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.install = Path(self.tmp.name) / "grafana"
        self.backups = self.install / "backups/full"
        for rel in ("data", "data/plugins/plug1", "provisioning/datasources", "secrets"):
            (self.install / rel).mkdir(parents=True)
        self.db = self.install / "data/grafana.db"
        con = sqlite3.connect(self.db)
        con.execute("CREATE TABLE dashboards (uid TEXT PRIMARY KEY, title TEXT)")
        con.execute("INSERT INTO dashboards VALUES ('a123', 'Fleet')")
        con.commit()
        con.close()
        (self.install / "data/plugins/plug1/plugin.json").write_text('{"id":"plug1"}')
        (self.install / "provisioning/datasources/prometheus.yml").write_text('apiVersion: 1\n')
        (self.install / "secrets/admin_password").write_text('demo-for-unit-tests-only')
        (self.install / "docker-compose.yml").write_text('services:\n  grafana:\n    image: grafana/grafana:13.2.3\n')
        (self.install / ".awx-initialized").write_text('not-a-real-fingerprint')

    def run_backup(self):
        with mock.patch.object(b, "inspect_running_container", return_value="grafana/grafana:13.2.3"):
            return b.run(self.install, self.backups, "grafana", 1)

    def test_backup_and_offline_validation(self):
        r = self.run_backup()
        verified = v.verify(Path(r["archive"]), r["sha256"])
        self.assertTrue(verified["verified"])
        self.assertGreaterEqual(verified["files"], 5)
        self.assertEqual(os.stat(r["archive"]).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.backups).st_mode & 0o777, 0o700)

    def test_backup_contains_all_three_mounts_and_database(self):
        r = self.run_backup()
        with tarfile.open(r["archive"], "r:gz") as tar:
            names = set(tar.getnames())
            self.assertTrue({"grafana/data/grafana.db", "grafana/docker-compose.yml",
                             "grafana/secrets/admin_password", "grafana/provisioning/datasources/prometheus.yml",
                             "grafana/data/plugins/plug1/plugin.json"}.issubset(names))
            self.assertFalse(any(n.endswith("grafana.db-wal") for n in names))

    def test_copia_consistente_sqlite_online(self):
        source = sqlite3.connect(self.db)
        source.execute("PRAGMA journal_mode=WAL")
        source.execute("INSERT INTO dashboards VALUES ('b234', 'Security')")
        source.commit()
        r = self.run_backup()
        with tarfile.open(r["archive"], "r:gz") as archive:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "grafana.db"
                path.write_bytes(archive.extractfile("grafana/data/grafana.db").read())
                with sqlite3.connect(path) as con:
                    self.assertEqual(con.execute("SELECT COUNT(*) FROM dashboards").fetchone()[0], 2)
        source.close()

    def test_rechaza_symlinks(self):
        (self.install / "data/malicious").symlink_to(self.install / "secrets/admin_password")
        with self.assertRaises(b.BackupError):
            self.run_backup()
        self.assertEqual(list(self.backups.glob("*.tar.gz")), [])

    def test_no_permite_backup_dentro_data(self):
        with self.assertRaises(b.BackupError):
            b.validate_paths(self.install, self.install / "data/backups")

    def test_suma_incorrecta_falla(self):
        r = self.run_backup()
        with self.assertRaises(v.VerifyError):
            v.verify(Path(r["archive"]), "0" * 64)

    def test_no_sobrescribe_backups_previos(self):
        a, second = self.run_backup(), self.run_backup()
        self.assertNotEqual(a["archive"], second["archive"])
        self.assertEqual(len(list(self.backups.glob("*.tar.gz"))), 2)

    def test_rechaza_montajes_ajenos(self):
        expected = [{"Destination": dest, "Source": str(self.install / rel), "Type": "bind"}
                    for dest, rel in b.EXPECTED_MOUNTS.items()]
        payload = json.dumps([{"State": {"Running": True}, "Mounts": expected +
                              [{"Destination": "/etc/grafana/custom.ini", "Source": "/etc/custom.ini", "Type": "bind"}],
                              "Config": {"Image": "grafana/grafana:13.2.3"}}])
        with mock.patch.object(b.subprocess, "run", side_effect=[
            mock.Mock(stdout="abc123\n"), mock.Mock(stdout=payload)
        ]):
            with self.assertRaisesRegex(b.BackupError, "montajes adicionales"):
                b.inspect_running_container(self.install, "grafana")


if __name__ == "__main__":
    unittest.main()
