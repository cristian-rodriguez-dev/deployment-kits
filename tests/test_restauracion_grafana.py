"""Ensayos de reconstrucción offline. No necesita Grafana ni AWX."""
from __future__ import annotations
import hashlib
import importlib.util
import io
import json
import os
import sqlite3
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parents[1]
FILES = HERE / 'monitorizacion/files'
sys.path.insert(0, str(FILES))
spec = importlib.util.spec_from_file_location('restauracion', FILES / 'ensayar_restauracion_grafana.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.guard = self.base / 'lab-allow'
        self.guard.write_text(r.GUARD_CONTENT + '\n')
        self.guard.chmod(0o600)
        self.work = self.base / 'restore-root'
        self.archive = self.base / 'grafana-full-test.tar.gz'
        self.sha = self.create_archive(15)

    def make_db(self, dashboards):
        db = self.base / 'grafana.db'
        if db.exists():
            db.unlink()
        with sqlite3.connect(db) as con:
            con.execute('CREATE TABLE dashboard (id INTEGER PRIMARY KEY, is_folder INTEGER, deleted INTEGER)')
            con.execute('CREATE TABLE data_source (id INTEGER PRIMARY KEY)')
            con.execute('CREATE TABLE alert_rule (id INTEGER PRIMARY KEY)')
            con.executemany('INSERT INTO dashboard VALUES (?, 0, 0)', [(i,) for i in range(1, dashboards + 1)])
            con.executemany('INSERT INTO data_source VALUES (?)', [(i,) for i in range(1, 6)])
        return db.read_bytes()

    def create_archive(self, dashboards, malicious=None):
        data = {
            'grafana/data/grafana.db': self.make_db(dashboards),
            'grafana/secrets/admin_password': b'test-only-secret',
            'grafana/docker-compose.yml': b'services: {}\n',
            'grafana/provisioning/datasources/prometheus.yml': b'apiVersion: 1\n',
        }
        manifest = {'schema': 1, 'files': []}
        for name, blob in sorted(data.items()):
            manifest['files'].append({'path': name, 'size': len(blob),
                                      'sha256': hashlib.sha256(blob).hexdigest(),
                                      'mode': '0600', 'uid': 0, 'gid': 0})
        with tarfile.open(self.archive, mode='w:gz') as tar:
            for name, blob in data.items():
                member = tarfile.TarInfo(name)
                member.size = len(blob)
                member.mode = 0o600
                tar.addfile(member, io.BytesIO(blob))
            payload = json.dumps(manifest).encode()
            member = tarfile.TarInfo('META/manifest.json')
            member.size = len(payload)
            tar.addfile(member, io.BytesIO(payload))
            if malicious is not None:
                link = tarfile.TarInfo(malicious)
                link.type = tarfile.SYMTYPE
                link.linkname = '/etc/passwd'
                tar.addfile(link)
        return r.bytes_sha256(self.archive)

    def test_success_and_idempotency(self):
        result = r.restore(self.archive, self.sha, self.work, self.guard, 15, 512 * 1024 * 1024)
        self.assertEqual(result['status'], 'RESTAURADO_OFFLINE')
        self.assertEqual(result['dashboards'], 15)
        self.assertEqual(result['datasources'], 5)
        self.assertTrue(result['changed'])
        other = r.restore(self.archive, self.sha, self.work, self.guard, 15, 512 * 1024 * 1024)
        self.assertFalse(other['changed'])
        self.assertEqual(other['status'], 'YA_VALIDADO')

    def test_wrong_digest_never_extracts(self):
        with self.assertRaises(Exception):
            r.restore(self.archive, '0' * 64, self.work, self.guard, 15, 512 * 1024 * 1024)
        self.assertFalse(self.work.exists())

    def test_wrong_dashboard_count_rejects_and_cleans_stage(self):
        with self.assertRaisesRegex(r.RestoreError, 'dashboards'):
            r.restore(self.archive, self.sha, self.work, self.guard, 14, 512 * 1024 * 1024)
        self.assertFalse(list(self.work.glob('ensayo-*')))
        self.assertFalse(list(self.work.glob('.restoring-*')))

    def test_marker_must_match(self):
        self.guard.write_text('NOT_A_LAB\n')
        with self.assertRaisesRegex(r.RestoreError, 'marca'):
            r.restore(self.archive, self.sha, self.work, self.guard, 15, 512 * 1024 * 1024)

    def test_never_follow_symlink_archive(self):
        link = self.base / 'fake.tar.gz'
        link.symlink_to(self.archive)
        with self.assertRaisesRegex(r.RestoreError, 'simbólico'):
            r.restore(link, self.sha, self.work, self.guard, 15, 512 * 1024 * 1024)

    def test_rejects_tar_symlink_entry(self):
        sha = self.create_archive(15, malicious='grafana/data/hijack')
        with self.assertRaises(Exception):
            r.restore(self.archive, sha, self.work, self.guard, 15, 512 * 1024 * 1024)

    def test_blocks_modified_restored_file(self):
        result = r.restore(self.archive, self.sha, self.work, self.guard, 15, 512 * 1024 * 1024)
        dest = Path(result['location']) / 'grafana/docker-compose.yml'
        dest.write_text('tampered')
        with self.assertRaisesRegex(r.RestoreError, 'restauración'):
            r.restore(self.archive, self.sha, self.work, self.guard, 15, 512 * 1024 * 1024)

    def test_rejects_archive_under_work_root(self):
        self.work.mkdir(mode=0o700)
        nested = self.work / 'grafana-full-nested.tar.gz'
        nested.write_bytes(self.archive.read_bytes())
        nested.chmod(0o600)
        with self.assertRaisesRegex(r.RestoreError, 'independientes'):
            r.restore(nested, self.sha, self.work, self.guard, 15, 512 * 1024 * 1024)


if __name__ == '__main__':
    unittest.main()
