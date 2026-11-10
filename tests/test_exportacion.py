"""Pruebas del empaquetador sin Grafana ni AWX: python -m unittest discover -s tests -v."""
from pathlib import Path
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / 'monitorizacion' / 'files' / 'grafana_export_bundle.py'
VERIFY = ROOT / 'tools' / 'verificar_exportacion_grafana.py'

spec = importlib.util.spec_from_file_location('bundle_grafana', BUNDLE)
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


def fake_snapshot(tmp, count=15):
    stage = tmp / 'stage'
    records = []
    for n in range(count):
        uid = f'dash{n:02d}'
        fmt = 'v2' if n % 3 == 0 else 'v1' if n % 3 == 1 else 'legacy'
        title = f'Dashboard {n}'
        rel = f'dashboards/{fmt}/{uid}.json'
        path = stage / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        content = ({'dashboard': {'uid': uid, 'title': title}, 'meta': {'folderUid': 'abc'}}
                   if fmt == 'legacy' else
                   {'apiVersion': f'dashboard.grafana.app/{fmt}', 'kind': 'Dashboard',
                    'metadata': {'name': uid}, 'spec': {'title': title, 'elements': {}}})
        path.write_text(json.dumps(content), encoding='utf-8')
        records.append({'uid': uid, 'title': title, 'format': fmt, 'path': rel})
    (stage / 'manifest.json').write_text(json.dumps({'expected_count': count, 'dashboards': records}), encoding='utf-8')
    return stage


class ExportTests(unittest.TestCase):
    def test_crear_y_verificar_quince_dashboards(self):
        with tempfile.TemporaryDirectory() as temp:
            tmp = Path(temp)
            stage = fake_snapshot(tmp)
            output = tmp / 'grafana.zip'
            bundle.build(stage, output)
            self.assertTrue(output.is_file())
            with zipfile.ZipFile(output) as z:
                self.assertEqual(len(z.namelist()), 16)
                self.assertIsNone(z.testzip())
            p = subprocess.run([sys.executable, str(VERIFY), str(output)], text=True, capture_output=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn('15 dashboards', p.stdout)

    def test_no_sobrescribe_backup_existente(self):
        with tempfile.TemporaryDirectory() as temp:
            tmp = Path(temp)
            stage = fake_snapshot(tmp, 2)
            output = tmp / 'grafana.zip'
            bundle.build(stage, output)
            with self.assertRaises(FileExistsError):
                bundle.build(stage, output)

    def test_rechaza_manifiesto_incompleto(self):
        with tempfile.TemporaryDirectory() as temp:
            tmp = Path(temp)
            stage = fake_snapshot(tmp, 3)
            (stage / 'dashboards/v2/dash00.json').unlink()
            with self.assertRaises(ValueError):
                bundle.build(stage, tmp / 'grafana.zip')

    def test_rechaza_uid_duplicado(self):
        with tempfile.TemporaryDirectory() as temp:
            tmp = Path(temp)
            stage = fake_snapshot(tmp, 2)
            manifest_path = stage / 'manifest.json'
            data = json.loads(manifest_path.read_text())
            data['dashboards'][1]['uid'] = data['dashboards'][0]['uid']
            manifest_path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                bundle.build(stage, tmp / 'grafana.zip')

    def test_verificador_detecta_corrupcion(self):
        with tempfile.TemporaryDirectory() as temp:
            tmp = Path(temp)
            stage = fake_snapshot(tmp, 1)
            output = tmp / 'grafana.zip'
            bundle.build(stage, output)
            altered = tmp / 'grafana-alterado.zip'
            with zipfile.ZipFile(output) as zsrc, zipfile.ZipFile(altered, 'w') as zdest:
                for name in zsrc.namelist():
                    content = zsrc.read(name)
                    if name.endswith('/dash00.json'):
                        content = content.replace(b'Dashboard 0', b'Dashboard X')
                    zdest.writestr(name, content)
            p = subprocess.run([sys.executable, str(VERIFY), str(altered)], text=True, capture_output=True)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn('SHA256', p.stderr)

    def test_sintaxis_y_seguridad_yaml(self):
        import yaml
        play = yaml.safe_load((ROOT / 'monitorizacion/playbooks/exportar_dashboards_grafana.yml').read_text())
        task = yaml.safe_load((ROOT / 'monitorizacion/tasks/grafana/exportar_dashboard.yml').read_text())
        self.assertEqual(play[0]['hosts'], 'grafana-servers')
        nested = [child for top in task for child in top.get('block', [top])]
        calls = [t for t in nested if 'ansible.builtin.uri' in t]
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(t['ansible.builtin.uri']['method'] == 'GET' for t in calls))
        self.assertTrue(all(t.get('no_log') is True for t in calls))

if __name__ == '__main__':
    unittest.main()
