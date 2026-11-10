"""Pruebas unitarias portables del verificador offline (no requiere AWX)."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / 'tools' / 'verificar_cobertura_dashboards.py'
spec = importlib.util.spec_from_file_location('verificar_cobertura_dashboards', TOOL)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class TestVerification(unittest.TestCase):
    def test_identificadores_esperados(self):
        self.assertEqual(len(mod.EXPECTED_TITLES), 15)
        self.assertEqual(len(mod.NEW_SHA256), 8)
        self.assertTrue(set(mod.NEW_SHA256).issubset(set(mod.EXPECTED_TITLES)))

    def test_ruta_vacia_rechazada(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                mod.inspect_repo(Path(d))

    def test_cantidad_incompleta_rechazada(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/'monitorizacion'/'dashboards').mkdir(parents=True)
            with self.assertRaisesRegex(ValueError,'15 JSON'):
                mod.inspect_repo(Path(d))

    def test_zip_incorrecto_rechazado(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'alterado.zip'
            p.write_bytes(b'123')
            with self.assertRaisesRegex(ValueError,'SHA256'):
                mod.verify_against_export({},p)

if __name__ == '__main__':
    unittest.main()
