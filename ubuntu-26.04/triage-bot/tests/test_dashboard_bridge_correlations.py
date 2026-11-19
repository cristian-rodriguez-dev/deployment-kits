"""Bloque 6: dashboard bridge exposes correlation without changing authentication."""
from pathlib import Path
import shutil
import subprocess
import unittest
ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / 'access' / 'dashboard.html'
BRIDGE = ROOT / 'access' / 'bridge.py'

class BridgeCorrelationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = HTML.read_text(encoding='utf-8')

    def test_keeps_read_only_authenticated_proxy_contract(self):
        doc = self.doc
        self.assertIn("fetch('/api/incidents'", doc)
        self.assertIn("credentials:'same-origin'", doc)
        self.assertIn('Panel autenticado.', doc)
        self.assertNotIn("fetch('/incidents'", doc)
        self.assertNotIn('WEBHOOK_TOKEN', doc)
        self.assertNotIn('id="token"', doc)
        self.assertNotIn('id="connect"', doc)
        self.assertNotIn("'Authorization':'Bearer '+token", doc)
        bridge = BRIDGE.read_text(encoding='utf-8')
        self.assertIn("DASHBOARD_PATH = ROOT / 'dashboard.html'", bridge)
        self.assertIn("if not authorized(", bridge)
        self.assertIn('DASHBOARD_PATH.read_bytes()', bridge)

    def test_correlations_visible_and_safe(self):
        for marker in ('id="correlated"','id="patterned"',
                       'id="correlation"','Correlación multifuente',
                       'Sin análisis','Con señales','Datos insuficientes',
                       'No verificable','renderCorrelation(i,area)',
                       'no prueban causalidad'):
            with self.subTest(marker=marker): self.assertIn(marker,self.doc)
        self.assertNotIn('localStorage',self.doc)
        self.assertNotIn('sessionStorage',self.doc)
        self.assertNotIn('.innerHTML',self.doc)
        self.assertNotIn('eval(',self.doc)

    @unittest.skipUnless(shutil.which('node'), 'Node not present')
    def test_bridge_frontend_with_mocked_browser(self):
        p = subprocess.run(['node',str(ROOT/'tests'/'dashboard_bridge_correlations_harness.js')],
                           cwd=ROOT, capture_output=True, text=True, encoding='utf-8',timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('OK: authenticated bridge',p.stdout)
