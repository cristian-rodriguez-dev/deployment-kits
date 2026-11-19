"""Block 6: read-only correlation view, original API contract stays unchanged."""
from pathlib import Path
import shutil
import subprocess
import unittest

BASE = Path(__file__).resolve().parents[1]
HTML = BASE / 'app' / 'dashboard.html'


class DashboardCorrelationsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = HTML.read_text(encoding='utf-8')

    def test_existing_protected_endpoint_preserved(self):
        self.assertIn("fetch('/incidents'", self.html)
        self.assertIn("'Authorization':'Bearer '+token", self.html)
        self.assertIn("'Cache-Control'", (BASE / 'app' / 'main.py').read_text(encoding='utf-8'))

    def test_no_storage_or_raw_html_sink(self):
        self.assertNotIn('localStorage', self.html)
        self.assertNotIn('sessionStorage', self.html)
        self.assertNotIn('.innerHTML', self.html)
        self.assertNotIn('eval(', self.html)
        self.assertIn('el.textContent=String(txt)', self.html)

    def test_correlation_status_and_historical_labels(self):
        for s in ('Sin análisis', 'Datos insuficientes', 'No disponible',
                  'Sin señales', 'Con señales', 'No verificable'):
            with self.subTest(status=s):
                self.assertIn(s, self.html)

    def test_no_backend_changes_for_dashboard_only(self):
        main = (BASE / 'app' / 'main.py').read_text(encoding='utf-8')
        self.assertIn("@app.get('/dashboard'", main)
        self.assertIn("@app.get('/incidents'", main)
        self.assertIn("@app.get('/internal/metrics'", main)
        self.assertIn('cross_source_correlate(', main)

    def test_frontend_avoids_causality_or_automatic_response(self):
        for s in ('no prueban causalidad', 'no demuestra que el host esté apagado',
                  'No descarta actividad maliciosa', 'no modifican Smart Triage'):
            with self.subTest(message=s):
                self.assertIn(s, self.html)

    @unittest.skipUnless(shutil.which('node'), 'Node unavailable: dynamic DOM harness optional')
    def test_frontend_behavior_without_browser_or_network(self):
        result = subprocess.run(
            ['node', str(BASE / 'tests' / 'dashboard_correlations_harness.js')],
            cwd=BASE, capture_output=True, text=True, encoding='utf-8',
            timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('OK: frontend correlations', result.stdout)


if __name__ == '__main__':
    unittest.main()
