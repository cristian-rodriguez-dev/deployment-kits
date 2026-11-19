"""Block 9: two authenticated interfaces, strict data, no token regression."""
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GroupEvolutionDashboardTests(unittest.TestCase):
    def test_both_dashboards_render_evolution_without_unsafe_dom(self):
        for html in ('app/dashboard.html', 'access/dashboard.html'):
            with self.subTest(html=html):
                source = (ROOT / html).read_text(encoding='utf-8')
                for marker in ('id="risingGroups"', 'id="introducedGroups"',
                               'id="evolutionFilter"', 'Evolución del grupo',
                               'group_evolution', 'first_rule_level',
                               'latest_rule_level', 'peak_increased_after_first',
                               'review_indicators', 'renderEvolution(i,area)',
                               'no modifica', 'last_50_incidents_received_by_bot'):
                    self.assertIn(marker,source)
                self.assertNotIn('innerHTML', source)
                self.assertNotIn('localStorage', source)
                self.assertNotIn('sessionStorage',source)
                self.assertNotIn('eval(',source)

    def test_authentication_models_are_preserved(self):
        bridge=(ROOT/'access/dashboard.html').read_text(encoding='utf-8')
        self.assertIn("fetch('/api/incidents'",bridge)
        self.assertIn("credentials:'same-origin'",bridge)
        self.assertNotIn("fetch('/incidents'",bridge)
        self.assertNotIn('WEBHOOK_TOKEN',bridge)
        internal=(ROOT/'app/dashboard.html').read_text(encoding='utf-8')
        self.assertIn("fetch('/incidents'",internal)
        self.assertIn("'Authorization':'Bearer '+token",internal)
        self.assertNotIn("fetch('/api/incidents'",internal)

    @unittest.skipUnless(shutil.which('node'), 'Node not installed')
    def test_both_ui_harnesses(self):
        for filename in ('dashboard_bridge_correlations_harness.js',
                         'dashboard_correlations_harness.js'):
            with self.subTest(filename=filename):
                process=subprocess.run(['node',str(ROOT/'tests'/filename)],
                                       cwd=ROOT,capture_output=True,text=True,
                                       encoding='utf-8',timeout=12)
                self.assertEqual(process.returncode,0,process.stderr)
                self.assertIn('OK:',process.stdout)


if __name__ == '__main__':
    unittest.main()
