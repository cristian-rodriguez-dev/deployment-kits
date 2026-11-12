"""Pruebas estáticas, sin Docker ni AWX."""
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
MON = ROOT / 'monitorizacion'

class TriageMetricsAWXTests(unittest.TestCase):
    def test_new_playbook_parses_and_audit_is_default(self):
        data = yaml.safe_load((MON/'playbooks/integrar_security_triage_metrics.yml').read_text())[0]
        self.assertEqual(data['hosts'], 'prometheus-servers')
        self.assertTrue(data['become'])
        self.assertEqual(data['vars']['var_triage_integration_mode'], 'audit')
        self.assertIn("var_triage_integration_mode == 'apply'", str(data['tasks']))

    def test_existing_job_never_overwritten(self):
        s = (MON/'playbooks/integrar_security_triage_metrics.yml').read_text()
        self.assertNotIn('docker compose up', s)
        self.assertNotIn('docker kill', s)
        self.assertIn('No se sobrescribe prometheus.yml', s)
        self.assertIn('force: false', s)

    def test_scrape_template_opt_in(self):
        s = (MON/'templates/prometheus/prometheus.yml.j2').read_text()
        self.assertIn('var_prometheus_triage_enabled | default(false) | bool', s)
        self.assertIn('job_name: "security-triage-bot"', s)
        self.assertIn('credentials_file: /etc/prometheus/triage_metrics_token', s)

    def test_network_template_opt_in(self):
        s = (MON/'templates/prometheus/docker-compose.yml.j2').read_text()
        self.assertIn('var_prometheus_triage_enabled | default(false) | bool', s)
        self.assertIn('triage_metrics: {}', s)
        self.assertIn("default('triage-metrics-private')", s)

    def test_existing_installer_validates_token_mount(self):
        s = (MON/'playbooks/instalar_prometheus.yml').read_text()
        self.assertIn('--volume {{ var_prometheus_install_dir }}/prometheus:/etc/prometheus:ro', s)
        self.assertIn('Rechazar integración sin token preexistente', s)
        self.assertIn('Impedir borrar accidentalmente el job Security Triage existente', s)

if __name__ == '__main__': unittest.main()
