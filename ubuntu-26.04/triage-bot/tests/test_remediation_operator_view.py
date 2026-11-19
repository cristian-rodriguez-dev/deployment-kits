"""Pruebas offline de la guía consultiva de Alloy (19I)."""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.remediation_operator_view import guidance_for_incident, VERSION

UTC = timezone.utc
NOW = datetime(2026, 11, 16, 16, 0, tzinfo=UTC)


def incident(**changes):
    row = {'id': 19, 'source': 'grafana', 'synthetic': False,
           'title': 'Alloy host inactivo',
           'received_at': (NOW - timedelta(minutes=2)).isoformat(),
           'analysis': {'triage': {'decision': 'notify'}, 'asset': {'name': 'unverified'}}}
    row.update(changes)
    return row


class OperatorGuidanceTests(unittest.TestCase):
    def call(self, **changes):
        return guidance_for_incident(incident(**changes), now=NOW)

    def test_candidate_is_review_only(self):
        d = self.call()
        self.assertEqual(d['version'], VERSION)
        self.assertEqual(d['status'], 'review_required')
        self.assertEqual(d['reason_code'], 'unverified_recent_alloy_signal')
        self.assertEqual(d['incident_id'], 19)
        self.assertEqual(d['service'], 'alloy.service')

    def test_no_execution_permissions(self):
        d = self.call()
        for key in ('execution_allowed', 'action_executed', 'awx_verified',
                    'signal_verified', 'independent_systemd_observation',
                    'incident_to_service_proven', 'automated_recovery_available'):
            self.assertIs(d[key], False, key)
        self.assertIs(d['requires_human_approval_for_recovery'], True)
        self.assertIs(d['requires_human_review'], True)
        self.assertEqual(d['service_state'], 'unknown')

    def test_awx_templates_fixed(self):
        d = self.call()
        self.assertEqual(d['audit_job_template'], '19H - Alloy Host - AUDIT')
        self.assertEqual(d['recovery_workflow'], '19H - Recuperacion Alloy - MANUAL')
        self.assertTrue(any('aprob' in x for x in d['steps']))

    def test_no_webhook_strings_in_guidance(self):
        d = self.call(title='Alloy down !password=hunter2')
        self.assertNotIn('hunter2', repr(d))
        self.assertNotIn('!password=', repr(d))

    def test_only_real(self):
        self.assertIsNone(self.call(synthetic=True))
        self.assertIsNone(self.call(synthetic=1))
        self.assertIsNone(self.call(synthetic=None))

    def test_only_allowed_sources(self):
        for source in ('loki', 'prometheus', '', None, 'unknown'):
            with self.subTest(source=source):
                self.assertIsNone(self.call(source=source))
        self.assertIsNotNone(self.call(source='wazuh'))

    def test_invalid_id(self):
        for value in (None, True, 0, -1, '19', 2_147_483_648):
            with self.subTest(value=value):
                self.assertIsNone(self.call(id=value))

    def test_unrelated_title_not_eligible(self):
        for title in ('Loki no disponible', 'Intentos SSH fallidos',
                      'Alloy activo', 'Alloy recovered', 'Deployment alloy healthy',
                      'alloyed down', None, {}, 'A' * 301):
            with self.subTest(title=str(title)[:40]):
                self.assertIsNone(self.call(title=title))

    def test_negative_signals(self):
        for title in ('Alloy down', 'alloy.service failed', 'Alloy detenido',
                      'Alloy no disponible', 'Alloy sin datos', 'ALLoy inactive'):
            with self.subTest(title=title):
                self.assertIsNotNone(self.call(title=title))

    def test_unverified_signal_cannot_prove_systemd_status(self):
        for analysis in (
            {'asset': {'name': 'ansible_server'}, 'telemetry': {'state': 'inactive'}},
            {'decision': {'execute': True}, 'ai': {'service_state': 'inactive'}},
            {'ai_decision_shadow': {'recommendation': 'start alloy.service'}},
            {'triage': {'decision': 'notify', 'confidence': 'high'}},
        ):
            d = self.call(analysis=analysis)
            self.assertEqual(d['service_state'], 'unknown')
            self.assertIs(d['execution_allowed'], False)
            self.assertIs(d['awx_verified'], False)

    def test_expired_context(self):
        d = self.call(received_at=(NOW - timedelta(minutes=16)).isoformat())
        self.assertIs(d['recent_incident'], False)
        self.assertEqual(d['reason_code'], 'unverified_or_historical_alloy_signal')

    def test_current_bound_inclusive(self):
        d = self.call(received_at=(NOW - timedelta(minutes=15)).isoformat())
        self.assertIs(d['recent_incident'], True)

    def test_future_context(self):
        d = self.call(received_at=(NOW + timedelta(seconds=1)).isoformat())
        self.assertFalse(d['recent_incident'])

    def test_invalid_timestamps(self):
        for value in ('', '2026-11-16T15:00:00', 'malformed', 10, None,
                      'X' * 100):
            with self.subTest(value=value):
                d = self.call(received_at=value)
                self.assertIs(d['recent_incident'], False)

    def test_invalid_now(self):
        self.assertIsNone(guidance_for_incident(incident(), now=NOW.replace(tzinfo=None)))
        self.assertIsNone(guidance_for_incident(incident(), now='2026-11-16'))

    def test_invalid_row_shape(self):
        for value in ({}, [], 'message', None, 5, True):
            with self.subTest(value=str(value)):
                self.assertIsNone(guidance_for_incident(value, now=NOW))

    def test_output_contains_only_fixed_strings_and_flags(self):
        d = self.call()
        self.assertFalse(any(k in d for k in ('url', 'token', 'command', 'host_ip', 'job_id')))
        self.assertTrue(all(type(v) is str for v in d['steps']))
        self.assertTrue(all(type(v) is str for v in d['evidence']))
        self.assertLess(len(repr(d)), 3100)

    def test_read_only_input(self):
        row = incident()
        before = repr(row)
        guidance_for_incident(row, now=NOW)
        self.assertEqual(repr(row), before)

    def test_main_has_only_read_only_response_enrichment(self):
        code = (Path(__file__).resolve().parents[1] / 'app/main.py').read_text(encoding='utf-8')
        self.assertEqual(code.count('from app.remediation_operator_view import guidance_for_incident'), 1)
        self.assertEqual(code.count('guide = guidance_for_incident(item)'), 1)
        self.assertIn("item['operator_guidance'] = guide", code)
        self.assertIn("@app.get('/incidents')", code)

    def test_both_dashboards_show_guidance(self):
        root = Path(__file__).resolve().parents[1]
        for relative in ('app/dashboard.html', 'access/dashboard.html'):
            with self.subTest(path=relative):
                content = (root / relative).read_text(encoding='utf-8')
                self.assertEqual(content.count("op.version==='alloy-operator-guidance-v1'"), 1)
                self.assertIn("section('Diagnóstico AWX (manual)',op.audit_job_template)", content)
                self.assertIn("section('Recuperación AWX (solo tras aprobación)',op.recovery_workflow)", content)
                self.assertIn("area.append(steps)", content)
                self.assertIn('el.textContent=String(txt)', content)

    def test_no_io_or_network_dependencies(self):
        source = Path(__file__).resolve().parents[1] / 'app/remediation_operator_view.py'
        code = source.read_text(encoding='utf-8')
        for forbidden in ('subprocess', 'requests.', 'urllib', 'sqlite3',
                          'open(', 'os.system', 'socket.', 'systemctl', 'docker '):
            self.assertNotIn(forbidden, code, forbidden)


if __name__ == '__main__':
    unittest.main()
