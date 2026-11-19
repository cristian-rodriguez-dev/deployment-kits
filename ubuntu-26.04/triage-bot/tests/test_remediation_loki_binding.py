"""19E: pruebas offline; no llamadas AWX, Gemini, Docker ni cambios de producción."""
from __future__ import annotations

import ast
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from app.awx_loki_verification import AWXReadOnlyConfig, AWXVerificationError, VerifiedLokiObservation
from app.remediation_loki_binding import (
    ALERT_TITLE, REFERENCE_VERSION, RULE_UID,
    capture_grafana_loki_reference, record_review, review_incident,
)

NOW = datetime(2026, 11, 16, 13, 0, tzinfo=timezone.utc)


def iso(dt):
    return dt.isoformat().replace('+00:00', 'Z')


def alert():
    return {'status': 'firing', 'startsAt': iso(NOW - timedelta(minutes=8)),
            'fingerprint': 'a1234567b1234567'}


def labels():
    return {'alertname': ALERT_TITLE, 'component': 'loki', 'managed_by': 'awx',
            'remediation_rule_uid': RULE_UID}


def verified(job_id=1234, ready=False, observed=None):
    return VerifiedLokiObservation(job_id=job_id, finished_at_utc=iso(NOW - timedelta(seconds=5)),
        observation={'source': 'kubernetes_api', 'namespace': 'logging',
                     'pod': 'loki-0', 'container': 'loki', 'pod_found': True,
                     'container_found': True, 'ready': ready,
                     'observed_at_utc': iso(observed or NOW - timedelta(seconds=30))})


class CaptureTests(unittest.TestCase):
    def test_valid(self):
        r = capture_grafana_loki_reference(alert(), labels())
        self.assertEqual(r['version'], REFERENCE_VERSION)
        self.assertEqual(r['rule_uid'], RULE_UID)
        self.assertEqual(len(r['fingerprint_sha256']), 64)
        self.assertNotIn(alert()['fingerprint'], json.dumps(r))

    def test_grafana_builtin_uid(self):
        l = labels(); del l['remediation_rule_uid']; l['__alert_rule_uid__'] = RULE_UID
        self.assertIsNotNone(capture_grafana_loki_reference(alert(), l))

    def test_redundant_consistent_uid(self):
        l = labels(); l['__alert_rule_uid__'] = RULE_UID
        self.assertIsNotNone(capture_grafana_loki_reference(alert(), l))

    def test_missing_uid(self):
        l = labels(); l.pop('remediation_rule_uid')
        self.assertIsNone(capture_grafana_loki_reference(alert(), l))

    def test_wrong_uid(self):
        l = labels(); l['remediation_rule_uid'] = 'another-rule'
        self.assertIsNone(capture_grafana_loki_reference(alert(), l))

    def test_conflicting_uids(self):
        l = labels(); l['__alert_rule_uid__'] = 'another'
        self.assertIsNone(capture_grafana_loki_reference(alert(), l))

    def test_wrong_component(self):
        l = labels(); l['component'] = 'wazuh'
        self.assertIsNone(capture_grafana_loki_reference(alert(), l))

    def test_wrong_manager(self):
        l = labels(); l['managed_by'] = 'external'
        self.assertIsNone(capture_grafana_loki_reference(alert(), l))

    def test_title_not_sufficient(self):
        l = labels(); l.pop('remediation_rule_uid')
        a = alert(); a['generatorURL'] = 'https://grafana/alerting/' + RULE_UID + '/view'
        self.assertIsNone(capture_grafana_loki_reference(a, l))

    def test_resolved_rejected(self):
        a = alert(); a['status'] = 'resolved'
        self.assertIsNone(capture_grafana_loki_reference(a, labels()))

    def test_invalid_date(self):
        a = alert(); a['startsAt'] = '2026-11-16 13:00:00'
        self.assertIsNone(capture_grafana_loki_reference(a, labels()))

    def test_invalid_fingerprint(self):
        a = alert(); a['fingerprint'] = 'token OR 1=1'
        self.assertIsNone(capture_grafana_loki_reference(a, labels()))

    def test_malformed(self):
        self.assertIsNone(capture_grafana_loki_reference(None, labels()))
        self.assertIsNone(capture_grafana_loki_reference(alert(), []))


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / 'incidents.db'
        with sqlite3.connect(self.db) as c:
            c.execute('''CREATE TABLE incidents (
                id INTEGER PRIMARY KEY, source TEXT, synthetic INTEGER,
                title TEXT, received_at TEXT, analysis TEXT)''')
        self.cfg = AWXReadOnlyConfig('https://awx.internal', Path('/tmp/token'), None,
                                      119, 9, 4)
        self.insert()

    def tearDown(self):
        self.temp.cleanup()

    def insert(self, *, ident=7, source='grafana', synthetic=0, title=ALERT_TITLE,
               received=None, reference=True, decision='notify'):
        analysis = {'triage': {'decision': decision}}
        if reference:
            analysis['grafana_loki_reference'] = capture_grafana_loki_reference(alert(), labels())
        with sqlite3.connect(self.db) as c:
            c.execute('INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?)',
                      (ident, source, synthetic, title, iso(received or NOW - timedelta(minutes=3)),
                       json.dumps(analysis)))

    def run_review(self, *, ident=7, job=1234, answer=None, now=NOW):
        with patch('app.remediation_loki_binding.fetch_verified_observation',
                   return_value=answer or verified(job_id=job)) as fetch:
            out = review_incident(incident_id=ident, job_id=job,
                                  db_path=self.db, config=self.cfg, now=now)
        return out, fetch.call_count

    def test_unready_proposal(self):
        r, called = self.run_review()
        self.assertEqual(called, 1)
        self.assertEqual(r['status'], 'proposed')
        self.assertTrue(r['awx_job_verified'])
        self.assertEqual(r['proposal']['action_id'], 'diagnose_k3s_pod')
        self.assertIs(r['execution_allowed'], False)

    def test_ready_no_action(self):
        r, _ = self.run_review(answer=verified(ready=True))
        self.assertEqual(r['status'], 'no_action')
        self.assertEqual(r['reason_code'], 'loki_currently_ready')

    def test_pod_missing_investigate(self):
        x = verified(); x.observation.update(pod_found=False, container_found=False, ready=None)
        r, _ = self.run_review(answer=x)
        self.assertEqual(r['status'], 'investigate')

    def test_wrong_source_rejected_without_awx(self):
        self.insert(source='wazuh')
        r, calls = self.run_review()
        self.assertEqual(calls, 0)
        self.assertEqual(r['status'], 'no_action')

    def test_synthetic_rejected(self):
        self.insert(synthetic=1)
        r, calls = self.run_review()
        self.assertEqual(calls, 0)
        self.assertEqual(r['status'], 'no_action')

    def test_wrong_title_rejected(self):
        self.insert(title='Otro componente')
        r, calls = self.run_review()
        self.assertEqual(calls, 0)
        self.assertEqual(r['status'], 'no_action')

    def test_legacy_incident_missing_reference(self):
        self.insert(reference=False)
        r, calls = self.run_review()
        self.assertEqual(calls, 0)
        self.assertEqual(r['reason_code'], 'missing_rule_uid_reference')

    def test_suppressed_triage_rejected(self):
        self.insert(decision='suppress')
        r, calls = self.run_review()
        self.assertEqual(calls, 0)
        self.assertEqual(r['status'], 'no_action')

    def test_review_triage_allowed(self):
        self.insert(decision='review')
        r, calls = self.run_review()
        self.assertEqual(calls, 1)
        self.assertEqual(r['status'], 'proposed')

    def test_stale_incident_fails_before_network(self):
        self.insert(received=NOW - timedelta(minutes=20))
        r, calls = self.run_review()
        self.assertEqual(calls, 0)
        self.assertEqual(r['reason_code'], 'stale_or_inconsistent_incident')

    def test_future_incident_fails(self):
        self.insert(received=NOW + timedelta(seconds=2))
        r, calls = self.run_review()
        self.assertEqual(calls, 0)
        self.assertEqual(r['reason_code'], 'stale_or_inconsistent_incident')

    def test_awx_observation_precedes_incident(self):
        r, calls = self.run_review(answer=verified(observed=NOW - timedelta(minutes=7)))
        self.assertEqual(calls, 1)
        self.assertEqual(r['reason_code'], 'observation_precedes_incident')
        self.assertFalse(r['awx_job_verified'])

    def test_awx_job_id_mismatch(self):
        r, _ = self.run_review(answer=verified(job_id=1235))
        self.assertEqual(r['reason_code'], 'observation_precedes_incident')

    def test_awx_error_fails_closed(self):
        with patch('app.remediation_loki_binding.fetch_verified_observation',
                   side_effect=AWXVerificationError('stale_or_invalid_job')):
            r = review_incident(incident_id=7, job_id=1234, db_path=self.db,
                                config=self.cfg, now=NOW)
        self.assertEqual(r['reason_code'], 'awx_verification_failed')
        self.assertEqual(r['verification_error_code'], 'stale_or_invalid_job')
        self.assertIs(r['execution_allowed'], False)

    def test_no_db_changes_in_review(self):
        r, _ = self.run_review()
        with sqlite3.connect(self.db) as c:
            self.assertIsNone(c.execute("SELECT name FROM sqlite_master WHERE name='remediation_reviews'").fetchone())
        self.assertTrue(r['awx_job_verified'])

    def test_no_job_id_from_alert(self):
        r, calls = self.run_review(job=True)
        self.assertEqual(calls, 0)
        self.assertEqual(r['status'], 'investigate')

    def test_bad_db_path(self):
        r = review_incident(incident_id=7, job_id=1234,
            db_path=Path(self.temp.name)/'missing.db', config=self.cfg, now=NOW)
        self.assertEqual(r['reason_code'], 'incident_unavailable')

    def test_invalid_reference_stored(self):
        with sqlite3.connect(self.db) as c:
            c.execute('UPDATE incidents SET analysis=? WHERE id=7',
                      (json.dumps({'triage': {'decision': 'notify'},
                       'grafana_loki_reference': {'rule_uid': RULE_UID}}),))
        r, calls = self.run_review()
        self.assertEqual(calls, 0)
        self.assertEqual(r['reason_code'], 'missing_rule_uid_reference')

    def test_record_opt_in(self):
        r, _ = self.run_review()
        self.assertTrue(record_review(db_path=self.db, review=r, now=NOW))
        self.assertFalse(record_review(db_path=self.db, review=r, now=NOW))
        with sqlite3.connect(self.db) as c:
            row = c.execute('SELECT incident_id,awx_job_id,proposal_json FROM remediation_reviews').fetchone()
        self.assertEqual((row[0], row[1]), (7, 1234))
        self.assertFalse(json.loads(row[2])['execution_allowed'])

    def test_job_reuse_blocked(self):
        r, _ = self.run_review()
        record_review(db_path=self.db, review=r, now=NOW)
        self.insert(ident=8)
        r2, _ = self.run_review(ident=8)
        self.assertFalse(record_review(db_path=self.db, review=r2, now=NOW))
        with sqlite3.connect(self.db) as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM remediation_reviews').fetchone()[0], 1)

    def test_bad_review_not_recorded(self):
        r, _ = self.run_review()
        r['execution_allowed'] = True
        with self.assertRaises(ValueError):
            record_review(db_path=self.db, review=r, now=NOW)

    def test_no_record_without_valid_job(self):
        r, _ = self.run_review(job=True)
        with self.assertRaises(ValueError):
            record_review(db_path=self.db, review=r, now=NOW)

    def test_main_integration_static(self):
        path = Path(__file__).resolve().parents[1] / 'app' / 'main.py'
        tree = ast.parse(path.read_text(encoding='utf8'))
        functions = {x.name:x for x in tree.body if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))}
        store = functions['store']
        grafana = functions['grafana']
        args = [a.arg for a in store.args.args]
        self.assertIn('grafana_loki_reference', args)
        captures = [n for n in ast.walk(grafana) if isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Name) and n.func.id == 'capture_grafana_loki_reference']
        self.assertEqual(len(captures), 1)
        # No llamadas a AWX en el procesamiento de webhooks.
        self.assertFalse(any(isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name) and 'awx' in n.func.id
            for n in ast.walk(grafana)))


if __name__ == '__main__':
    unittest.main()
