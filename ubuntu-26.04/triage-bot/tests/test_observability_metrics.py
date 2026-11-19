"""Block 4: read-only, authenticated, bounded-label self-observability."""
from __future__ import annotations

import json
from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from app import main
from app.observability_metrics import render

TOKEN = 'f' * 48


class MetricsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / 'incidents.db'
        with closing(sqlite3.connect(self.db)) as c, c:
            c.execute('''CREATE TABLE incidents (
                id INTEGER PRIMARY KEY, received_at TEXT, source TEXT,
                fingerprint TEXT, severity TEXT, title TEXT,
                synthetic INTEGER, analysis_mode TEXT, analysis TEXT)''')
            c.execute('CREATE TABLE ai_requests (requested_at INTEGER NOT NULL)')
            c.execute('''CREATE TABLE mail_deliveries (
                incident_id INTEGER PRIMARY KEY, status TEXT)''')
            c.execute('''CREATE TABLE telegram_deliveries (
                incident_id INTEGER PRIMARY KEY, status TEXT)''')

    def add_incident(self, incident_id, *, source='wazuh', decision='notify',
                     synthetic=0, mode='gemini', context=None, raw=None):
        analysis = {'triage': {'decision': decision}}
        if context:
            analysis.update(context)
        if raw is None:
            raw = json.dumps(analysis)
        with closing(sqlite3.connect(self.db)) as c, c:
            c.execute('INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?)', (
                incident_id, '2026-11-12T09:00:00+00:00', source,
                'secret-fingerprint', '15', 'sensitive-title', synthetic, mode, raw,
            ))

    def test_counts_decisions_and_synthetic_without_sensitive_labels(self):
        self.add_incident(1)
        self.add_incident(2, decision='review', synthetic=1, mode='rules_only')
        body = render(self.db, now=1794475800)
        self.assertIn('security_triage_incidents_total{decision="notify",source="wazuh",synthetic="false"} 1', body)
        self.assertIn('security_triage_incidents_total{decision="review",source="wazuh",synthetic="true"} 1', body)
        self.assertIn('security_triage_analysis_modes_total{mode="gemini"} 1', body)
        for secret in ('sensitive-title', 'secret-fingerprint', '192.168.', 'group_key'):
            self.assertNotIn(secret, body)

    def test_untrusted_labels_are_collapsed(self):
        self.add_incident(1, source='evil"\nsecret=1', decision='inject\nvalue', mode='custom',
                          context={'wazuh_context': {'status': 'bad"\nx'}})
        body = render(self.db, now=1794475800)
        self.assertIn('decision="unknown",source="other",synthetic="false"', body)
        self.assertIn('component="wazuh_webhook",status="other"', body)
        self.assertIn('mode="other"', body)
        self.assertNotIn('evil', body)
        self.assertNotIn('inject', body)

    def test_enricher_states_and_missing_context(self):
        self.add_incident(1, context={
            'wazuh_indexer': {'status': 'ok'},
            'wazuh_agent_monitoring': {'status': 'stale'},
            'logs_context': {'status': 'unavailable'},
        })
        self.add_incident(2)  # absent historical fields must not inflate metrics
        body = render(self.db, now=1794475800)
        self.assertIn('component="wazuh_indexer",status="ok"} 1', body)
        self.assertIn('component="wazuh_agent_monitoring",status="stale"} 1', body)
        self.assertIn('component="loki",status="unavailable"} 1', body)
        self.assertNotIn('status="not_collected"', body)

    def test_malformed_legacy_json_does_not_fail(self):
        self.add_incident(1, raw='not-json')
        body = render(self.db, now=1794475800)
        self.assertIn('decision="unknown"', body)
        self.assertNotIn('not-json', body)

    def test_delivery_states_are_bounded_and_only_from_database(self):
        with closing(sqlite3.connect(self.db)) as c, c:
            c.execute('INSERT INTO mail_deliveries VALUES (1, "sent")')
            c.execute('INSERT INTO telegram_deliveries VALUES (1, "pending")')
        body = render(self.db, now=1794475800)
        self.assertIn('channel="smtp",status="sent"} 1', body)
        self.assertIn('channel="telegram",status="pending"} 1', body)

    def test_absent_notifier_tables_do_not_create_them(self):
        with closing(sqlite3.connect(self.db)) as c, c:
            c.execute('DROP TABLE mail_deliveries')
            c.execute('DROP TABLE telegram_deliveries')
        render(self.db, now=1794475800)
        with closing(sqlite3.connect(self.db)) as c, c:
            names = {x[0] for x in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn('mail_deliveries', names)
        self.assertNotIn('telegram_deliveries', names)

    def test_reservations_last_hour_not_successful_api_calls(self):
        now = 1794475800
        with closing(sqlite3.connect(self.db)) as c, c:
            c.executemany('INSERT INTO ai_requests VALUES (?)', [(now-3599,), (now-3601,), (now+1,)])
        body = render(self.db, now=now)
        self.assertIn('security_triage_ai_reservations_last_hour 1', body)

    def test_missing_database_not_created(self):
        missing = Path(self.tmp.name) / 'absent.db'
        with self.assertRaises(sqlite3.OperationalError):
            render(missing, now=1794475800)
        self.assertFalse(missing.exists())

    def test_invalid_clock_rejected(self):
        for invalid in (True, -1, '2026', 0):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                render(self.db, now=invalid)

    def test_endpoint_disabled_by_default(self):
        with patch.object(main, 'OBSERVABILITY_METRICS_ENABLED', False), \
             patch.object(main, 'OBSERVABILITY_METRICS_TOKEN', TOKEN):
            with self.assertRaises(HTTPException) as ctx:
                main.internal_metrics('Bearer ' + TOKEN)
            self.assertEqual(ctx.exception.status_code, 404)

    def test_endpoint_rejects_missing_or_wrong_bearer(self):
        with patch.object(main, 'OBSERVABILITY_METRICS_ENABLED', True), \
             patch.object(main, 'OBSERVABILITY_METRICS_TOKEN', TOKEN), \
             patch.object(main, 'DB', self.db):
            for auth in (None, 'Bearer wrong', 'Bearer ' + 'x'*48, 'Basic ' + TOKEN):
                with self.subTest(auth=auth), self.assertRaises(HTTPException) as ctx:
                    main.internal_metrics(auth)
                self.assertEqual(ctx.exception.status_code, 401)

    def test_endpoint_returns_plaintext_only_when_authorized(self):
        self.add_incident(1)
        with patch.object(main, 'OBSERVABILITY_METRICS_ENABLED', True), \
             patch.object(main, 'OBSERVABILITY_METRICS_TOKEN', TOKEN), \
             patch.object(main, 'DB', self.db):
            res = main.internal_metrics('Bearer ' + TOKEN)
        self.assertIn(b'security_triage_incidents_total', res.body)
        self.assertEqual(res.headers['cache-control'], 'no-store')
        self.assertTrue(res.headers['content-type'].startswith('text/plain'))

    def test_endpoint_db_failure_is_503_without_details(self):
        with patch.object(main, 'OBSERVABILITY_METRICS_ENABLED', True), \
             patch.object(main, 'OBSERVABILITY_METRICS_TOKEN', TOKEN), \
             patch.object(main, 'DB', Path(self.tmp.name) / 'missing.db'):
            with self.assertRaises(HTTPException) as ctx:
                main.internal_metrics('Bearer ' + TOKEN)
            self.assertEqual(ctx.exception.status_code, 503)
            self.assertNotIn('missing.db', str(ctx.exception.detail))


if __name__ == '__main__':
    unittest.main()
