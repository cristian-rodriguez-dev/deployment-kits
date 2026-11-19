"""Block 3: critical-first delivery and informative recurrence (all offline)."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import mail_notifier, telegram_notifier
from app.notification_format import details, render_email_text, render_email_html, render_telegram_html


def make_analysis(*, previous=0, decision='notify', group='group-demo'):
    return json.dumps({
        'priority': 'high', 'summary': 'Incidente de prueba controlada',
        'triage': {'policy_version': 'triage-v1', 'decision': decision,
                   'notify': decision == 'notify', 'group_key': group,
                   'recent_same_rule_host_30m': previous},
    })


def incident_row(incident_id=1, *, source='wazuh', severity='11', previous=0,
                 decision='notify', group='group-demo'):
    return (incident_id, '2026-11-11T14:00:00+00:00', source,
            'Incidente simulado', severity, 0, 'rules_only',
            make_analysis(previous=previous, decision=decision, group=group))


class RecurrenceFormatTests(unittest.TestCase):
    def test_two_events_reported_without_escalating(self):
        d = details(incident_row(previous=1), '')
        self.assertEqual(d['notification_recurrence'],
                         {'total': 2, 'window_minutes': 30, 'manual_review': False})
        for output in (render_email_text(d), render_email_html(d), render_telegram_html(d)):
            self.assertIn('2 incidentes recibidos por el bot', output)
            self.assertNotIn('Revisión humana prioritaria', output)

    def test_three_events_suggest_manual_review_in_all_channels(self):
        d = details(incident_row(previous=2), '')
        self.assertTrue(d['notification_recurrence']['manual_review'])
        for output in (render_email_text(d), render_email_html(d), render_telegram_html(d)):
            self.assertIn('3 incidentes recibidos por el bot', output)
            self.assertIn('Revisión humana prioritaria', output)
            self.assertIn('sin escalado automático', output)

    def test_zero_or_missing_count_does_not_fabricate_recurrence(self):
        self.assertIsNone(details(incident_row(previous=0), '')['notification_recurrence'])
        row = list(incident_row())
        analysis = json.loads(row[7]); del analysis['triage']['recent_same_rule_host_30m']
        row[7] = json.dumps(analysis)
        self.assertIsNone(details(tuple(row), '')['notification_recurrence'])

    def test_untrusted_counts_fail_closed(self):
        for invalid in (True, -1, '3', 100_001, None, 1.5):
            with self.subTest(invalid=invalid):
                d = details(incident_row(previous=invalid), '')
                self.assertIsNone(d['notification_recurrence'])

    def test_suppressed_or_legacy_incident_has_no_recurrence(self):
        self.assertIsNone(details(incident_row(previous=4, decision='review'), '')['notification_recurrence'])
        row = list(incident_row(previous=4))
        analysis = json.loads(row[7]); analysis['triage']['policy_version'] = 'legacy'
        row[7] = json.dumps(analysis)
        self.assertIsNone(details(tuple(row), '')['notification_recurrence'])

    def test_grafana_uses_same_verified_bot_count(self):
        d = details(incident_row(source='grafana', severity='high', previous=2), '')
        self.assertEqual(d['notification_recurrence']['total'], 3)


class QueuePriorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'incidents.db'
        with sqlite3.connect(self.path) as db:
            db.execute('''CREATE TABLE incidents (
                id INTEGER PRIMARY KEY, received_at TEXT, source TEXT,
                title TEXT, severity TEXT, synthetic INTEGER,
                analysis_mode TEXT, analysis TEXT)''')

    def insert(self, id, source='wazuh', severity='11', decision='notify'):
        row = incident_row(id, source=source, severity=severity,
                           decision=decision, group=f'{source}-{id}')
        with sqlite3.connect(self.path) as db:
            db.execute('INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?)', row)

    def mail_cfg(self, *, limit=10):
        return mail_notifier.Config(
            db_path=self.path, enabled=True, host='example.invalid', port=465,
            security='ssl', user='test', password='test', sender='a@example.invalid',
            recipients=('b@example.invalid',), interval=10, max_per_hour=limit,
            max_retries=3, dashboard_url='', cooldown_seconds=1800)

    def telegram_cfg(self, *, limit=10):
        return telegram_notifier.Config(
            db_path=self.path, enabled=True, token='unused', chat_id='1',
            interval=10, max_per_hour=limit, max_retries=3,
            cooldown_seconds=1800, dashboard_url='')

    def prepare(self, kind, *, limit=10):
        cfg = self.mail_cfg(limit=limit) if kind == 'mail' else self.telegram_cfg(limit=limit)
        module = mail_notifier if kind == 'mail' else telegram_notifier
        module.setup_db(cfg)
        for incident_id in (1, 2):
            module.enqueue_existing(cfg, incident_id)
        return module, cfg

    def sent_ids(self, kind):
        table = 'mail_deliveries' if kind == 'mail' else 'telegram_deliveries'
        with sqlite3.connect(self.path) as db:
            return db.execute(f"SELECT incident_id,status FROM {table} ORDER BY incident_id").fetchall()

    def _send(self, kind, module, cfg):
        send_name = 'smtp_send' if kind == 'mail' else 'telegram_send'
        build_name = 'build_message' if kind == 'mail' else 'build_text'
        with patch.object(module, send_name) as send, patch.object(module, build_name, return_value='test'):
            self.assertTrue(module.send_due(cfg))
            send.assert_called_once()
        return self.sent_ids(kind)

    def test_critical_wazuh_first_mail_and_telegram(self):
        for kind in ('mail', 'telegram'):
            with self.subTest(kind=kind):
                # Fresh DB for both independent channels is not required:
                # the workers maintain separate delivery state tables.
                if kind == 'mail':
                    self.insert(1, severity='11')
                    self.insert(2, severity='15')
                module, cfg = self.prepare(kind)
                self.assertEqual(self._send(kind, module, cfg), [(1, 'pending'), (2, 'sent')])

    def test_grafana_critical_first_mail_and_telegram(self):
        self.insert(1, severity='11')
        self.insert(2, source='grafana', severity='critical')
        for kind in ('mail', 'telegram'):
            module, cfg = self.prepare(kind)
            self.assertEqual(self._send(kind, module, cfg), [(1, 'pending'), (2, 'sent')])

    def test_same_priority_keeps_fifo_for_both(self):
        self.insert(1, severity='11')
        self.insert(2, severity='11')
        for kind in ('mail', 'telegram'):
            module, cfg = self.prepare(kind)
            self.assertEqual(self._send(kind, module, cfg), [(1, 'sent'), (2, 'pending')])

    def test_all_critical_keeps_fifo_for_both(self):
        self.insert(1, severity='14')
        self.insert(2, severity='15')
        for kind in ('mail', 'telegram'):
            module, cfg = self.prepare(kind)
            self.assertEqual(self._send(kind, module, cfg), [(1, 'sent'), (2, 'pending')])

    def test_hourly_budget_still_blocks_second_delivery(self):
        self.insert(1, severity='11')
        self.insert(2, severity='15')
        for kind in ('mail', 'telegram'):
            module, cfg = self.prepare(kind, limit=1)
            self._send(kind, module, cfg)
            self.assertFalse(module.send_due(cfg))
            self.assertEqual(self.sent_ids(kind), [(1, 'pending'), (2, 'sent')])

    def test_non_notify_critical_cannot_be_sent(self):
        self.insert(1, severity='11')
        self.insert(2, severity='15', decision='review')
        for kind in ('mail', 'telegram'):
            module = mail_notifier if kind == 'mail' else telegram_notifier
            cfg = self.mail_cfg() if kind == 'mail' else self.telegram_cfg()
            module.setup_db(cfg)
            module.enqueue_existing(cfg, 1)
            with self.assertRaises(ValueError):
                module.enqueue_existing(cfg, 2)
            self.assertEqual(self._send(kind, module, cfg), [(1, 'sent')])


if __name__ == '__main__':
    unittest.main()
