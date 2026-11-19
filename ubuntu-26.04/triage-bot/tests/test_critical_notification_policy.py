"""Regression coverage for critical notification policy; no network calls."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from app import mail_notifier, telegram_notifier
from app.triage_policy import assess, hard_critical_source


@contextmanager
def db_session(path):
    con = sqlite3.connect(path)
    try:
        with con:
            yield con
    finally:
        con.close()


def decision(source='wazuh', title='LAB - ssh attack', severity='15',
             synthetic=False, category='security', mode='gemini'):
    analysis = {
        'priority': 'low',
        'false_positive': 'likely',
        'confidence': 'high',
        'notify': False,
        'classification': 'benign',
    }
    triage = assess(source, title, severity, synthetic, mode, analysis,
                    {'host': 'srv-1', 'rule_key': '5763', 'category': category}, 0)
    return analysis, triage


def incident_row(source='wazuh', severity='15', title='LAB - ssh attack',
                 synthetic=False):
    analysis, triage = decision(source, title, severity, synthetic)
    return (1, source, title, severity, int(synthetic), json.dumps({
        **analysis, 'triage': triage,
    }))


class CriticalPolicyTests(unittest.TestCase):
    def test_wazuh_critical_ignores_lab_title_and_ai_downgrade(self):
        analysis, triage = decision()
        self.assertEqual(triage['decision'], 'notify')
        self.assertTrue(triage['notify'])
        self.assertEqual(analysis['priority'], 'high')
        self.assertEqual(triage['ai_suggests_notify'], False)

    def test_grafana_critical_ignores_test_title_and_category(self):
        _, triage = decision('grafana', 'TestAlert', 'critical', category='lab')
        self.assertEqual(triage['decision'], 'notify')

    def test_synthetic_critical_is_never_notified(self):
        _, triage = decision(synthetic=True)
        self.assertEqual(triage['decision'], 'suppress')
        self.assertFalse(triage['notify'])

    def test_real_noncritical_lab_title_stays_suppressed(self):
        _, triage = decision(severity='8')
        self.assertEqual(triage['decision'], 'suppress')

    def test_real_noncritical_lab_category_stays_suppressed(self):
        _, triage = decision(title='ordinary event', severity='8', category='lab')
        self.assertEqual(triage['decision'], 'suppress')

    def test_boundary_and_invalid_levels(self):
        self.assertTrue(hard_critical_source('wazuh', '12'))
        self.assertFalse(hard_critical_source('wazuh', '11'))
        self.assertFalse(hard_critical_source('wazuh', 'bad'))
        self.assertTrue(hard_critical_source('grafana', 'CRITICAL'))
        self.assertFalse(hard_critical_source('grafana', 'high'))
        self.assertFalse(hard_critical_source('loki', 'critical'))

    def test_notifiers_follow_policy_even_with_testlike_title(self):
        for title in ('LAB - ssh attack', 'TestAlert', 'test alert'):
            with self.subTest(title=title):
                row = incident_row(title=title)
                self.assertTrue(mail_notifier.eligible(row))
                self.assertTrue(telegram_notifier.eligible(row))

    def test_notifiers_reject_synthetic_or_legacy(self):
        row = incident_row(synthetic=True)
        self.assertFalse(mail_notifier.eligible(row))
        self.assertFalse(telegram_notifier.eligible(row))
        legacy = (1, 'wazuh', 'incident', '15', 0, json.dumps({'priority': 'critical'}))
        self.assertFalse(mail_notifier.eligible(legacy))
        self.assertFalse(telegram_notifier.eligible(legacy))

    def test_notifiers_reject_fabricated_ai_only_notify(self):
        row = (1, 'wazuh', 'incident', '15', 0, json.dumps({
            'notify': True,
            'triage': {'policy_version': 'triage-v1', 'decision': 'review',
                       'notify': False, 'group_key': 'test'},
        }))
        self.assertFalse(mail_notifier.eligible(row))
        self.assertFalse(telegram_notifier.eligible(row))


class WorkerCooldownTests(unittest.TestCase):
    """Real SQLite, mocked transports, no SMTP/Telegram or external dependencies."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / 'incidents.db'
        with db_session(self.db) as conn:
            conn.execute('''CREATE TABLE incidents (
                id INTEGER PRIMARY KEY, received_at TEXT, source TEXT,
                title TEXT, severity TEXT, synthetic INTEGER,
                analysis_mode TEXT, analysis TEXT
            )''')
        self.now = int(time.time())

    def add_incident(self, row):
        with db_session(self.db) as conn:
            conn.execute('''INSERT INTO incidents(id,received_at,source,title,
                severity,synthetic,analysis_mode,analysis)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?)''',
                (row[0], '2026-11-11T00:00:00Z', row[1], row[2],
                 row[3], row[4], 'rules_only', row[5]))
        return json.loads(row[5])['triage']['group_key']

    def mail_cfg(self, *, max_per_hour=10):
        return mail_notifier.Config(
            db_path=self.db, enabled=True, host='smtp.example.invalid',
            port=465, security='ssl', user='not-used', password='not-used',
            sender='notify@example.invalid', recipients=('soc@example.invalid',),
            interval=10, max_per_hour=max_per_hour, max_retries=3,
            dashboard_url='', cooldown_seconds=1800,
        )

    def telegram_cfg(self, *, max_per_hour=10):
        return telegram_notifier.Config(
            db_path=self.db, enabled=True, token='not-used', chat_id='1',
            interval=10, max_per_hour=max_per_hour, max_retries=3,
            cooldown_seconds=1800, dashboard_url='',
        )

    def test_mail_critical_bypasses_cooldown(self):
        row = incident_row()
        group = self.add_incident(row)
        cfg = self.mail_cfg()
        mail_notifier.setup_db(cfg)
        mail_notifier.enqueue_existing(cfg, 1)
        with db_session(self.db) as con:
            con.execute('INSERT INTO mailer_cooldowns VALUES (?, ?)', (group, self.now - 20))
        with patch.object(mail_notifier, 'smtp_send') as send, \
             patch.object(mail_notifier, 'build_message', return_value='test'):
            self.assertTrue(mail_notifier.send_due(cfg))
            send.assert_called_once()
        with db_session(self.db) as con:
            self.assertEqual(con.execute('SELECT status FROM mail_deliveries').fetchone()[0], 'sent')

    def test_telegram_critical_bypasses_cooldown(self):
        row = incident_row()
        group = self.add_incident(row)
        cfg = self.telegram_cfg()
        telegram_notifier.setup_db(cfg)
        telegram_notifier.enqueue_existing(cfg, 1)
        with db_session(self.db) as con:
            con.execute('INSERT INTO telegram_cooldowns VALUES (?, ?)', (group, self.now - 20))
        with patch.object(telegram_notifier, 'telegram_send') as send, \
             patch.object(telegram_notifier, 'build_text', return_value='test'):
            self.assertTrue(telegram_notifier.send_due(cfg, now=self.now))
            send.assert_called_once()
        with db_session(self.db) as con:
            self.assertEqual(con.execute('SELECT status FROM telegram_deliveries').fetchone()[0], 'sent')

    def test_mail_noncritical_still_suppressed_by_cooldown(self):
        row = incident_row(severity='11', title='SSH suspected')
        # Higher-priority AI policy is not part of the cooldown exception.
        data = json.loads(row[5])
        data['triage']['decision'] = 'notify'
        data['triage']['notify'] = True
        row = (*row[:-1], json.dumps(data))
        group = self.add_incident(row)
        cfg = self.mail_cfg()
        mail_notifier.setup_db(cfg)
        mail_notifier.enqueue_existing(cfg, 1)
        with db_session(self.db) as con:
            con.execute('INSERT INTO mailer_cooldowns VALUES (?, ?)', (group, self.now - 20))
        with patch.object(mail_notifier, 'smtp_send') as send:
            self.assertTrue(mail_notifier.send_due(cfg))
            send.assert_not_called()
        with db_session(self.db) as con:
            self.assertEqual(con.execute('SELECT status FROM mail_deliveries').fetchone()[0], 'suppressed')

    def test_telegram_noncritical_still_suppressed_by_cooldown(self):
        row = incident_row(severity='11', title='SSH suspected')
        data = json.loads(row[5])
        data['triage']['decision'] = 'notify'
        data['triage']['notify'] = True
        row = (*row[:-1], json.dumps(data))
        group = self.add_incident(row)
        cfg = self.telegram_cfg()
        telegram_notifier.setup_db(cfg)
        telegram_notifier.enqueue_existing(cfg, 1)
        with db_session(self.db) as con:
            con.execute('INSERT INTO telegram_cooldowns VALUES (?, ?)', (group, self.now - 20))
        with patch.object(telegram_notifier, 'telegram_send') as send:
            self.assertTrue(telegram_notifier.send_due(cfg, now=self.now))
            send.assert_not_called()
        with db_session(self.db) as con:
            self.assertEqual(con.execute('SELECT status FROM telegram_deliveries').fetchone()[0], 'suppressed')

    def test_telegram_hourly_limit_defers_critical_without_suppression(self):
        row = incident_row()
        self.add_incident(row)
        cfg = self.telegram_cfg(max_per_hour=1)
        telegram_notifier.setup_db(cfg)
        telegram_notifier.enqueue_existing(cfg, 1)
        with db_session(self.db) as con:
            con.execute("INSERT INTO telegram_deliveries(incident_id,status,sent_ts) "
                        "VALUES (2,'sent',?)", (self.now,))
        with patch.object(telegram_notifier, 'telegram_send') as send:
            self.assertFalse(telegram_notifier.send_due(cfg, now=self.now))
            send.assert_not_called()
        with db_session(self.db) as con:
            self.assertEqual(con.execute(
                'SELECT status FROM telegram_deliveries WHERE incident_id=1'
            ).fetchone()[0], 'pending')

    def test_hourly_limit_defers_critical_without_suppression(self):
        row = incident_row()
        self.add_incident(row)
        cfg = self.mail_cfg(max_per_hour=1)
        mail_notifier.setup_db(cfg)
        mail_notifier.enqueue_existing(cfg, 1)
        with db_session(self.db) as con:
            con.execute("INSERT INTO mail_deliveries(incident_id,status,sent_ts) VALUES (2,'sent',?)", (self.now,))
        with patch.object(mail_notifier, 'smtp_send') as send:
            self.assertFalse(mail_notifier.send_due(cfg))
            send.assert_not_called()
        with db_session(self.db) as con:
            self.assertEqual(con.execute('SELECT status FROM mail_deliveries WHERE incident_id=1').fetchone()[0], 'pending')


if __name__ == '__main__':
    unittest.main()
