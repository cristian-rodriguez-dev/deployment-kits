"""Standalone SMTP notifier for Security Triage Bot.

Does not change FastAPI. Monitors its existing SQLite DB for new incidents,
queues high-priority operational events, and emails them with bounded retries.
Start only one instance. Uses Python stdlib and requires TLS.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import smtplib
import sqlite3
import ssl
import sys
import time
from dataclasses import dataclass
from contextlib import contextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from app.notification_format import details, render_email_text, render_email_html
from app.triage_policy import hard_critical_source

LOG = logging.getLogger('security-triage-mail')
ACTIVE = True


def stop_handler(_signum, _frame):
    global ACTIVE
    ACTIVE = False


def env_int(key: str, default: int, minimum: int, maximum: int) -> int:
    try:
        val = int(os.getenv(key, str(default)))
    except ValueError as exc:
        raise ValueError(f'{key}: se esperaba entero') from exc
    if not minimum <= val <= maximum:
        raise ValueError(f'{key}: fuera de rango [{minimum}, {maximum}]')
    return val


def mail_address(value: str, field: str) -> str:
    value = value.strip()
    if '\n' in value or '\r' in value or not re.fullmatch(r'[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+', value):
        raise ValueError(f'{field}: dirección de correo no válida')
    return value


@dataclass(frozen=True)
class Config:
    db_path: Path
    enabled: bool
    host: str
    port: int
    security: str
    user: str
    password: str
    sender: str
    recipients: tuple[str, ...]
    interval: int
    max_per_hour: int
    max_retries: int
    dashboard_url: str
    cooldown_seconds: int = 1800

    @classmethod
    def load(cls) -> 'Config':
        host = os.getenv('SMTP_HOST', '').strip()
        security = os.getenv('SMTP_SECURITY', 'ssl').strip().lower()
        if security not in ('ssl', 'starttls'):
            raise ValueError('SMTP_SECURITY debe ser ssl o starttls; no se permite SMTP sin TLS')
        raw_to = os.getenv('MAIL_TO', '')
        recipients = tuple(mail_address(x, 'MAIL_TO') for x in re.split('[,;]', raw_to) if x.strip())
        if len(recipients) > 3:
            raise ValueError('MAIL_TO admite máximo 3 destinatarios')
        sender_raw = os.getenv('MAIL_FROM', '')
        user = os.getenv('SMTP_USER', '').strip()
        sender = mail_address(sender_raw, 'MAIL_FROM') if sender_raw.strip() else ''
        dashboard_url = os.getenv('DASHBOARD_URL', '').strip()
        if dashboard_url and not dashboard_url.startswith('https://'):
            raise ValueError('DASHBOARD_URL debe empezar por https://')
        return cls(
            db_path=Path(os.getenv('DB_PATH', '/data/incidents.db')),
            enabled=os.getenv('MAIL_ENABLED', 'false').lower() == 'true',
            host=host,
            port=env_int('SMTP_PORT', 465 if security == 'ssl' else 587, 1, 65535),
            security=security,
            user=user,
            password=os.getenv('SMTP_PASSWORD', ''),
            sender=sender,
            recipients=recipients,
            interval=env_int('MAIL_POLL_SECONDS', 10, 5, 300),
            max_per_hour=env_int('MAIL_MAX_PER_HOUR', 10, 1, 100),
            max_retries=env_int('MAIL_MAX_RETRIES', 4, 1, 8),
            dashboard_url=dashboard_url,
            cooldown_seconds=env_int('MAIL_COOLDOWN_MINUTES', 30, 0, 240) * 60,
        )

    def validate_smtp(self) -> None:
        if not self.host or not re.fullmatch(r'[A-Za-z0-9.:-]+', self.host):
            raise ValueError('SMTP_HOST no válido')
        if not self.sender or not self.recipients:
            raise ValueError('Configura MAIL_FROM y MAIL_TO')
        if not self.user or not self.password:
            raise ValueError('Configura SMTP_USER y SMTP_PASSWORD')


@contextmanager
def db_connect(cfg: Config):
    if not cfg.db_path.is_file():
        raise RuntimeError('Base de incidentes no encontrada en /data; no se crearán bases vacías')
    c = sqlite3.connect(str(cfg.db_path), timeout=10)
    try:
        c.execute('PRAGMA busy_timeout=10000')
        # Pure, bounded severity classification for deterministic queue priority.
        # It does not bypass the notification policy or hourly delivery quota.
        c.create_function('source_critical', 2,
                          lambda source, severity: int(hard_critical_source(source, severity)))
        with c:
            yield c
    finally:
        c.close()


def setup_db(cfg: Config) -> int:
    """Add mailer metadata only; preserve incident DB and current mail watermark."""
    with db_connect(cfg) as c:
        check = c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='incidents'").fetchone()
        if not check:
            raise RuntimeError('No existe la tabla incidents en la SQLite compartida')
        c.execute('''CREATE TABLE IF NOT EXISTS mailer_state (
            key TEXT PRIMARY KEY, value TEXT NOT NULL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS mail_deliveries (
            incident_id INTEGER PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_ts INTEGER NOT NULL DEFAULT 0,
            sent_ts INTEGER,
            last_error TEXT NOT NULL DEFAULT ''
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS mailer_cooldowns (
            group_key TEXT PRIMARY KEY,
            last_sent_ts INTEGER NOT NULL
        )''')
        row = c.execute("SELECT value FROM mailer_state WHERE key='last_seen_id'").fetchone()
        if row is None:
            baseline = c.execute('SELECT COALESCE(MAX(id),0) FROM incidents').fetchone()[0]
            c.execute("INSERT INTO mailer_state(key,value) VALUES('last_seen_id',?)", (str(baseline),))
            LOG.info('Inicializado desde incidente #%s: sin envío retrospectivo', baseline)
            return baseline
        return int(row[0])



def eligible(row: tuple) -> bool:
    """Only explicit, validated policy decisions from smart-triage-v1 may send mail.

    Legacy analyses without the triage block are fail-closed, even if severity high.
    row = id, source, title, severity, synthetic, analysis-json.
    """
    _id, source, _title, _severity, synthetic, raw = row
    if synthetic or source not in ('wazuh', 'grafana'):
        return False
    # Text-only test markers must not override a validated policy decision.
    # The authoritative test flag is `synthetic`; the policy can still suppress
    # noncritical demonstrations before they reach this worker.
    try:
        analysis = json.loads(raw)
        info = analysis.get('triage', {})
        return (isinstance(info, dict)
                and info.get('policy_version') == 'triage-v1'
                and info.get('decision') == 'notify'
                and info.get('notify') is True
                and isinstance(info.get('group_key'), str)
                and bool(info['group_key']))
    except (ValueError, TypeError, AttributeError):
        return False



def scan_new(cfg: Config) -> int:
    added = 0
    with db_connect(cfg) as c:
        current = int(c.execute("SELECT value FROM mailer_state WHERE key='last_seen_id'").fetchone()[0])
        rows = c.execute('''SELECT id,source,title,severity,synthetic,analysis
                            FROM incidents WHERE id>? ORDER BY id LIMIT 200''', (current,)).fetchall()
        for row in rows:
            if eligible(row):
                cur = c.execute('INSERT OR IGNORE INTO mail_deliveries(incident_id) VALUES(?)', (row[0],))
                added += cur.rowcount
        if rows:
            c.execute("UPDATE mailer_state SET value=? WHERE key='last_seen_id'", (str(rows[-1][0]),))
    if added:
        LOG.info('Nuevas notificaciones preparadas: %s', added)
    return added


def truncate(value, limit: int) -> str:
    text = str(value) if value is not None else ''
    text = ''.join(ch for ch in text if ch == '\n' or ch == '\t' or ord(ch) >= 32)
    return text[:limit]


def build_message(cfg: Config, row: tuple) -> EmailMessage:
    """MIME multipart/alternative: safe plain text + responsive HTML (no tracking)."""
    d = details(row, cfg.dashboard_url)
    msg = EmailMessage()
    msg['From'] = cfg.sender
    msg['To'] = ', '.join(cfg.recipients)
    # Never interpolate untrusted incident title into mail headers.
    msg['Subject'] = f"[Security Triage][{d['priority_label']}] Incidente #{d['id']} — {d['source']}"
    msg.set_content(render_email_text(d), charset='utf-8')
    msg.add_alternative(render_email_html(d), subtype='html', charset='utf-8')
    return msg


def smtp_send(cfg: Config, msg: EmailMessage) -> None:
    cfg.validate_smtp()
    context = ssl.create_default_context()
    if cfg.security == 'ssl':
        with smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=12, context=context) as smtp:
            smtp.login(cfg.user, cfg.password)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(cfg.host, cfg.port, timeout=12) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(cfg.user, cfg.password)
            smtp.send_message(msg)


def send_test(cfg: Config) -> None:
    msg = EmailMessage()
    msg['From'] = cfg.sender
    msg['To'] = ', '.join(cfg.recipients)
    msg['Subject'] = '[Security Triage] Prueba de correo SMTP'
    msg.set_content('Prueba del canal SMTP de Security Triage Bot.\n'
                    'No corresponde a un incidente de seguridad.\n', charset='utf-8')
    smtp_send(cfg, msg)
    print('SMTP aceptó el mensaje de prueba. Confirma su recepción en la bandeja de entrada.')


def enqueue_existing(cfg: Config, incident_id: int) -> None:
    with db_connect(cfg) as c:
        row = c.execute('SELECT id,source,title,severity,synthetic,analysis FROM incidents WHERE id=?',
                        (incident_id,)).fetchone()
        if row is None:
            raise ValueError(f'Incidente #{incident_id} no encontrado')
        if not eligible(row):
            raise ValueError('Solo se permiten incidentes operativos Wazuh/Grafana de prioridad alta')
        cur = c.execute('INSERT OR IGNORE INTO mail_deliveries(incident_id) VALUES(?)', (incident_id,))
    if cur.rowcount:
        LOG.info('Incidente #%s puesto en cola manualmente', incident_id)
    else:
        LOG.info('Incidente #%s ya fue preparado/notificado; no se duplica', incident_id)


def send_due(cfg: Config) -> bool:
    now = int(time.time())
    with db_connect(cfg) as c:
        n = c.execute("SELECT COUNT(*) FROM mail_deliveries WHERE status='sent' AND sent_ts>=?",
                      (now - 3600,)).fetchone()[0]
        if n >= cfg.max_per_hour:
            return False
        row = c.execute('''SELECT m.incident_id,i.received_at,i.source,i.title,i.severity,
                                  i.synthetic,i.analysis_mode,i.analysis,m.attempts
                           FROM mail_deliveries AS m
                           JOIN incidents AS i ON i.id=m.incident_id
                           WHERE m.status='pending' AND m.next_attempt_ts<=?
                           ORDER BY source_critical(i.source,i.severity) DESC,
                                    m.incident_id LIMIT 1''', (now,)).fetchone()
        if row is None:
            return False
        incident_id = row[0]
        eligibility_tuple = (row[0], row[2], row[3], row[4], row[5], row[7])
        if not eligible(eligibility_tuple):
            c.execute("UPDATE mail_deliveries SET status='suppressed',last_error='policy' WHERE incident_id=?",
                      (incident_id,))
            LOG.info('Incidente #%s suprimido: la política no autoriza correo', incident_id)
            return True
        analysis = json.loads(row[7])
        group = analysis['triage']['group_key']
        last = c.execute('SELECT last_sent_ts FROM mailer_cooldowns WHERE group_key=?', (group,)).fetchone()
        # A fresh source-critical incident must not be permanently suppressed
        # by a prior notification for the same host/rule group. The hourly
        # delivery budget still applies and leaves excess alerts pending.
        if (last and (now - int(last[0])) < cfg.cooldown_seconds
                and not hard_critical_source(row[2], row[4])):
            c.execute("UPDATE mail_deliveries SET status='suppressed',last_error='cooldown' WHERE incident_id=?",
                      (incident_id,))
            LOG.info('Incidente #%s suprimido por cooldown de grupo', incident_id)
            return True
    try:
        smtp_send(cfg, build_message(cfg, row[:8]))
    except (smtplib.SMTPException, OSError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        attempts = row[8] + 1
        status = 'failed' if attempts >= cfg.max_retries else 'pending'
        delay = min(3600, 20 * 2 ** (attempts - 1))
        with db_connect(cfg) as c:
            c.execute('''UPDATE mail_deliveries SET attempts=?, status=?, next_attempt_ts=?, last_error=?
                         WHERE incident_id=?''',
                      (attempts, status, now + delay, type(exc).__name__, incident_id))
        LOG.warning('Fallo SMTP incidente #%s: %s intento %s/%s',
                    incident_id, type(exc).__name__, attempts, cfg.max_retries)
        return False
    with db_connect(cfg) as c:
        c.execute("UPDATE mail_deliveries SET status='sent',sent_ts=?,attempts=attempts+1,last_error='' WHERE incident_id=?",
                  (int(time.time()), incident_id))
        c.execute('''INSERT INTO mailer_cooldowns(group_key,last_sent_ts) VALUES(?,?)
                     ON CONFLICT(group_key) DO UPDATE SET last_sent_ts=excluded.last_sent_ts''',
                  (group, int(time.time())))
    LOG.info('Correo aceptado por SMTP para incidente #%s', incident_id)
    return True



def print_status(cfg: Config) -> None:
    with db_connect(cfg) as c:
        last = c.execute("SELECT value FROM mailer_state WHERE key='last_seen_id'").fetchone()
        rows = c.execute('SELECT status,COUNT(*) FROM mail_deliveries GROUP BY status').fetchall()
    print('Último incidente inspeccionado:', last[0] if last else 'sin inicializar')
    print('Estado de notificaciones:', dict(rows))


def preview(cfg: Config) -> None:
    """Inspect last decisions without any SMTP connection or email side effect."""
    with db_connect(cfg) as c:
        rows = c.execute('''SELECT id,source,title,severity,synthetic,analysis
                            FROM incidents ORDER BY id DESC LIMIT 12''').fetchall()
    print('VISTA PREVIA — ningún correo enviado')
    for row in rows:
        try:
            analysis = json.loads(row[5])
            triage = analysis.get('triage') or {}
        except (ValueError, TypeError):
            triage = {}
        reason = str(triage.get('reason', 'Sin evaluación inteligente (incidente antiguo)'))[:130]
        print(f'#{row[0]} [{row[1]}] {row[2][:55]} -> '
              f'{"ENVIAR" if eligible(row) else "NO ENVIAR"}; '
              f'{triage.get("decision", "legacy")}; {reason}')


def main() -> int:
    parser = argparse.ArgumentParser(description='Worker SMTP independiente de FastAPI')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--test', action='store_true', help='Prueba SMTP sin datos de incidentes')
    group.add_argument('--preview', action='store_true', help='Revisa decisiones, sin conectar a SMTP')
    group.add_argument('--status', action='store_true', help='Muestra estado y contador')
    group.add_argument('--send-incident', type=int, metavar='ID', help='Encola incidente con política notify')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    try:
        cfg = Config.load()
        if args.test:
            send_test(cfg)
            return 0
        if args.preview:
            preview(cfg)
            return 0
        if args.status:
            print_status(cfg)
            return 0
        if args.send_incident is not None:
            cfg.validate_smtp()
            setup_db(cfg)
            enqueue_existing(cfg, args.send_incident)
            print('Incidente en cola si la política lo autoriza; el worker activo lo enviará.')
            print_status(cfg)
            return 0
        if not cfg.enabled:
            raise RuntimeError('MAIL_ENABLED no es true; worker no arrancado')
        cfg.validate_smtp()
        signal.signal(signal.SIGTERM, stop_handler)
        signal.signal(signal.SIGINT, stop_handler)
        setup_db(cfg)
        LOG.info('Worker activo: decisión de triaje explícita, cooldown, máximo %s/h', cfg.max_per_hour)
        while ACTIVE:
            scan_new(cfg)
            for _ in range(2):
                if not send_due(cfg):
                    break
            time.sleep(cfg.interval)
        return 0
    except (ValueError, RuntimeError, sqlite3.Error) as exc:
        LOG.error('Configuración o DB inválida: %s', type(exc).__name__)
        return 1



if __name__ == '__main__':
    sys.exit(main())
