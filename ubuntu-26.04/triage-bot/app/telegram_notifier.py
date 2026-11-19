"""Standalone Telegram notifier for Security Triage Bot (lab).

Shares only the incidents SQLite file with FastAPI/SMTP; maintains separate
watermark, deliveries, rate limit and cooldown. Uses exactly the SMTP worker's
versioned smart-triage eligibility function, not the model's raw suggestion.
Python standard library only. One running worker instance per DB.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import re
import signal
import sqlite3
import sys
import time
import urllib.error
import urllib.request

from app.notification_format import details, render_telegram_html
from app.mail_notifier import eligible as _mail_eligible  # Reuse validated policy gate.
from app.triage_policy import hard_critical_source


def eligible(row: tuple) -> bool:
    """Use exactly the same explicit policy gate as the SMTP worker."""
    return _mail_eligible(row)

LOG = logging.getLogger('security-triage-telegram')
RUNNING = True


def stop_handler(_sig, _frame):
    global RUNNING
    RUNNING = False


def integer_setting(key: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(os.getenv(key, str(default)))
    except ValueError as exc:
        raise ValueError(f'{key} debe ser un entero') from exc
    if not lower <= value <= upper:
        raise ValueError(f'{key} fuera de rango ({lower}-{upper})')
    return value


@dataclass(frozen=True)
class Config:
    db_path: Path
    enabled: bool
    token: str
    chat_id: str
    interval: int
    max_per_hour: int
    max_retries: int
    cooldown_seconds: int
    dashboard_url: str

    @classmethod
    def load(cls) -> 'Config':
        url = os.getenv('DASHBOARD_URL', '').strip()
        if url and not url.startswith('https://'):
            raise ValueError('DASHBOARD_URL debe usar https://')
        return cls(
            db_path=Path(os.getenv('DB_PATH', '/data/incidents.db')),
            enabled=os.getenv('TELEGRAM_ENABLED', 'false').lower() == 'true',
            token=os.getenv('TELEGRAM_BOT_TOKEN', '').strip(),
            chat_id=os.getenv('TELEGRAM_CHAT_ID', '').strip(),
            interval=integer_setting('TELEGRAM_POLL_SECONDS', 10, 5, 300),
            max_per_hour=integer_setting('TELEGRAM_MAX_PER_HOUR', 10, 1, 100),
            max_retries=integer_setting('TELEGRAM_MAX_RETRIES', 4, 1, 8),
            cooldown_seconds=integer_setting('TELEGRAM_COOLDOWN_MINUTES', 30, 0, 240) * 60,
            dashboard_url=url,
        )

    def validate_api(self) -> None:
        if not re.fullmatch(r'[0-9]+:[A-Za-z0-9_-]{20,}', self.token):
            raise ValueError('TELEGRAM_BOT_TOKEN no tiene un formato válido')
        if not re.fullmatch(r'-?[0-9]{1,20}', self.chat_id):
            raise ValueError('TELEGRAM_CHAT_ID debe ser numérico')


@contextmanager
def db_connect(cfg: Config):
    if not cfg.db_path.is_file():
        raise RuntimeError('La base SQLite no existe; no se creará una base vacía')
    con = sqlite3.connect(str(cfg.db_path), timeout=10)
    try:
        con.execute('PRAGMA busy_timeout=10000')
        # Same source-critical-first ordering as SMTP, without changing policy.
        con.create_function('source_critical', 2,
                            lambda source, severity: int(hard_critical_source(source, severity)))
        with con:
            yield con
    finally:
        con.close()


def setup_db(cfg: Config) -> int:
    """Create only telegram_* objects; snapshot high-watermark to avoid backlog."""
    with db_connect(cfg) as con:
        if not con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='incidents'").fetchone():
            raise RuntimeError('No existe la tabla incidents')
        con.execute('''CREATE TABLE IF NOT EXISTS telegram_state (
            key TEXT PRIMARY KEY, value TEXT NOT NULL)''')
        con.execute('''CREATE TABLE IF NOT EXISTS telegram_deliveries (
            incident_id INTEGER PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_ts INTEGER NOT NULL DEFAULT 0,
            sent_ts INTEGER,
            last_error TEXT NOT NULL DEFAULT ''
        )''')
        con.execute('''CREATE TABLE IF NOT EXISTS telegram_cooldowns (
            group_key TEXT PRIMARY KEY,
            last_sent_ts INTEGER NOT NULL
        )''')
        seen = con.execute("SELECT value FROM telegram_state WHERE key='last_seen_id'").fetchone()
        if seen is None:
            latest = con.execute('SELECT COALESCE(MAX(id), 0) FROM incidents').fetchone()[0]
            con.execute("INSERT INTO telegram_state(key, value) VALUES('last_seen_id', ?)", (str(latest),))
            LOG.info('Inicializado desde incidente #%s: sin envíos retrospectivos', latest)
            return latest
        return int(seen[0])


def scan_new(cfg: Config) -> int:
    queued = 0
    with db_connect(cfg) as con:
        state = con.execute("SELECT value FROM telegram_state WHERE key='last_seen_id'").fetchone()
        if state is None:
            raise RuntimeError('Telegram no inicializado; ejecutar primero setup_db')
        rows = con.execute('''SELECT id,source,title,severity,synthetic,analysis
                              FROM incidents WHERE id>? ORDER BY id LIMIT 200''',
                           (int(state[0]),)).fetchall()
        for row in rows:
            if eligible(row):
                cur = con.execute('INSERT OR IGNORE INTO telegram_deliveries(incident_id) VALUES(?)', (row[0],))
                queued += cur.rowcount
        if rows:
            con.execute("UPDATE telegram_state SET value=? WHERE key='last_seen_id'", (str(rows[-1][0]),))
    if queued:
        LOG.info('Alertas Telegram en cola: %s', queued)
    return queued


def bounded(value, limit: int) -> str:
    value = str(value if value is not None else '')
    return ''.join(c for c in value if c in '\n\t' or ord(c) >= 32)[:limit]


def build_text(cfg: Config, incident: tuple) -> str:
    """Escaped Telegram HTML using the shared incident presentation fields."""
    return render_telegram_html(details(incident, cfg.dashboard_url))


class TelegramAPIError(Exception):
    """A scrubbed error that must never contain the bot token or full URL."""


def telegram_send(cfg: Config, message: str) -> None:
    cfg.validate_api()
    payload = json.dumps({'chat_id': cfg.chat_id, 'text': message,
                          'parse_mode': 'HTML',
                          'link_preview_options': {'is_disabled': True}}, ensure_ascii=False).encode('utf-8')
    request = urllib.request.Request(
        f'https://api.telegram.org/bot{cfg.token}/sendMessage',
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.load(response)
    except urllib.error.HTTPError as exc:
        # Never log exc, its URL embeds TELEGRAM_BOT_TOKEN.
        raise TelegramAPIError(f'HTTP_{exc.code}') from None
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
        raise TelegramAPIError(type(exc).__name__) from None
    if not isinstance(data, dict) or data.get('ok') is not True:
        raise TelegramAPIError('API_not_ok')


def send_test(cfg: Config) -> None:
    telegram_send(cfg, '🛡️ Security Triage Bot\n✅ Prueba del canal Telegram correcta.\n🧪 No es una alerta de seguridad.')
    print('Telegram aceptó el mensaje de prueba; comprueba su recepción en el móvil.')


def enqueue_existing(cfg: Config, incident_id: int) -> None:
    with db_connect(cfg) as con:
        row = con.execute('SELECT id,source,title,severity,synthetic,analysis FROM incidents WHERE id=?',
                          (incident_id,)).fetchone()
        if row is None:
            raise ValueError(f'Incidente #{incident_id} inexistente')
        if not eligible(row):
            raise ValueError('Smart Triage no autoriza notificar este incidente')
        cur = con.execute('INSERT OR IGNORE INTO telegram_deliveries(incident_id) VALUES(?)', (incident_id,))
    if cur.rowcount:
        LOG.info('Incidente #%s en cola manual de Telegram', incident_id)
    else:
        LOG.info('Incidente #%s ya en cola o procesado; no se duplica', incident_id)


def send_due(cfg: Config, *, now: int | None = None) -> bool:
    """Process up to one queued delivery. Caller invokes repeatedly.

    Single-worker assumption. Network I/O happens OUTSIDE SQLite transactions.
    Crashes after successful Telegram delivery but before DB commit can duplicate.
    """
    current = int(time.time()) if now is None else now
    with db_connect(cfg) as con:
        # Recover a delivery claimed by a crashed worker (bounded retries still apply).
        con.execute('''UPDATE telegram_deliveries SET status='pending'
                       WHERE status='sending' AND next_attempt_ts<=?''', (current,))
        sent_last_hour = con.execute('''SELECT COUNT(*) FROM telegram_deliveries
              WHERE status='sent' AND sent_ts>=?''', (current - 3600,)).fetchone()[0]
        if sent_last_hour >= cfg.max_per_hour:
            return False
        row = con.execute('''SELECT d.incident_id,i.received_at,i.source,i.title,i.severity,
                  i.synthetic,i.analysis_mode,i.analysis,d.attempts
                  FROM telegram_deliveries d JOIN incidents i ON i.id=d.incident_id
                  WHERE d.status='pending' AND d.next_attempt_ts<=?
                  ORDER BY source_critical(i.source,i.severity) DESC,
                           d.incident_id LIMIT 1''', (current,)).fetchone()
        if row is None:
            return False
        incident_id = row[0]
        if not eligible((row[0], row[2], row[3], row[4], row[5], row[7])):
            con.execute("UPDATE telegram_deliveries SET status='suppressed',last_error='policy' WHERE incident_id=?", (incident_id,))
            LOG.info('Incidente #%s rechazado por la política de triaje', incident_id)
            return True
        analysis = json.loads(row[7])
        group = analysis['triage']['group_key']
        cooldown = con.execute('SELECT last_sent_ts FROM telegram_cooldowns WHERE group_key=?', (group,)).fetchone()
        if (cooldown and current - int(cooldown[0]) < cfg.cooldown_seconds
                and not hard_critical_source(row[2], row[4])):
            con.execute("UPDATE telegram_deliveries SET status='suppressed',last_error='cooldown' WHERE incident_id=?", (incident_id,))
            LOG.info('Incidente #%s retenido por cooldown de grupo', incident_id)
            return True
        # Lease for crash recovery. Other worker must not be running concurrently.
        con.execute("UPDATE telegram_deliveries SET status='sending',next_attempt_ts=? WHERE incident_id=?",
                    (current + 120, incident_id))
    try:
        telegram_send(cfg, build_text(cfg, row[:8]))
    except (TelegramAPIError, ValueError, TypeError, json.JSONDecodeError) as exc:
        attempts = row[8] + 1
        status = 'failed' if attempts >= cfg.max_retries else 'pending'
        delay = min(3600, 20 * (2 ** (attempts - 1)))
        with db_connect(cfg) as con:
            con.execute('''UPDATE telegram_deliveries
                  SET attempts=?, status=?, next_attempt_ts=?, last_error=? WHERE incident_id=?''',
                        (attempts, status, current + delay, type(exc).__name__, incident_id))
        LOG.warning('Error Telegram incidente #%s: %s, intento %s/%s',
                    incident_id, type(exc).__name__, attempts, cfg.max_retries)
        return False
    with db_connect(cfg) as con:
        con.execute("UPDATE telegram_deliveries SET status='sent',sent_ts=?,attempts=attempts+1,last_error='' WHERE incident_id=?",
                    (int(time.time()) if now is None else current, incident_id))
        con.execute('''INSERT INTO telegram_cooldowns(group_key,last_sent_ts) VALUES(?,?)
                  ON CONFLICT(group_key) DO UPDATE SET last_sent_ts=excluded.last_sent_ts''',
                    (group, int(time.time()) if now is None else current))
    LOG.info('Mensaje aceptado por Telegram para incidente #%s', incident_id)
    return True


def print_status(cfg: Config) -> None:
    with db_connect(cfg) as con:
        exists = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='telegram_state'").fetchone()
        if not exists:
            print('Telegram sin inicializar; ningún incidente enviado')
            return
        watermark = con.execute("SELECT value FROM telegram_state WHERE key='last_seen_id'").fetchone()
        states = con.execute('SELECT status, COUNT(*) FROM telegram_deliveries GROUP BY status').fetchall()
    print('Último incidente inspeccionado:', watermark[0] if watermark else 'sin inicializar')
    print('Estado de Telegram:', dict(states))


def preview(cfg: Config) -> None:
    with db_connect(cfg) as con:
        rows = con.execute('''SELECT id,source,title,severity,synthetic,analysis
                              FROM incidents ORDER BY id DESC LIMIT 12''').fetchall()
    print('VISTA PREVIA TELEGRAM — no se envió ningún mensaje')
    for row in rows:
        try:
            triage = (json.loads(row[5]).get('triage') or {})
            if not isinstance(triage, dict):
                triage = {}
        except (ValueError, TypeError, AttributeError):
            triage = {}
        reason = bounded(triage.get('reason', 'Sin política Smart Triage (legacy)'), 120)
        print(f'#{row[0]} [{row[1]}] {bounded(row[2], 52)} -> '
              f'{"ENVIAR" if eligible(row) else "NO ENVIAR"}; '
              f'{triage.get("decision", "legacy")}; {reason}')


def main() -> int:
    parser = argparse.ArgumentParser(description='Notificador Telegram independiente, con Smart Triage')
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--test', action='store_true', help='Mensaje de prueba sin incidentes')
    actions.add_argument('--preview', action='store_true', help='Muestra decisiones sin enviar')
    actions.add_argument('--status', action='store_true', help='Ver estado sin crear tablas')
    actions.add_argument('--send-incident', type=int, metavar='ID', help='Encola manualmente un incidente elegible')
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
            setup_db(cfg)
            enqueue_existing(cfg, args.send_incident)
            print('Incidente autorizado en cola; el worker activo lo procesará.')
            print_status(cfg)
            return 0
        if not cfg.enabled:
            raise RuntimeError('TELEGRAM_ENABLED no es true; servicio no iniciado')
        cfg.validate_api()
        signal.signal(signal.SIGTERM, stop_handler)
        signal.signal(signal.SIGINT, stop_handler)
        setup_db(cfg)
        LOG.info('Telegram activo: política Smart Triage, cooldown %s min, máximo %s/h',
                 cfg.cooldown_seconds // 60, cfg.max_per_hour)
        while RUNNING:
            scan_new(cfg)
            for _ in range(3):
                if not send_due(cfg):
                    break
            time.sleep(cfg.interval)
        return 0
    except (ValueError, RuntimeError, sqlite3.Error, TelegramAPIError) as exc:
        # Exception details can include sensitive context; never dump traceback or tokens.
        LOG.error('No se pudo continuar: %s', type(exc).__name__)
        return 1


if __name__ == '__main__':
    sys.exit(main())
