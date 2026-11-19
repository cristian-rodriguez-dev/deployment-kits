#!/usr/bin/env python3
"""Read-only dashboard bridge for the lab. Not a production identity gateway.

GET /dashboard      : static user interface
GET /api/incidents  : read-only proxy to local security-triage-bot /incidents
All requests require separate Basic authentication; never expose webhook keys.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import error, request

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent
CONFIG_PATH = ROOT / 'auth.json'
DASHBOARD_PATH = ROOT / 'dashboard.html'
BOT_ENV = PROJECT / '.env'
BIND = os.environ.get('TRIAGE_BRIDGE_BIND', '10.42.0.1')
PORT = int(os.environ.get('TRIAGE_BRIDGE_PORT', '18081'))
BACKEND = os.environ.get('TRIAGE_BACKEND', 'http://127.0.0.1:18080')
MAX_BODY = 2_000_000


def load_token():
    for line in BOT_ENV.read_text(encoding='utf-8').splitlines():
        if line.startswith('WEBHOOK_TOKEN='):
            token = line.partition('=')[2].strip().strip('"').strip("'")
            if token:
                return token
    raise RuntimeError('WEBHOOK_TOKEN absent from bot .env')


def authorized(value, config):
    if not value or not value.startswith('Basic '):
        return False
    try:
        decoded = base64.b64decode(value[6:], validate=True).decode('utf-8')
        name, sep, password = decoded.partition(':')
        if not sep:
            return False
        salt = bytes.fromhex(config['salt'])
        calculated = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, int(config['rounds']))
        return hmac.compare_digest(name.encode(), config['username'].encode()) and hmac.compare_digest(calculated, bytes.fromhex(config['digest']))
    except (ValueError, KeyError, TypeError, UnicodeDecodeError, OverflowError):
        return False


class Handler(BaseHTTPRequestHandler):
    server_version = 'TriageReadOnlyBridge/1.0'
    sys_version = ''

    def respond(self, code, body, content_type='text/plain; charset=utf-8', extra=None):
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.split('?', 1)[0] not in ('/dashboard', '/api/incidents'):
            return self.respond(404, b'Not found')
        if not authorized(self.headers.get('Authorization'), self.server.auth):
            return self.respond(401, b'Authentication required', extra={'WWW-Authenticate': 'Basic realm="Security Triage"'})
        if self.path.split('?', 1)[0] == '/dashboard':
            try:
                return self.respond(200, DASHBOARD_PATH.read_bytes(), 'text/html; charset=utf-8')
            except OSError:
                logging.exception('Missing dashboard file')
                return self.respond(503, b'Dashboard unavailable')
        try:
            token = load_token()
            req = request.Request(BACKEND + '/incidents', headers={'Authorization': 'Bearer ' + token})
            with request.urlopen(req, timeout=10) as res:
                body = res.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                return self.respond(502, b'Backend response too large')
            # Ensure the upstream returned JSON; no modification to incident data.
            if not isinstance(json.loads(body), list):
                return self.respond(502, b'Unexpected backend response')
            return self.respond(200, body, 'application/json; charset=utf-8')
        except (error.URLError, error.HTTPError, OSError, ValueError, RuntimeError):
            logging.exception('Could not retrieve incidents')
            return self.respond(502, b'Incidents unavailable')

    def do_POST(self):
        self.respond(405, b'Method not allowed', extra={'Allow': 'GET'})

    def log_message(self, fmt, *args):
        # Do not record Authorization headers or secrets.
        logging.info('%s - %s', self.client_address[0], fmt % args)


def main():
    config = json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
    if not DASHBOARD_PATH.is_file():
        raise RuntimeError('Missing dashboard.html')
    # Fail fast if the bot's token cannot be read by service user.
    load_token()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    server = ThreadingHTTPServer((BIND, PORT), Handler)
    server.auth = config
    logging.info('Read-only bridge listening on %s:%d', BIND, PORT)
    server.serve_forever(poll_interval=0.5)


if __name__ == '__main__':
    main()
