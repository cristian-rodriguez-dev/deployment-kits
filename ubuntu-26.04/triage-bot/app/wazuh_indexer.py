"""Read-only, aggregate-only Wazuh Indexer enrichment.

Hardcoded endpoint, validated agent+rule from authenticated webhook AND asset,
explicit CA/hostname TLS verification, no document hits and no raw alerts.
This data is advisory, not fed to Gemini or Smart Triage.
"""
from __future__ import annotations

import base64
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = 'wazuh-indexer-aggregate-v2'
AGENT_RE = re.compile(r'\d{3,6}\Z')
RULE_RE = re.compile(r'\d{1,6}\Z')
USERNAME_RE = re.compile(r'[a-zA-Z0-9_\-]{1,64}\Z')
URL = 'https://wazuh.indexer:9200'
PASSWORD_FILE = '/run/secrets/wazuh_indexer_password'
CA_FILE = '/run/secrets/wazuh_indexer_ca.pem'
TIMEOUT = 3.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


MAX_RESPONSE_BYTES = 96_000


def _identifier(value: Any, pattern: re.Pattern) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return ''
    value = str(value)
    return value if pattern.fullmatch(value) else ''


def _utc(seconds: int) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec='seconds')


def _safe_count(value: Any, limit: int = 100_000_000) -> int:
    if type(value) is not int or value < 0 or value > limit:
        raise ValueError('Invalid aggregate count')
    return value


def _make_query(agent_id: str, rule_id: str, now: int) -> dict:
    # Time window anchored to receipt, never interpreted as event-time evidence.
    return {
        'size': 0,
        'track_total_hits': True,
        'timeout': '2s',
        'query': {'bool': {'filter': [
            {'term': {'agent.id': agent_id}},
            {'range': {'timestamp': {'gte': _utc(now - 900), 'lte': _utc(now)}}},
        ]}},
        'aggs': {
            'same_rule': {'filter': {'term': {'rule.id': rule_id}}},
            'rules': {'terms': {'field': 'rule.id', 'size': 8}},
            'levels': {'terms': {'field': 'rule.level', 'size': 8}},
        },
    }


def _base() -> dict:
    return {
        'version': VERSION, 'status': 'unavailable',
        'source': 'wazuh_indexer_aggregations',
        'scope': 'agent_id_received_last_15m',
        'window_minutes': 15,
        'changes_triage': False,
        'raw_alerts_stored': False,
        'raw_alerts_sent_to_ai': False,
        'sent_to_ai': False,
        'agent_live_status': 'not_queried',
    }


def collect(agent: dict, rule: dict, asset: dict, *,
            username: str, password_file: str = PASSWORD_FILE,
            ca_file: str = CA_FILE, url: str = URL,
            now: int | None = None, opener=None) -> dict:
    """Query one 15-minute agent-scoped window; return only sanitized counts.

    Bad config, authentication, timeout, unexpected or partial responses fail closed
    into 'unavailable', never return raw URLs/credentials/exception text.
    """
    base = _base()
    if not all(isinstance(x, dict) for x in (agent, rule, asset)):
        return base
    agent_id = _identifier(agent.get('id'), AGENT_RE)
    rule_id = _identifier(rule.get('id'), RULE_RE)
    if (not agent_id or not rule_id
            or agent_id != _identifier(asset.get('agent_id'), AGENT_RE)
            or rule_id != _identifier(asset.get('rule_id'), RULE_RE)):
        return base
    if now is None:
        import time
        now = int(time.time())
    if type(now) is not int or not 1_600_000_000 <= now <= 4_000_000_000:
        return base
    if (url != URL or not isinstance(username, str)
            or not USERNAME_RE.fullmatch(username)
            or not isinstance(password_file, str) or not password_file.startswith('/')
            or not isinstance(ca_file, str) or not ca_file.startswith('/')):
        return base
    try:
        password = Path(password_file).read_text(encoding='utf-8')
        if not 12 <= len(password) <= 512 or '\n' in password or '\r' in password:
            return base
        context = ssl.create_default_context(cafile=ca_file)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        credentials = base64.b64encode(f'{username}:{password}'.encode()).decode('ascii')
        request = urllib.request.Request(
            URL + '/wazuh-alerts-*/_search',
            data=json.dumps(_make_query(agent_id, rule_id, now), separators=(',', ':')).encode(),
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Basic ' + credentials,
            }, method='POST',
        )
        credentials = ''
        # The hostname must resolve to the configured gateway. Never follow redirects.
        client = opener or urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context),
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
        )
        with client.open(request, timeout=TIMEOUT) as response:
            if response.status != 200:
                return base
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            return base
        payload = json.loads(raw)
        if not isinstance(payload, dict) or payload.get('timed_out') is not False:
            return base
        shards = payload.get('_shards')
        if (not isinstance(shards, dict)
                or type(shards.get('failed')) is not int or shards['failed'] != 0
                or type(shards.get('successful')) is not int or shards['successful'] < 1):
            return base
        hits = payload.get('hits')
        if not isinstance(hits, dict):
            return base
        total_info = hits.get('total')
        if (not isinstance(total_info, dict)
                or total_info.get('relation') != 'eq'):
            return base
        total = _safe_count(total_info.get('value'))
        aggs = payload.get('aggregations')
        if not isinstance(aggs, dict):
            return base
        same_rule_data = aggs.get('same_rule')
        if not isinstance(same_rule_data, dict):
            return base
        same_rule = _safe_count(same_rule_data.get('doc_count'))
        if same_rule > total:
            return base
        groups = {}
        for label, pattern in (('rules', RULE_RE), ('levels', re.compile(r'\d{1,2}\Z'))):
            item = aggs.get(label)
            if not isinstance(item, dict) or not isinstance(item.get('buckets'), list):
                return base
            rows = item['buckets']
            if len(rows) > 8:
                return base
            safe = []
            for row in rows:
                if not isinstance(row, dict):
                    return base
                key = _identifier(row.get('key_as_string', row.get('key')), pattern)
                count = _safe_count(row.get('doc_count'))
                if not key or count > total:
                    return base
                safe.append({'id' if label == 'rules' else 'level': key, 'count': count})
            groups[label] = safe
        return {
            **base,
            'status': 'ok' if total else 'no_alerts',
            'agent_id': agent_id,
            'rule_id': rule_id,
            'time_window_utc': {'start': _utc(now - 900), 'end': _utc(now)},
            'total_alerts_agent_15m': total,
            'alerts_same_rule_agent_15m': same_rule,
            'top_rules': groups['rules'],
            'top_levels': groups['levels'],
            'frequency_scope': 'wazuh_indexer_agent_scoped_alert_documents',
        }
    except (OSError, ValueError, UnicodeError, TypeError, KeyError,
            json.JSONDecodeError, ssl.SSLError, urllib.error.URLError):
        return base
