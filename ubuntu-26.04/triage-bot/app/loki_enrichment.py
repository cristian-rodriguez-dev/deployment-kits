"""Aggregate-only, read-only Loki enrichment for a single verified host.

Never retrieves or stores original log messages; never sends logs to Gemini.
Never changes Smart Triage or notifications. Optional and fail-closed.
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

WINDOW_SECONDS = 15 * 60
MAX_RESPONSE_BYTES = 80_000
MAX_GROUPS = 25
TIMEOUT_SECONDS = 2.5
_HOST_RE = re.compile(r'^[A-Za-z0-9_.-]{2,100}$')
_DEPT_RE = re.compile(r'^[A-Za-z0-9À-ÿ_. -]{2,80}$')
_INV_RE = re.compile(r'^inventario-[A-Za-z0-9_.-]{1,80}$')


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _empty(status: str, now: int) -> dict:
    return {
        'version': 'loki-aggregate-readonly-v1',
        'status': status,
        'scope': 'exact_host_department',
        'checked_at_utc': _iso(now),
        'window_minutes': 15,
        'changes_security_decision': False,
        'log_lines_stored': False,
        'sent_to_ai': False,
    }


def _identity(asset: Any) -> dict | None:
    if not isinstance(asset, dict):
        return None
    host = asset.get('name')
    department = asset.get('department')
    if not isinstance(host, str) or not isinstance(department, str):
        return None
    host, department = host.strip(), department.strip()
    if not _HOST_RE.fullmatch(host) or host.isdecimal() or not _DEPT_RE.fullmatch(department):
        return None
    if department.casefold() in ('sin asignar', 'unknown', 'n/d', 'desconocido'):
        return None
    try:
        ipaddress.ip_address(host)
        return None  # IP alone is not verified as the Loki host label
    except ValueError:
        pass
    selector = {'host': host, 'departamento': department}
    job = asset.get('job')
    # Include the inventory label only when the actual inventory namespace is known.
    # Otherwise filter by the two exact labels, never broaden to all departments.
    if isinstance(job, str) and _INV_RE.fullmatch(job.strip()):
        selector['inventario'] = job.strip()
    return selector


def _base_url(base: Any) -> str:
    if not isinstance(base, str) or len(base) > 200:
        raise ValueError('invalid Loki URL')
    split = urllib.parse.urlsplit(base.strip())
    if (split.scheme not in ('http', 'https') or not split.hostname or split.username or
        split.password or split.query or split.fragment or split.path not in ('', '/') or
        (split.port is not None and not 1 <= split.port <= 65535)):
        raise ValueError('invalid Loki URL')
    # Only privately reachable services are acceptable in this lab.
    try:
        ip = ipaddress.ip_address(split.hostname)
    except ValueError as exc:
        raise ValueError('Loki URL must use a private IP') from exc
    if not ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        raise ValueError('Loki URL must use a private IP')
    return base.strip().rstrip('/')


def _parse_vector(payload: Any, selector: dict) -> tuple[int, list]:
    if not isinstance(payload, dict) or payload.get('status') != 'success':
        raise ValueError('Loki API status')
    data = payload.get('data')
    if not isinstance(data, dict) or data.get('resultType') != 'vector':
        raise ValueError('Loki vector required')
    items = data.get('result')
    if not isinstance(items, list) or len(items) > MAX_GROUPS:
        raise ValueError('Loki result too large')
    total, groups = 0, []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('bad Loki result')
        labels = item.get('metric')
        sample = item.get('value')
        if not isinstance(labels, dict) or not isinstance(sample, list) or len(sample) != 2:
            raise ValueError('bad Loki value')
        # The response is untrusted: never count metrics from another host/dept.
        for key, value in selector.items():
            if key in labels and labels[key] != value:
                raise ValueError('Loki returned mismatched source')
        try:
            n = float(sample[1])
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError('bad Loki count') from exc
        if not math.isfinite(n) or n < 0 or n > 100_000 or not n.is_integer():
            raise ValueError('bad Loki count')
        count = int(n)
        if count == 0:
            continue
        unit = labels.get('unit', '')
        source = labels.get('source', '')
        if not isinstance(unit, str) or len(unit) > 100 or any(ord(c) < 32 for c in unit):
            unit = ''
        if not isinstance(source, str) or len(source) > 50 or any(ord(c) < 32 for c in source):
            source = ''
        groups.append({'unit': unit or 'sin_unidad', 'source': source or 'no_disponible', 'entries': count})
        total += count
    return total, sorted(groups, key=lambda x: (-x['entries'], x['unit'], x['source']))


def collect(asset: dict | None, base_url: str, *, now: int | None = None) -> dict:
    """Return aggregate counts only. Capped HTTP, time and response size."""
    now = int(time.time()) if now is None else int(now)
    identity = _identity(asset)
    if not identity:
        return _empty('no_verified_identity', now)
    try:
        base = _base_url(base_url)
        selector = '{' + ','.join(f'{k}={json.dumps(v, ensure_ascii=True)}'
                                  for k, v in identity.items()) + '}'
        expression = f'sum by (unit,source) (count_over_time({selector}[15m]))'
        url = base + '/loki/api/v1/query?' + urllib.parse.urlencode({
            'query': expression, 'time': _iso(now)
        })
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError('Loki payload too large')
        total, groups = _parse_vector(json.loads(raw), identity)
        result = _empty('ok' if total else 'no_logs', now)
        result.update({
            'selector': identity, 'observed_entries_15m': total,
            'by_unit_source': groups,
            'interpretation': 'Recuento de entradas de logs, no prueba de causa ni de severidad',
        })
        return result
    except (ValueError, TypeError, OSError, TimeoutError, UnicodeError):
        return _empty('unavailable', now)
