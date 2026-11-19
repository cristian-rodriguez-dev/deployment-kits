"""Prometheus read-only enrichment. No AI, notifications or classification changes.

Uses the *observed* target labels (not hostname guesses); if matching is ambiguous,
returns no metrics. All network operations have small bounded timeouts and output.
"""
from __future__ import annotations

import json
import math
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

WINDOW_SECONDS = 15 * 60
STALE_AFTER_SECONDS = 150
MAX_RESPONSE_BYTES = 160_000
MAX_TARGETS = 50
TIMEOUT_SECONDS = 1.5


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _short(value: Any, length=120) -> str:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        return ''
    text = str(value).strip()
    if any(ord(ch) < 32 for ch in text) or len(text) > length:
        return ''
    return text


def _number(value: Any) -> float | None:
    try:
        result = float(value)
        return result if math.isfinite(result) else None
    except (TypeError, ValueError, OverflowError):
        return None


def _valid_url(url: str) -> str:
    if not isinstance(url, str) or len(url) > 180:
        raise ValueError('Invalid PROMETHEUS_URL')
    parsed = urllib.parse.urlsplit(url.strip())
    if (parsed.scheme not in {'http', 'https'} or not parsed.hostname or
            parsed.username or parsed.password or parsed.query or parsed.fragment or
            parsed.path not in {'', '/'} or parsed.port is not None and not 1 <= parsed.port <= 65535):
        raise ValueError('Invalid PROMETHEUS_URL')
    return url.strip().rstrip('/')


def _api(base: str, endpoint: str, params: dict, *, timeout=TIMEOUT_SECONDS) -> list[dict]:
    address = _valid_url(base) + endpoint + '?' + urllib.parse.urlencode(params)
    request = urllib.request.Request(address, headers={'Accept': 'application/json'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError('Prometheus response oversized')
    parsed = json.loads(raw)
    if not isinstance(parsed, dict) or parsed.get('status') != 'success':
        raise ValueError('Prometheus unsuccessful response')
    data = parsed.get('data')
    if not isinstance(data, dict):
        raise ValueError('Prometheus data missing')
    expected = 'vector' if endpoint.endswith('query') else 'matrix'
    if data.get('resultType') != expected:
        raise ValueError('Prometheus result type unexpected')
    result = data.get('result')
    if not isinstance(result, list) or len(result) > MAX_TARGETS:
        raise ValueError('Prometheus result oversized')
    return result


def _instant(base: str, expression: str, at: int) -> list[dict]:
    return _api(base, '/api/v1/query', {'query': expression, 'time': at})


def _range(base: str, expression: str, start: int, end: int) -> list[dict]:
    return _api(base, '/api/v1/query_range', {
        'query': expression, 'start': start, 'end': end, 'step': 60,
    })


def _match_labels(labels: dict, asset: dict) -> bool:
    if not isinstance(labels, dict) or not isinstance(asset, dict):
        return False
    host = _short(asset.get('name'), 100)
    instance = _short(asset.get('instance'), 120)
    job = _short(asset.get('job'), 100)
    department = _short(asset.get('department'), 80)
    # At least one real exact reference. Ignore bare Wazuh numeric agent IDs.
    if not instance and (not host or host.isdecimal()):
        return False
    # Never let host 'Servidor-Principal' match the arbitrary first service.
    if host and labels.get('nodename') and labels['nodename'].casefold() != host.casefold():
        return False
    if instance and labels.get('instance') != instance:
        return False
    if job and labels.get('job') != job:
        return False
    if department and labels.get('departamento') and labels['departamento'].casefold() != department.casefold():
        return False
    # Require a matching primary identity (name label OR instance), not just job.
    return bool((host and labels.get('nodename', '').casefold() == host.casefold()) or
                (instance and labels.get('instance') == instance))


def _metric_selector(labels: dict) -> str:
    # Values are JSON-escaped to prevent PromQL label-selector injection.
    return ','.join(f'{key}={json.dumps(labels[key], ensure_ascii=True)}'
                    for key in ('instance', 'job'))


def _sample(values: Any, now: int, state: str) -> dict | None:
    if not isinstance(values, list):
        return None
    for item in reversed(values[-20:]):
        if not isinstance(item, list) or len(item) != 2:
            continue
        ts = _number(item[0]); val = _number(item[1])
        if ts is None or val is None or not now - WINDOW_SECONDS - 2 <= ts <= now + 2:
            continue
        if not -0.1 <= val <= 100.1:
            continue
        return {'value_percent': round(min(100, max(0, val)), 1),
                'point_time_utc': _iso(ts),
                'age_seconds': max(0, int(now - ts)),
                'reading_type': 'recent' if state == 'up' and now - ts <= STALE_AFTER_SECONDS
                else 'historical_or_stale'}
    return None


def _empty(status: str, now: int, *, note: str = '') -> dict:
    result = {'version': 'prometheus-readonly-v1', 'status': status,
              'scope': 'verified_exact_target', 'checked_at_utc': _iso(now),
              'window_minutes': WINDOW_SECONDS // 60,
              'changes_security_decision': False}
    if note:
        result['note'] = note
    return result


def collect(asset: dict | None, base_url: str, *, now: int | None = None) -> dict:
    """Best effort; no exceptions escape to caller. Never queries user-supplied URLs."""
    now = int(time.time()) if now is None else now
    if not isinstance(asset, dict):
        return _empty('no_identity', now)
    try:
        base = _valid_url(base_url)
        targets = _instant(base, 'up', now)
        matches = []
        for series in targets:
            labels = series.get('metric') if isinstance(series, dict) else None
            if _match_labels(labels, asset):
                matches.append(series)
        if not matches:
            return _empty('no_match', now, note='Sin target con identidad coincidente')
        if len(matches) != 1:
            return _empty('ambiguous', now, note='Varios targets compatibles; no atribuir métricas')

        target = matches[0]
        labels = target['metric']
        sample = target.get('value')
        timestamp = _number(sample[0]) if isinstance(sample, list) and len(sample) == 2 else None
        up_value = _number(sample[1]) if isinstance(sample, list) and len(sample) == 2 else None
        # Prometheus /query timestamps are evaluation timestamps, NOT raw scrape
        # timestamps. Never infer source freshness from this number.
        state = ('up' if up_value == 1 else 'down' if up_value == 0 else 'unknown')
        result = _empty('ok', now)
        result['target'] = {key: _short(labels.get(key), 120) for key in
                            ('nodename', 'departamento', 'instance', 'job')}
        result['availability'] = {
            'state': state,
            'evaluated_at_utc': _iso(timestamp) if timestamp is not None else None,
            'raw_sample_freshness': 'not_verified',
            'interpretation': ('No se pudo recopilar la métrica del target' if state == 'down'
                               else 'Target con métricas disponibles' if state == 'up'
                               else 'No se dispone de un estado suficientemente reciente'),
        }
        selectors = _metric_selector(labels)
        cpu = f'100 * (1 - avg by(instance,job) (rate(node_cpu_seconds_total{{{selectors},mode="idle"}}[5m])))'
        mem = (f'100 * (1 - node_memory_MemAvailable_bytes{{{selectors}}} / '
               f'node_memory_MemTotal_bytes{{{selectors}}})')
        disk = (f'100 * (1 - node_filesystem_avail_bytes{{{selectors},mountpoint="/"}} / '
                f'node_filesystem_size_bytes{{{selectors},mountpoint="/"}})')
        metrics = {}
        for name, expr in [('cpu', cpu), ('ram', mem), ('disk_root', disk)]:
            try:
                rows = _range(base, expr, now - WINDOW_SECONDS, now)
                # Never silently choose a filesystem or host from multiple series.
                if len(rows) != 1 or not isinstance(rows[0], dict):
                    continue
                sample_value = _sample(rows[0].get('values'), now, state)
                if sample_value:
                    metrics[name] = sample_value
            except (OSError, ValueError, TypeError, TimeoutError):
                continue
        result['metrics'] = metrics
        result['metric_caveat'] = ('Lecturas Prometheus en una ventana de 15 minutos. '
                                   'Las métricas históricas no demuestran el estado actual '
                                   'ni la causa de la incidencia.')
        return result
    except (OSError, ValueError, TypeError, TimeoutError):
        return _empty('unavailable', now, note='Prometheus no disponible o respuesta inválida')
