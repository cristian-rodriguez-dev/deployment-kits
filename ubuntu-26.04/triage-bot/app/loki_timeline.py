"""Read-only Loki incident timeline with three exact, non-overlapping 5m windows.

One instant LogQL query uses offsets 10m, 5m and 0m at the *actual* incident
anchor. No query_range step rounding, raw log lines, model input or triage change.
"""
from __future__ import annotations

import json
import math
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from app.loki_enrichment import _identity, _base_url

MAX_REPLY_BYTES = 80_000
MAX_GROUPS = 25
MAX_TOTAL = 100_000
TIMEOUT_SECONDS = 2.5
WINDOW_SECONDS = 300
BUCKETS = 3


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def _anchor(event_timestamp: str | None, received: int) -> tuple[int, str]:
    if isinstance(event_timestamp, str) and len(event_timestamp) <= 64:
        try:
            parsed = datetime.fromisoformat(event_timestamp.strip().replace('Z', '+00:00'))
            if parsed.tzinfo is not None:
                epoch = int(parsed.timestamp())
                if received - 3600 <= epoch <= received + 60:
                    return min(epoch, received), 'event_time'
        except (ValueError, OverflowError, OSError):
            pass
    return received, 'reception_time'


def _base(status: str, received: int, *, anchor: int | None = None,
          anchor_type: str = 'reception_time') -> dict:
    return {
        'version': 'loki-temporal-readonly-v1.1', 'status': status,
        'scope': 'exact_host_department', 'anchor_type': anchor_type,
        'anchor_utc': _iso(anchor if anchor is not None else received),
        'checked_at_utc': _iso(received), 'window_minutes': 15,
        'bucket_minutes': 5, 'excludes_collector_health': True,
        'log_lines_stored': False, 'sent_to_ai': False,
        'changes_triage': False,
    }


def _build_query(selector: dict) -> str:
    """One vector at exact anchor; offsets partition preceding 15 minutes."""
    matchers = '{' + ','.join(
        f'{key}={json.dumps(value, ensure_ascii=True)}'
        for key, value in selector.items()
    ) + ',unit!="alloy.service"}'
    expressions = []
    for idx, minutes in enumerate((10, 5, 0)):
        offset = f' offset {minutes}m' if minutes else ''
        aggregation = (f'sum by (unit,source) '
                       f'(count_over_time({matchers}[5m]{offset}))')
        expressions.append(
            f'label_replace({aggregation}, "triage_bucket", "{idx}", '
            '"unit", ".*")'
        )
    return ' or '.join(expressions)


def _parse_vector(payload: Any, selector: dict, anchor: int) -> tuple[list[int], list[dict]]:
    if not isinstance(payload, dict) or payload.get('status') != 'success':
        raise ValueError('Loki API status failed')
    data = payload.get('data')
    if not isinstance(data, dict) or data.get('resultType') != 'vector':
        raise ValueError('Loki instant vector required')
    series = data.get('result')
    if not isinstance(series, list) or len(series) > MAX_GROUPS * BUCKETS:
        raise ValueError('Loki result size exceeded')

    totals = [0] * BUCKETS
    groups: dict[tuple[str, str], list[int]] = {}
    seen = set()
    for item in series:
        if not isinstance(item, dict):
            raise ValueError('Malformed Loki sample')
        labels, sample = item.get('metric'), item.get('value')
        if not isinstance(labels, dict) or not isinstance(sample, list) or len(sample) != 2:
            raise ValueError('Malformed Loki metric')
        for name, expected in selector.items():
            if name in labels and labels[name] != expected:
                raise ValueError('Unexpected asset labels')

        bucket = labels.get('triage_bucket')
        if bucket not in ('0', '1', '2'):
            raise ValueError('Missing or invalid bucket label')
        idx = int(bucket)
        unit, source = labels.get('unit', ''), labels.get('source', '')
        if not isinstance(unit, str) or len(unit) > 100 or any(ord(x) < 32 for x in unit):
            unit = 'sin_unidad'
        if not isinstance(source, str) or len(source) > 50 or any(ord(x) < 32 for x in source):
            source = 'no_disponible'
        if unit == 'alloy.service':
            raise ValueError('Collector logs not excluded')
        key = (unit or 'sin_unidad', source or 'no_disponible')
        if (key, idx) in seen:
            raise ValueError('Repeated group/bucket')
        seen.add((key, idx))

        try:
            timestamp = float(sample[0])
            count = float(sample[1])
        except (ValueError, OverflowError, TypeError) as exc:
            raise ValueError('Invalid Loki numeric value') from exc
        if not math.isfinite(timestamp) or abs(timestamp - anchor) > 1.5:
            raise ValueError('Loki instant timestamp differs from event anchor')
        if not math.isfinite(count) or count < 0 or count > MAX_TOTAL or not count.is_integer():
            raise ValueError('Invalid Loki event count')

        if key not in groups and len(groups) >= MAX_GROUPS:
            raise ValueError('Too many Loki groups')
        counts = groups.setdefault(key, [0] * BUCKETS)
        counts[idx] = int(count)
        totals[idx] += int(count)
        if sum(totals) > MAX_TOTAL:
            raise ValueError('Too many events')

    by_unit = [
        {'unit': unit, 'source': source, 'counts': counts}
        for (unit, source), counts in groups.items() if any(counts)
    ]
    by_unit.sort(key=lambda x: (-sum(x['counts']), x['unit'], x['source']))
    return totals, by_unit


def collect(asset: dict | None, base_url: str, *, event_timestamp: str | None = None,
            now: int | None = None) -> dict:
    """Three exact 5m intervals; failures do not block incident processing."""
    received = int(time.time()) if now is None else int(now)
    anchor, anchor_type = _anchor(event_timestamp, received)
    identity = _identity(asset)
    if identity is None:
        return _base('no_verified_identity', received, anchor=anchor,
                     anchor_type=anchor_type)
    try:
        base = _base_url(base_url)
        query = _build_query(identity)
        url = base + '/loki/api/v1/query?' + urllib.parse.urlencode({
            'query': query,
            'time': str(anchor * 1_000_000_000),
        })
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_REPLY_BYTES + 1)
        if len(raw) > MAX_REPLY_BYTES:
            raise ValueError('Loki response too large')
        totals, groups = _parse_vector(json.loads(raw), identity, anchor)
        out = _base('ok' if any(totals) else 'no_logs', received,
                    anchor=anchor, anchor_type=anchor_type)
        ticks = [anchor - 600, anchor - 300, anchor]
        out.update({
            'selector': identity,
            'buckets': [
                {'start_utc': _iso(t - WINDOW_SECONDS),
                 'end_utc': _iso(t), 'entries': n}
                for t, n in zip(ticks, totals)
            ],
            'observed_entries_15m': sum(totals),
            'by_unit_source': groups,
            'interpretation': ('Tres ventanas de 5m consecutivas, sin solapamiento, '
                               'evaluadas exactamente en la fecha de evento o recepción. '
                               'Recuento de actividad, no atribución causal.'),
        })
        return out
    except (ValueError, TypeError, OSError, TimeoutError, UnicodeError):
        return _base('unavailable', received, anchor=anchor, anchor_type=anchor_type)
