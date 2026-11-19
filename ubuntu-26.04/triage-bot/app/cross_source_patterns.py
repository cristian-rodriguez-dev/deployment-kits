"""Conservative, deterministic cross-source observations for an authenticated Wazuh incident.

Uses ONLY the current incident's already-collected, read-only and validated summaries.
No network, database or AI calls. No notifications, ranking, severity or response changes.
A temporal coincidence, sensor failure or log-count increase never proves causation.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from app.contextual_analysis import sanitized_facts as safe_prometheus
from app.contextual_analysis import sanitized_loki_timeline as safe_loki_timeline
from app.prometheus_enrichment import _match_labels
from app.wazuh_enrichment import sanitized_facts as safe_wazuh

VERSION = 'cross-source-patterns-v1'


def _count(value: Any, ceiling: int = 100_000_000) -> bool:
    return type(value) is int and 0 <= value <= ceiling


def _time(value: Any) -> int | None:
    if not isinstance(value, str) or len(value) > 45:
        return None
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return int(dt.timestamp()) if dt.tzinfo is not None else None
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _indexer_counts(data: Any, asset: dict, now: int) -> dict | None:
    """Validate counts and their exact agent/rule/time scope before cross-source use."""
    if not isinstance(data, dict) or not isinstance(asset, dict):
        return None
    if (data.get('version') != 'wazuh-indexer-aggregate-v2'
            or data.get('status') not in ('ok', 'no_alerts')
            or data.get('source') != 'wazuh_indexer_aggregations'
            or data.get('scope') != 'agent_id_received_last_15m'
            or data.get('frequency_scope') != 'wazuh_indexer_agent_scoped_alert_documents'
            or data.get('window_minutes') != 15
            or data.get('changes_triage') is not False
            or data.get('raw_alerts_stored') is not False
            or data.get('sent_to_ai') is not False
            or data.get('agent_id') != asset.get('agent_id')
            or data.get('rule_id') != asset.get('rule_id')):
        return None
    window = data.get('time_window_utc')
    if not isinstance(window, dict):
        return None
    start = _time(window.get('start'))
    end = _time(window.get('end'))
    if (start is None or end is None or end - start != 900
            or not -60 <= now - end <= 90):
        return None
    total = data.get('total_alerts_agent_15m')
    repeated = data.get('alerts_same_rule_agent_15m')
    if (not _count(total) or not _count(repeated) or repeated > total
            or (data['status'] == 'no_alerts' and total != 0)
            or (data['status'] == 'ok' and total == 0)):
        return None
    rows = data.get('top_rules')
    if not isinstance(rows, list) or len(rows) > 8:
        return None
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            return None
        rule = row.get('id')
        n = row.get('count')
        if (not isinstance(rule, str) or not rule.isascii() or not rule.isdecimal()
                or not 1 <= len(rule) <= 6 or rule in seen or
                not _count(n) or n > total):
            return None
        seen.add(rule)
    return {'total': total, 'same_rule': repeated, 'min_distinct_rules': len(seen)}


def _prometheus(data: Any, asset: dict) -> dict | None:
    if not isinstance(data, dict):
        return None
    if (data.get('version') != 'prometheus-readonly-v1'
            or data.get('changes_security_decision') is not False
            or data.get('window_minutes') != 15):
        return None
    if not _match_labels(data.get('target'), asset):
        return None
    return safe_prometheus(data)


def _jump(values: Any, threshold: int) -> bool:
    # A volume jump is an observation, not a security classification.
    if not isinstance(values, list) or len(values) != 3:
        return False
    if any(not _count(n, 100_000) for n in values):
        return False
    return values[2] >= threshold and values[2] >= 2 * max(values[0], values[1], 1)


def correlate(*, source: str, synthetic: bool, asset: dict | None,
              wazuh_context: dict | None = None,
              wazuh_indexer: dict | None = None,
              telemetry: dict | None = None,
              logs_timeline: dict | None = None,
              now: int) -> dict:
    """Return bounded enums and counts; do not leak identifiers or raw events.

    The webhook is an authenticated incident; we additionally require trusted
    Wazuh metadata matching the inventory asset. Missing data is *unknown*, not
    evidence of no attack. Existing Smart Triage decisions remain untouched.
    """
    result = {
        'version': VERSION,
        'status': 'insufficient_data',
        'scope': 'verified_wazuh_asset_only',
        'sources_validated': [],
        'signals': [],
        'signal_count': 0,
        'temporal_relationship': 'separate_sensor_windows_not_causality',
        'limitations': (
            'Observations only. Wazuh alert counts are not SSH attempts or proof '
            'of compromise. Loki counts are not authentication failures. '
            'Prometheus up=0 is scrape failure, not proof of host shutdown. '
            'No causal relation or automatic remediation is established.'
        ),
        'changes_triage': False,
        'changes_notifications': False,
        'sent_to_ai': False,
        'raw_logs_stored': False,
    }
    if (source != 'wazuh' or synthetic is not False
            or not isinstance(asset, dict) or type(now) is not int
            or now < 1_600_000_000 or not safe_wazuh(wazuh_context, asset)):
        return result

    sources = ['wazuh_webhook']
    signals = []
    counts = _indexer_counts(wazuh_indexer, asset, now)
    if counts is not None:
        sources.append('wazuh_indexer')
        if counts['same_rule'] >= 3:
            signals.append({
                'kind': 'wazuh_rule_repeated_15m',
                'source': 'wazuh_indexer',
                'count': counts['same_rule'], 'window_minutes': 15,
            })
        if counts['min_distinct_rules'] >= 2:
            signals.append({
                'kind': 'wazuh_multiple_rules_observed_15m',
                'source': 'wazuh_indexer',
                'minimum_distinct_rules': counts['min_distinct_rules'],
                'window_minutes': 15,
            })

    prom = _prometheus(telemetry, asset)
    if prom is not None:
        sources.append('prometheus')
        if prom['target_scrape_state'] == 'down':
            signals.append({
                'kind': 'prometheus_scrape_unavailable',
                'source': 'prometheus',
                'observation': 'up_equals_zero',
            })

    timeline = safe_loki_timeline(logs_timeline, asset)
    if timeline is not None:
        sources.append('loki_timeline')
        windows = timeline['window_counts_chronological']
        if _jump(windows, 10):
            signals.append({
                'kind': 'loki_observed_log_volume_increase',
                'source': 'loki_timeline',
                'bucket_minutes': 5,
                'window_counts': list(windows),
                'anchor_type': timeline['anchor_type'],
            })
        ssh_windows = timeline['service_windows'].get('ssh')
        if _jump(ssh_windows, 5):
            signals.append({
                'kind': 'loki_ssh_service_log_volume_increase',
                'source': 'loki_timeline',
                'bucket_minutes': 5,
                'window_counts': list(ssh_windows),
                'anchor_type': timeline['anchor_type'],
            })

    result.update({
        'status': 'ok',
        'sources_validated': sources,
        'signals': signals,
        'signal_count': len(signals),
    })
    return result
