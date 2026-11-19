"""Bounded, webhook-native Wazuh metadata. No network calls or raw logs.

This is NOT an Indexer aggregation or an online agent-status check.
"""
from __future__ import annotations
import re
from typing import Any

VERSION = 'wazuh-webhook-metadata-v1'
RULE_PATTERN = re.compile(r'[0-9]{1,6}\Z')
AGENT_PATTERN = re.compile(r'[0-9]{3,6}\Z')
GROUP_PATTERN = re.compile(r'[a-zA-Z0-9_-]{1,40}\Z')
MITRE_PATTERN = re.compile(r'T[0-9]{4}(?:\.[0-9]{3})?\Z')
# A small safe vocabulary; unknown groups never enter Gemini. The stored
# webhook-derived groups are separately sanitized and displayed as metadata.
AI_GROUPS = frozenset({
    'sshd', 'ssh', 'authentication_failed', 'authentication_success',
    'invalid_login', 'authentication_failures', 'bruteforce', 'attack',
    'syscheck', 'syslog', 'sca', 'rootcheck', 'fim', 'firewall',
    'iptables', 'pam', 'systemd', 'cron', 'sudo', 'active_response',
    'vulnerability-detector', 'policy', 'compliance', 'web', 'apache',
    'nginx', 'authentication', 'login_denied', 'mitre',
})


def _numeric(value: Any, matcher: re.Pattern) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return ''
    text = str(value)
    return text if matcher.fullmatch(text) else ''


def _groups(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out = []
    for item in value[:25]:
        if isinstance(item, str) and GROUP_PATTERN.fullmatch(item) and item not in out:
            out.append(item)
            if len(out) == 8:
                break
    return out


def _mitre(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    ids = value.get('id')
    if isinstance(ids, str):
        ids = [ids]
    if not isinstance(ids, list):
        return []
    out = []
    for item in ids[:20]:
        if isinstance(item, str) and MITRE_PATTERN.fullmatch(item) and item not in out:
            out.append(item)
            if len(out) == 8:
                break
    return out


def collect(rule: dict, agent: dict, asset: dict, recent_same_rule_host: int) -> dict:
    """Accept only a validated webhook's limited metadata and verified asset.

    recent_same_rule_host is from existing bot SQLite triage_context: one count
    per unique incident, not an exhaustive count of Wazuh or sshd events.
    """
    base = {
        'version': VERSION,
        'status': 'unavailable',
        'source': 'authenticated_wazuh_webhook',
        'changes_triage': False,
        'raw_log_lines_stored': False,
        'agent_live_status': 'not_queried',
        'indexer_alert_totals': 'not_queried',
        'sent_to_ai': False,
    }
    if not all(isinstance(obj, dict) for obj in (rule, agent, asset)):
        return base
    agent_id = _numeric(agent.get('id'), AGENT_PATTERN)
    rule_id = _numeric(rule.get('id'), RULE_PATTERN)
    try:
        level = int(rule.get('level')) if not isinstance(rule.get('level'), bool) else -1
    except (ValueError, TypeError, OverflowError):
        level = -1
    if (not agent_id or not rule_id or not 0 <= level <= 16
            or _numeric(asset.get('agent_id'), AGENT_PATTERN) != agent_id
            or _numeric(asset.get('rule_id'), RULE_PATTERN) != rule_id
            or not isinstance(recent_same_rule_host, int)
            or isinstance(recent_same_rule_host, bool)
            or not 0 <= recent_same_rule_host <= 100_000):
        return base
    # Trust the inventory-backed asset mapping for display/scope. The incoming
    # webhook might not contain department or job; do not guess it.
    host = asset.get('name')
    if not isinstance(host, str) or not 1 <= len(host) <= 120:
        return base
    return {
        **base, 'status': 'ok',
        'scope': 'exact_agent_rule_webhook',
        'selector': {
            'agent_id': agent_id, 'rule_id': rule_id,
            'host': host,
            'department': asset.get('department') if isinstance(asset.get('department'), str) else '',
        },
        'rule_level': level,
        'rule_groups': _groups(rule.get('groups')),
        'mitre_technique_ids': _mitre(rule.get('mitre')),
        'bot_incidents_same_host_rule_30m_including_current': recent_same_rule_host + 1,
        'frequency_scope': 'unique_incidents_received_by_this_bot_only',
        'window_minutes': 30,
    }


def sanitized_facts(context: dict | None, asset: dict | None) -> dict | None:
    """Strict, identifier-free facts for the existing advisory Gemini call."""
    if (not isinstance(context, dict) or not isinstance(asset, dict)
            or context.get('version') != VERSION
            or context.get('status') != 'ok'
            or context.get('source') != 'authenticated_wazuh_webhook'
            or context.get('scope') != 'exact_agent_rule_webhook'
            or context.get('changes_triage') is not False
            or context.get('raw_log_lines_stored') is not False
            or context.get('agent_live_status') != 'not_queried'
            or context.get('indexer_alert_totals') != 'not_queried'
            or context.get('frequency_scope') != 'unique_incidents_received_by_this_bot_only'
            or context.get('window_minutes') != 30):
        return None
    scope = context.get('selector')
    if not isinstance(scope, dict):
        return None
    if any(scope.get(a) != asset.get(b) for a, b in (
            ('host', 'name'), ('department', 'department'),
            ('agent_id', 'agent_id'), ('rule_id', 'rule_id'))):
        return None
    if (not _numeric(scope.get('agent_id'), AGENT_PATTERN)
            or not _numeric(scope.get('rule_id'), RULE_PATTERN)):
        return None
    level = context.get('rule_level')
    count = context.get('bot_incidents_same_host_rule_30m_including_current')
    groups = context.get('rule_groups')
    mitre = context.get('mitre_technique_ids')
    if (type(level) is not int or not 0 <= level <= 16
            or type(count) is not int or not 1 <= count <= 100_001
            or not isinstance(groups, list) or len(groups) > 8
            or not isinstance(mitre, list) or len(mitre) > 8
            or any(not isinstance(g, str) or not GROUP_PATTERN.fullmatch(g) for g in groups)
            or any(not isinstance(i, str) or not MITRE_PATTERN.fullmatch(i) for i in mitre)):
        return None
    return {
        'collector': 'wazuh_webhook',
        'rule_level': level,
        'rule_categories': sorted({g for g in groups if g in AI_GROUPS}),
        'mitre_technique_ids': sorted(set(mitre)),
        'bot_incidents_same_host_rule_30m': count,
        'limitations': (
            'The count covers unique events accepted by this bot only, not all '
            'Wazuh alerts or SSH attempts. The agent live status has not been '
            'queried. Rule groups and MITRE mappings are alert metadata, not '
            'evidence that an attack succeeded, or that Active Response ran.'
        ),
    }
