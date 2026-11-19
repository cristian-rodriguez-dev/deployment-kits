"""Verified host metadata from alert labels, Wazuh agent fields or local inventory.

Never infers department from a hostname and never contacts the network.
There is no database migration; metadata lives in analysis.asset JSON.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

DEFAULT_INVENTORY = Path(__file__).with_name('asset_inventory.json')


def field(value: Any, limit: int = 120) -> str:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ''
    s = str(value).strip()
    return ''.join(c for c in s if ord(c) >= 32 and ord(c) not in range(0x202a, 0x202f))[:limit]


def first(*values: Any, limit: int = 120) -> str:
    return next((s for v in values if (s := field(v, limit))), '')


def inventory() -> dict:
    """Optional small local JSON file, empty when absent/invalid; no secret data."""
    path = Path(os.getenv('ASSET_INVENTORY_PATH') or DEFAULT_INVENTORY)
    try:
        if not path.is_file() or path.stat().st_size > 65_536:
            return {}
        data = json.loads(path.read_text(encoding='utf-8'))
        if isinstance(data, dict):
            return data
    except (OSError, ValueError, UnicodeError):
        pass
    return {}


def _lookup(records: Any, key: str) -> dict:
    if not key or not isinstance(records, dict):
        return {}
    # Small lab inventory: allow case differences between Grafana/Wazuh labels.
    match = next((v for k, v in records.items()
                  if isinstance(k, str) and k.casefold() == key.casefold()
                  and isinstance(v, dict)), None)
    return match or {}


def _inventory_matches(inv: dict, host: str, agent_id: str, instance: str) -> tuple[dict, dict]:
    agents = _lookup(inv.get('agents'), agent_id)
    resolved_name = first(host, agents.get('name'))
    hosts = _lookup(inv.get('hosts'), resolved_name)
    if not hosts:
        hosts = _lookup(inv.get('hosts'), instance)
    return agents, hosts


def _enrich(asset: dict, inv: dict | None = None) -> dict:
    inv = inventory() if inv is None else inv
    agents, hosts = _inventory_matches(inv, asset.get('name', ''),
                                       asset.get('agent_id', ''), asset.get('instance', ''))
    observed_name = asset.get('name', '')
    # If the only observed name is instance or numeric agent ID, a verified
    # inventory name is more useful; never override a real observed nodename.
    if observed_name in (asset.get('instance'), asset.get('agent_id')) and hosts.get('name'):
        observed_name = ''
    asset['name'] = first(observed_name, agents.get('name'), hosts.get('name'))
    if not hosts and asset['name']:
        hosts = _lookup(inv.get('hosts'), asset['name'])
    asset['department'] = first(asset.get('department'), agents.get('department'),
                                hosts.get('department'), limit=80)
    asset['job'] = first(asset.get('job'), agents.get('job'), hosts.get('job'), limit=100)
    return asset


def from_grafana(labels: dict | None, annotations: dict | None = None,
                 inventory_data: dict | None = None) -> dict:
    labels = labels if isinstance(labels, dict) else {}
    annotations = annotations if isinstance(annotations, dict) else {}
    asset = {
        'name': first(labels.get('nodename'), labels.get('hostname'), labels.get('host'),
                      annotations.get('nodename'), annotations.get('hostname'),
                      annotations.get('host')),
        'department': first(labels.get('departamento'), labels.get('department'),
                            annotations.get('departamento'), annotations.get('department'), limit=80),
        'instance': first(labels.get('instance'), annotations.get('instance')),
        'job': first(labels.get('job'), annotations.get('job'), limit=100),
        'agent_id': '',
        'rule_id': '',
    }
    if not asset['name']:
        asset['name'] = asset['instance']  # fallback, visibly a monitoring endpoint
    return _enrich(asset, inventory_data)


def from_wazuh(agent: dict | None, rule: dict | None = None,
               inventory_data: dict | None = None) -> dict:
    agent = agent if isinstance(agent, dict) else {}
    rule = rule if isinstance(rule, dict) else {}
    labels = agent.get('labels')
    labels = labels if isinstance(labels, dict) else {}
    asset = {
        'name': first(agent.get('name'), agent.get('hostname')),
        'department': first(labels.get('departamento'), labels.get('department'),
                            agent.get('department'), limit=80),
        'instance': '',  # do not persist Wazuh agent IPs
        'job': '',
        'agent_id': first(agent.get('id'), limit=40),
        'rule_id': first(rule.get('id'), limit=40),
    }
    return _enrich(asset, inventory_data)


def for_incident(source: str, analysis: dict) -> dict:
    """Readable fields for both new and legacy incidents. Never modify DB."""
    asset = analysis.get('asset')
    asset = dict(asset) if isinstance(asset, dict) else {}
    triage = analysis.get('triage')
    triage = triage if isinstance(triage, dict) else {}
    old_host = field(triage.get('host'))
    if not asset.get('name') and old_host and not old_host.startswith('unknown-'):
        if source == 'wazuh' and old_host.isdecimal():
            asset['agent_id'] = old_host
        else:
            asset['name'] = old_host
    asset = {k: field(asset.get(k), 80 if k == 'department' else 120)
             for k in ('name','department','instance','job','agent_id','rule_id')}
    return _enrich(asset)
