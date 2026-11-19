"""Simulación de la API sin red ni notificaciones reales."""
from pathlib import Path
import importlib.util
import json
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('grafana_alerting_26', ROOT/'tools/restore_grafana_alerting.py')
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)
SOURCE = ROOT/'alerting/grafana-alerting-sanitized.json'


class FakeGrafana:
    def __init__(self):
        self.folder = None
        self.rules = {}
        self.contacts = {}
        self.policy = {'receiver': 'grafana-default-email', 'group_by': ['grafana_folder'], 'routes': []}
        self.writes = []

    def request(self, method, path, payload=None, missing_ok=False):
        if method != 'GET':
            self.writes.append((method, path))
        if path.startswith('/api/folders'):
            if method == 'GET':
                return self.folder
            assert method == 'POST'
            self.folder = payload.copy()
            return self.folder
        if path == '/api/v1/provisioning/alert-rules':
            if method == 'GET':
                return list(self.rules.values())
            assert method == 'POST'
            self.rules[payload['uid']] = payload.copy()
            return payload
        if path.startswith('/api/v1/provisioning/alert-rules/'):
            assert method == 'PUT'
            self.rules[payload['uid']] = payload.copy()
            return payload
        if path == '/api/v1/provisioning/contact-points':
            if method == 'GET':
                return list(self.contacts.values())
            assert method == 'POST'
            self.contacts[payload['uid']] = payload.copy()
            return payload
        if path == '/api/v1/provisioning/policies':
            if method == 'GET':
                return self.policy.copy()
            self.policy = payload.copy()
            return self.policy
        raise AssertionError('Ruta inesperada: ' + path)


def private_contacts():
    src = MOD.load_source(SOURCE)
    return json.dumps([dict(uid=c['uid'],name=c['name'],type=c['type'],
                            settings={k: 'valor-test' for k in c['settings_keys']})
                       for c in src['contact_points']])


def test_source_is_exactly_ten_and_contains_original_routes():
    src = MOD.load_source(SOURCE)
    assert len(src['alert_rules']) == 10
    assert len(src['contact_points']) == 3
    assert {c['type'] for c in src['contact_points']} == {'telegram','email','webhook'}
    assert src['policies']['routes'][0]['receiver'] == 'Security Triage Bot'
    assert src['alert_rules'][0]['notification_settings']['receiver'] == 'Infraestructura - Emergencias'
    assert all('settings' not in c for c in src['contact_points'])
    assert all(not v.get('isPaused') for v in src['alert_rules'])


def test_plan_offline_no_network():
    p=subprocess.run([sys.executable,str(ROOT/'tools/restore_grafana_alerting.py'),
                      '--source',str(SOURCE),'--mode','plan'],capture_output=True,text=True,check=True)
    assert json.loads(p.stdout)['writes'] == 0


def test_staging_is_paused_and_idempotent():
    src = MOD.load_source(SOURCE)
    client = FakeGrafana()
    first = MOD.apply(src, client, 'stage', 'Infrastructure')
    assert first['created'] == 10 and not first['policies_applied']
    assert len(client.rules) == 10 and all(r['isPaused'] is True for r in client.rules.values())
    assert not client.contacts and client.policy['receiver'] == 'grafana-default-email'
    assert client.rules['awx-critical-triage-down'].get('notification_settings') is None
    previous = list(client.writes)
    again = MOD.apply(src, client, 'stage', 'Infrastructure')
    assert again['created'] == 0 and again['updated'] == 0 and client.writes == previous


def test_activation_requires_three_complete_original_contacts():
    src=MOD.load_source(SOURCE)
    with pytest.raises(MOD.SafeError, match='faltan'):
        MOD.validate_contact_runtime(src, '')
    with pytest.raises(MOD.SafeError, match='tres'):
        MOD.validate_contact_runtime(src,'[]')
    contacts=json.loads(private_contacts())
    del contacts[0]['settings'][next(iter(contacts[0]['settings']))]
    with pytest.raises(MOD.SafeError, match='Faltan ajustes'):
        MOD.validate_contact_runtime(src,json.dumps(contacts))


def test_explicit_activation_preserves_policy_and_keeps_demo_paused():
    src=MOD.load_source(SOURCE)
    client=FakeGrafana()
    MOD.apply(src,client,'stage','Infrastructure')
    active=MOD.apply(src,client,'activate','Infrastructure',private_contacts())
    assert active['created']==0 and active['updated']==9
    assert len(client.contacts)==3
    assert client.policy == src['policies']
    assert sum(r['isPaused'] for r in client.rules.values()) == 1
    assert client.rules['ag3v526avhipsb']['isPaused'] is True
    assert client.rules['awx-critical-triage-down']['notification_settings']['receiver'] == 'Infraestructura - Emergencias'
    written=list(client.writes)
    rerun=MOD.apply(src,client,'activate','Infrastructure',private_contacts())
    assert rerun['updated']==0 and client.writes==written


def test_drift_fails_before_any_write():
    src=MOD.load_source(SOURCE)
    client=FakeGrafana()
    existing=MOD.rule_payload(src['alert_rules'][0],False)
    existing['title']='Cambio ajeno'
    client.rules[existing['uid']]=existing
    with pytest.raises(MOD.SafeError,match='Deriva'):
        MOD.apply(src,client,'stage','Infrastructure')
    assert not client.writes


def test_jobs_18_only_after_16_and_no_ssh_activation():
    workflow=json.loads((ROOT/'awx/workflow/workflow.json').read_text())
    assert workflow['nodes'][-1]['id']=='18'
    assert workflow['nodes'][-1]['after']==['16']
    assert '17' not in [x['id'] for x in workflow['nodes']]
    job=(ROOT/'playbooks/18_grafana_alerting_original.yml').read_text()
    assert "default('stage')" in job
    assert 'var_grafana_alerting_authorize_notifications' in job
    assert 'no_log: true' in job
