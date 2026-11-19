"""Pruebas offline del piloto recuperado: no ejecutan iptables ni systemd."""
import importlib.util
import io
import json
from pathlib import Path
import sys
from types import ModuleType

import pytest
import yaml
from jinja2 import Environment

ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / 'pilot-ssh'


def load_script(name, monkeypatch=None):
    spec = importlib.util.spec_from_file_location('pilot_' + name.replace('-', '_'), PILOT / name)
    mod = importlib.util.module_from_spec(spec)
    if sys.platform == 'win32' and name == 'ssh-block-pilot.py':
        # Los tests no ejecutan el firewall: simular solo flock en Windows.
        # En Linux se importa fcntl real y se comprueba el flujo original.
        assert monkeypatch is not None
        fake_fcntl = ModuleType('fcntl')
        fake_fcntl.LOCK_EX = 2
        fake_fcntl.flock = lambda *_: None
        with monkeypatch.context() as patch:
            patch.setitem(sys.modules, 'fcntl', fake_fcntl)
            spec.loader.exec_module(mod)
    else:
        spec.loader.exec_module(mod)
    return mod


def test_pilot_source_retains_original_protections():
    cfg = json.loads((PILOT / 'config.original.sanitized.json').read_text())
    assert cfg['rules'] == ['5763']
    assert cfg['chain'] == 'WAZUH_SSH_BLOCK'
    assert cfg['ssh_port'] == 22
    assert cfg['block_seconds'] == 180
    assert cfg['recovery_seconds'] == 240
    assert cfg['enable_ipv6'] is False
    assert '127.0.0.0/8' in cfg['protected_networks']
    assert '192.168.56.0/24' in cfg['protected_networks']
    assert '/var/ossec/logs/geoip-lab.log' in cfg['excluded_log_sources']
    assert (PILOT / 'ssh-block-pilot.py').is_file()
    assert (PILOT / 'wazuh-ssh-firewall-init.py').is_file()


def test_original_script_filters_untrusted_sources_without_firewall(monkeypatch, tmp_path):
    mod = load_script('ssh-block-pilot.py', monkeypatch)
    cfg = json.loads((PILOT / 'config.original.sanitized.json').read_text())
    assert mod.acceptable_ip('192.168.56.33', cfg) is None
    assert mod.acceptable_ip('127.0.0.1', cfg) is None
    assert mod.acceptable_ip('203.0.113.77', cfg) is None
    assert mod.acceptable_ip('8.8.8.8', cfg) is not None
    cfg['protected_ips'] = ['8.8.8.8']
    assert mod.acceptable_ip('8.8.8.8', cfg) is None

    cfg['protected_ips'] = []
    monkeypatch.setattr(mod, 'settings', lambda: cfg)
    monkeypatch.setattr(mod, 'local_agent_id', lambda: '005')
    monkeypatch.setattr(mod, 'log', lambda s: None)
    def no_system_calls(*args, **kwargs):
        raise AssertionError('El evento excluido no debe ejecutar iptables ni systemd')
    monkeypatch.setattr(mod, 'execute', no_system_calls)
    msg = {
        'command': 'add',
        'parameters': {'alert': {'id': 'id-1', 'data': {'srcip': '8.8.8.8'},
            'agent': {'id': '005'}, 'rule': {'id': '5763'},
            'location': '/var/ossec/logs/geoip-lab.log'}}
    }
    monkeypatch.setattr(sys, 'stdin', io.StringIO(json.dumps(msg) + '\n'))
    mod.main([])


def test_failed_recovery_timer_cancels_block_without_firewall(monkeypatch, tmp_path):
    mod = load_script('ssh-block-pilot.py', monkeypatch)
    cfg = json.loads((PILOT / 'config.original.sanitized.json').read_text())
    monkeypatch.setattr(mod, 'STATE', tmp_path / 'state')
    monkeypatch.setattr(mod, 'LOG', tmp_path / 'pilot.log')
    monkeypatch.setattr(mod, 'exists', lambda cfg, ip: False)
    monkeypatch.setattr(mod, 'schedule', lambda ip, token, cfg: False)
    def no_firewall(*args, **kwargs):
        raise AssertionError('No debe bloquear si falló la programación del desbloqueo')
    monkeypatch.setattr(mod, 'iptables', no_firewall)
    mod.add(mod.acceptable_ip('8.8.8.8', cfg), {'id': 'sample', 'rule': {'id': '5763'}}, cfg)
    assert 'BLOCK CANCELLED' in (tmp_path / 'pilot.log').read_text()
    assert not list((tmp_path / 'state').glob('*.json'))


def test_manager_and_firewall_activation_not_part_of_auto_workflow():
    import json as jsonlib
    manifest = jsonlib.loads((ROOT / 'awx/workflow/workflow.json').read_text())
    assert [node['id'] for node in manifest['nodes']][-4:] == ['14', '15', '16', '18']
    assert '17' not in [node['id'] for node in manifest['nodes']]
    jobs = yaml.safe_load((ROOT / 'awx/jobs.yml').read_text())['plantillas']
    pilot_job = next(j for j in jobs if j['id'] == '17')
    assert pilot_job['playbook'] == 'ubuntu-26.04/playbooks/17_preparar_piloto_ssh.yml'
    assert pilot_job['depende_de'] == ['06']
    playbook = yaml.safe_load((ROOT / 'playbooks/17_preparar_piloto_ssh.yml').read_text())[0]
    assert playbook['hosts'] == 'monitoring-agents'
    assert playbook['serial'] == 1
    tasks = playbook['tasks']
    gate = tasks[0]['ansible.builtin.assert']['that']
    assert any('install_authorized' in condition for condition in gate)
    assert any('pilot_agent_id' in condition for condition in gate)
    block = next(x['block'] for x in tasks if 'block' in x)
    assert any('pilot_local_id.stdout' in cond for x in block if 'ansible.builtin.assert' in x
               for cond in x['ansible.builtin.assert']['that'])
    assert not any('enabled' in x.get('ansible.builtin.systemd_service', {}) for x in block)
    assert not any('ansible.builtin.command' in t and 'iptables' in str(t['ansible.builtin.command']) for t in block)
    assert 'wazuh_manager.conf' not in (ROOT / 'playbooks/17_preparar_piloto_ssh.yml').read_text()
    env = Environment()
    def visit(v):
        if isinstance(v, dict):
            for item in v.values():
                visit(item)
        elif isinstance(v, list):
            for item in v:
                visit(item)
        elif isinstance(v, str) and ('{{' in v or '{%' in v):
            env.parse(v)
    visit(playbook)


def test_initializer_refuses_invalid_config_before_touching_firewall():
    mod = load_script('wazuh-ssh-firewall-init.py')
    cfg = json.loads((PILOT / 'config.original.sanitized.json').read_text())
    cfg['chain'] = 'INPUT'
    with pytest.raises(ValueError, match='Unsupported'):
        mod.bootstrap(cfg)
    cfg['chain'] = 'WAZUH_SSH_BLOCK'
    cfg['protected_networks'] = ['192.168.56.0/24']
    with pytest.raises(ValueError, match='loopback'):
        mod.bootstrap(cfg)
