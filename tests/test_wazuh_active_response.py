"""Tests sin privilegios, sin Wazuh, sin iptables ni systemd reales."""
import importlib.util
import io
import json
import os
import sys
import types
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import contextlib
import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'monitorizacion'
AGENT = BASE / 'roles/wazuh_active_response_agent/files/ssh-block-pilot.py'
FIREWALL = BASE / 'roles/wazuh_active_response_agent/files/wazuh-ssh-firewall-init.py'
MANAGER = BASE / 'roles/wazuh_active_response_manager/files/wazuh-ar-manager-config.py'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    if path == AGENT:
        # El agente se ejecuta SOLO en Linux y utiliza flock(2).
        # Para pruebas simuladas en Windows, sustituimos exclusivamente
        # esa primitiva POSIX; nunca el script de produccion.
        fake_fcntl = types.ModuleType('fcntl')
        fake_fcntl.LOCK_EX = 2
        fake_fcntl.flock = lambda *_args: None
        with patch.dict(sys.modules, {'fcntl': fake_fcntl}):
            spec.loader.exec_module(module)
    else:
        spec.loader.exec_module(module)
    return module


class ActiveResponseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.module = load(AGENT, 'test_agent')
        self.module.STATE = self.base / 'state'
        self.module.LOG = self.base / 'events.log'
        self.module.CONFIG = self.base / 'config.json'
        self.cfg = {
            'chain': 'WAZUH_SSH_BLOCK', 'ssh_port': 22, 'rules': ['5763'],
            'block_seconds': 180, 'recovery_seconds': 240,
            'enable_ipv6': False,
            'protected_networks': ['192.168.56.0/24', '127.0.0.0/8', '::1/128'],
            'protected_ips': ['8.8.8.8'],
            'excluded_log_sources': ['/var/ossec/logs/geoip-lab.log']
        }
        self.module.CONFIG.write_text(json.dumps(self.cfg))
        self.rules = set()
        self.timers = []

        def fake_execute(*argv):
            if argv[0] == '/usr/bin/systemd-run':
                self.timers.append(argv)
                return subprocess.CompletedProcess(argv, 0, '', '')
            if argv[0] in ('/usr/sbin/iptables', '/usr/sbin/ip6tables'):
                op = argv[2]
                if op == '-S':
                    return subprocess.CompletedProcess(argv, 0, '-N WAZUH_SSH_BLOCK', '')
                ip = argv[argv.index('-s') + 1]
                if op == '-C':
                    return subprocess.CompletedProcess(argv, 0 if ip in self.rules else 1, '', '')
                if op == '-A':
                    self.rules.add(ip)
                if op == '-D':
                    self.rules.remove(ip)
                return subprocess.CompletedProcess(argv, 0, '', '')
            raise AssertionError(argv)
        self.patch = patch.object(self.module, 'execute', side_effect=fake_execute)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.alert = {
            'id': '1794000000.123', 'agent': {'id': '005'},
            'rule': {'id': '5763'},
            'location': 'journald', 'data': {'srcip': '1.1.1.1'}
        }

    def test_add_delete_by_same_alert_and_stale_recovery(self):
        ip = self.module.acceptable_ip('1.1.1.1', self.cfg)
        self.module.add(ip, self.alert, self.cfg)
        first = self.module.load_state(ip)
        self.assertIn(str(ip), self.rules)
        self.assertEqual(len(self.timers), 1)
        self.module.delete(ip, self.alert, self.cfg)
        self.assertNotIn(str(ip), self.rules)
        self.module.add(ip, {'id': '1794000001.456', **{k: v for k, v in self.alert.items() if k != 'id'}}, self.cfg)
        second = self.module.load_state(ip)
        self.assertNotEqual(first['token'], second['token'])
        self.module.locked(lambda: self.module.recover(ip, first['token'], self.cfg))
        self.assertIn(str(ip), self.rules, 'Old cleanup must not release new block')
        self.module.delete(ip, self.alert, self.cfg)
        self.assertIn(str(ip), self.rules, 'Old Wazuh DELETE must not release new block')
        self.module.locked(lambda: self.module.recover(ip, second['token'], self.cfg))
        self.assertNotIn(str(ip), self.rules)

    def test_no_alert_id_falls_back_to_token_recovery(self):
        ip = self.module.acceptable_ip('1.1.1.1', self.cfg)
        self.module.add(ip, self.alert, self.cfg)
        state = self.module.load_state(ip)
        without_id = {k: v for k, v in self.alert.items() if k != 'id'}
        self.module.delete(ip, without_id, self.cfg)
        self.assertIn(str(ip), self.rules)
        self.module.locked(lambda: self.module.recover(ip, state['token'], self.cfg))
        self.assertNotIn(str(ip), self.rules)

    def test_protected_ips_are_rejected(self):
        for value in ['192.168.56.1', '127.0.0.1', '8.8.8.8', '203.0.113.77', '::1', '2001:4860:4860::8888']:
            with self.subTest(ip=value):
                self.assertIsNone(self.module.acceptable_ip(value, self.cfg))

    def test_failure_to_schedule_prevents_block(self):
        ip = self.module.acceptable_ip('1.1.1.1', self.cfg)
        with patch.object(self.module, 'schedule', return_value=False):
            self.module.add(ip, self.alert, self.cfg)
        self.assertFalse(self.rules)
        self.assertFalse(self.module.load_state(ip))

    def test_protocol_abort_continue_and_unexpected_rule(self):
        message = {'command': 'add', 'parameters': {'alert': self.alert}}
        with patch('sys.stdin', io.StringIO(json.dumps(message) + '\n' + json.dumps({'command': 'abort'}) + '\n')):
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.module.main()
        self.assertEqual(json.loads(out.getvalue())['command'], 'check_keys')
        self.assertFalse(self.rules)
        with patch('sys.stdin', io.StringIO(json.dumps(message) + '\n' + json.dumps({'command': 'continue'}) + '\n')):
            with contextlib.redirect_stdout(io.StringIO()):
                self.module.main()
        self.assertIn('1.1.1.1', self.rules)
        self.assertEqual(len(self.timers), 1)
        message['parameters']['alert']['rule']['id'] = '5710'
        with patch('sys.stdin', io.StringIO(json.dumps(message) + '\n')):
            self.module.main()
        self.assertEqual(len(self.timers), 1)

    def test_unmanaged_rule_not_removed(self):
        ip = self.module.acceptable_ip('1.1.1.1', self.cfg)
        self.rules.add('1.1.1.1')
        self.module.delete(ip, self.alert, self.cfg)
        self.assertIn('1.1.1.1', self.rules)


class FirewallBootstrapTests(unittest.TestCase):
    def test_init_idempotent_and_protected(self):
        mod = load(FIREWALL, 'test_fw')
        rules = {'/usr/sbin/iptables': [], '/usr/sbin/ip6tables': []}
        chains = set()

        def fake_execute(*argv):
            cmd, _, op = argv[:3]
            family_rules = rules[cmd]
            if op == '-S':
                chain = argv[3]
                if chain not in chains:
                    return subprocess.CompletedProcess(argv, 1, '', 'missing')
                lines = ['-N ' + chain] + ['-A ' + chain + ' ' + ' '.join(x[1:]) for x in family_rules if x[0] == chain]
                return subprocess.CompletedProcess(argv, 0, '\n'.join(lines), '')
            if op == '-N':
                chains.add(argv[3])
                return subprocess.CompletedProcess(argv, 0, '', '')
            if op == '-C':
                r = (argv[3],) + argv[4:]
                return subprocess.CompletedProcess(argv, 0 if r in family_rules else 1, '', '')
            if op == '-I':
                r = (argv[3],) + argv[5:]  # ignore index
                family_rules.insert(0, r)
                return subprocess.CompletedProcess(argv, 0, '', '')
            raise AssertionError(argv)
        cfg = {'chain': 'WAZUH_SSH_BLOCK', 'ssh_port': 22,
               'protected_networks': ['127.0.0.0/8', '192.168.56.0/24', '::1/128'],
               'protected_ips': ['8.8.8.8'],
               'enable_ipv6': False}
        chains.add('INPUT')
        with patch.object(mod, 'execute', side_effect=fake_execute):
            mod.bootstrap(cfg)
            once = list(rules['/usr/sbin/iptables'])
            mod.bootstrap(cfg)
        self.assertEqual(once, rules['/usr/sbin/iptables'])
        self.assertEqual(len(once), 4)
        self.assertEqual(rules['/usr/sbin/ip6tables'], [])


class ManagerConfigTests(unittest.TestCase):
    def setUp(self):
        self.mod = load(MANAGER, 'test_manager')
        self.original = '<ossec_config>\n  <global><white_list>192.168.56.0/24</white_list></global>\n</ossec_config>\n'

    def test_new_install_and_idempotent_render(self):
        result = self.mod.render(self.original, 180, '5763', False)
        self.mod.check_xml(result)
        self.assertIn('<location>local</location>', result)
        self.assertEqual(self.mod.render(result, 180, '5763', False), result)
        self.assertEqual(result.count('<name>ssh-block-pilot</name>'), 1)

    def test_migration_requires_explicit_approval(self):
        previous = self.original.replace('</ossec_config>',
            '  <command>\n    <name>ssh-block-pilot</name>\n    <executable>ssh-block-pilot.py</executable>\n    <timeout_allowed>yes</timeout_allowed>\n  </command>\n'
            '  <active-response>\n    <command>ssh-block-pilot</command>\n'
            '    <location>defined-agent</location>\n    <agent_id>005</agent_id>\n'
            '    <rules_id>5763</rules_id>\n    <timeout>180</timeout>\n  </active-response>\n</ossec_config>')
        with self.assertRaises(ValueError):
            self.mod.render(previous, 180, '5763', False)
        result = self.mod.render(previous, 180, '5763', True)
        self.assertIn('<location>local</location>', result)
        self.assertNotIn('<agent_id>005</agent_id>', result)

    def test_cli_audit_of_legacy_does_not_modify_configuration(self):
        import sys
        previous = self.original.replace('</ossec_config>',
            '  <command>\n    <name>ssh-block-pilot</name>\n    <executable>ssh-block-pilot.py</executable>\n    <timeout_allowed>yes</timeout_allowed>\n  </command>\n'
            '  <active-response>\n    <command>ssh-block-pilot</command>\n'
            '    <location>defined-agent</location>\n    <agent_id>005</agent_id>\n'
            '    <rules_id>5763</rules_id>\n    <timeout>180</timeout>\n  </active-response>\n</ossec_config>')
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / 'wazuh_manager.conf'
            file.write_text(previous)
            result = subprocess.run([sys.executable, str(MANAGER), '--file', str(file), '--mode', 'audit'],
                                    text=True, capture_output=True, check=True)
            self.assertIn('desired=no', result.stdout)
            self.assertEqual(file.read_text(), previous)
            self.assertFalse((file.parent / '.wazuh-active-response-backups').exists())

    def test_atomic_backup_and_no_write_on_identical_content(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / 'wazuh_manager.conf'
            file.write_text(self.original)
            new = self.mod.render(self.original, 180, '5763', False)
            # Windows carece de fchown; el codigo real conserva el
            # propietario en Linux. Simulamos SOLO la llamada no disponible.
            ownership = (contextlib.nullcontext() if hasattr(os, 'fchown')
                         else patch.object(self.mod.os, 'fchown', create=True))
            with ownership:
                backup = self.mod.backup_and_replace(file, new)
            self.assertEqual(backup.read_text(), self.original)
            self.assertEqual(file.read_text(), new)
            self.assertEqual(self.mod.render(new, 180, '5763', False), new)


class AnsibleContracts(unittest.TestCase):
    def test_new_yaml_files_are_valid(self):
        paths = list(BASE.glob('playbooks/*wazuh_active_response*.yml'))
        paths += list(BASE.glob('roles/wazuh_active_response_*/*/*.yml'))
        paths += list(BASE.glob('examples/variables_wazuh_active_response.yml'))
        self.assertGreaterEqual(len(paths), 8)
        for p in paths:
            with self.subTest(file=p):
                self.assertIsNotNone(yaml.safe_load(p.read_text(encoding='utf8')))


if __name__ == '__main__':
    unittest.main()
