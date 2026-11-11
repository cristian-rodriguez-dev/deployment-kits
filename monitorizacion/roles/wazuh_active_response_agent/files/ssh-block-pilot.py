#!/usr/bin/env python3
"""Wazuh stateful SSH Active Response (IPv4; optional IPv6).

The persistent token prevents an old systemd timer from releasing a newer block.
This file is intended to be run as root by wazuh-execd, never via shell expansion.
"""
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

CONFIG = Path('/etc/wazuh-ssh-ar/config.json')
STATE = Path('/var/lib/wazuh-ssh-ar')
LOG = Path('/var/ossec/logs/ssh-block-pilot.log')
SCRIPT = '/var/ossec/active-response/bin/ssh-block-pilot.py'
TOOLS = {4: '/usr/sbin/iptables', 6: '/usr/sbin/ip6tables'}


def log(message):
    stamp = datetime.now(timezone.utc).isoformat()
    with LOG.open('a', encoding='utf-8') as f:
        f.write(f'{stamp} {message}\n')


def execute(*argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False)


def settings():
    cfg = json.loads(CONFIG.read_text(encoding='utf-8'))
    assert cfg['chain'] == 'WAZUH_SSH_BLOCK'
    assert 1 <= int(cfg['ssh_port']) <= 65535
    assert 181 <= int(cfg['recovery_seconds']) <= 86400
    assert 1 <= int(cfg['block_seconds']) < int(cfg['recovery_seconds'])
    assert cfg['rules'] and all(str(x).isdigit() for x in cfg['rules'])
    for x in cfg['protected_networks']:
        ipaddress.ip_network(x, strict=False)
    for x in cfg['protected_ips']:
        ipaddress.ip_address(x)
    return cfg


def acceptable_ip(value, cfg):
    try:
        ip = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None
    if not ip.is_global or (ip.version == 6 and not cfg['enable_ipv6']):
        return None
    if str(ip) in cfg['protected_ips']:
        return None
    if any(ip in ipaddress.ip_network(n, strict=False) for n in cfg['protected_networks'] if ipaddress.ip_network(n, strict=False).version == ip.version):
        return None
    return ip


def firewall(ip):
    return TOOLS[ip.version]


def iptables(cfg, ip, operation):
    # Rule in a chain reached only from INPUT with --dport ssh_port.
    return execute(firewall(ip), '-w', operation, cfg['chain'], '-s', str(ip), '-j', 'DROP')


def exists(cfg, ip):
    result = iptables(cfg, ip, '-C')
    if result.returncode not in (0, 1):
        raise RuntimeError('iptables -C failed: ' + result.stderr.strip()[:300])
    # iptables returns 1 for missing rule AND invalid chain; preflight the chain.
    chain = execute(firewall(ip), '-w', '-S', cfg['chain'])
    if chain.returncode != 0:
        raise RuntimeError('Managed chain missing: ' + chain.stderr.strip()[:300])
    return result.returncode == 0


def state_path(ip):
    return STATE / (hashlib.sha256(str(ip).encode('ascii')).hexdigest() + '.json')


def load_state(ip):
    path = state_path(ip)
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding='utf-8'))
    if data.get('ip') != str(ip):
        raise RuntimeError('State address mismatch')
    return data


def write_state(ip, data):
    path = state_path(ip)
    fd, temporary = tempfile.mkstemp(dir=str(STATE), prefix='.tmp-', text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(data, f)
            f.write('\n')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def locked(callback):
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if STATE.is_symlink() or not STATE.is_dir():
        raise RuntimeError('Invalid state directory')
    with (STATE / '.lock').open('a+') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        return callback()


def schedule(ip, token, cfg):
    unit = 'wazuh-ssh-recovery-' + token
    res = execute('/usr/bin/systemd-run', '--quiet', '--unit', unit,
                  '--on-active=' + str(cfg['recovery_seconds']) + 's',
                  '/usr/bin/python3', SCRIPT, '--cleanup', str(ip), token)
    if res.returncode:
        log('ERROR scheduling recovery ' + str(ip) + ': ' + res.stderr.strip()[:300])
        return False
    return True


def remove_owned(ip, cfg, state, reason):
    if exists(cfg, ip):
        r = iptables(cfg, ip, '-D')
        if r.returncode:
            log('ERROR UNBLOCK ' + str(ip) + ': ' + r.stderr.strip()[:300])
            return False
        log('UNBLOCKED ' + str(ip) + ' reason=' + reason)
    else:
        log('DELETE SKIPPED ' + str(ip) + ': rule absent')
    state_path(ip).unlink(missing_ok=True)
    return True


def recover(ip, token, cfg):
    state = load_state(ip)
    if not state or state.get('token') != token:
        log('RECOVERY SKIPPED ' + str(ip) + ': stale or absent token')
        return
    remove_owned(ip, cfg, state, 'systemd')


def add(ip, alert, cfg):
    def transaction():
        previous = load_state(ip)
        if exists(cfg, ip):
            log('ALREADY BLOCKED ' + str(ip) + (' (managed)' if previous else ' (unmanaged)'))
            return
        if previous:
            state_path(ip).unlink(missing_ok=True)
        token = secrets.token_hex(12)
        if not schedule(ip, token, cfg):
            log('BLOCK CANCELLED ' + str(ip) + ': no recovery timer')
            return
        write_state(ip, {'ip': str(ip), 'token': token,
                         'alert_id': str(alert.get('id') or ''),
                         'created_utc': datetime.now(timezone.utc).isoformat()})
        r = iptables(cfg, ip, '-A')
        if r.returncode:
            state_path(ip).unlink(missing_ok=True)
            log('ERROR BLOCK ' + str(ip) + ': ' + r.stderr.strip()[:300])
            return
        log('BLOCKED ' + str(ip) + ' rule=' + str(alert['rule']['id']) +
            ' timeout=' + str(cfg['block_seconds']))
    locked(transaction)


def delete(ip, alert, cfg):
    def transaction():
        state = load_state(ip)
        if not state:
            log('DELETE SKIPPED ' + str(ip) + ': unmanaged or absent state')
            return
        alert_id = str(alert.get('id') or '')
        # A Wazuh DELETE can only reverse the same alert. An old DELETE must
        # not release a subsequent block. Without an ID the 240s timer handles it.
        if not alert_id or not state['alert_id'] or alert_id != state['alert_id']:
            log('DELETE SKIPPED ' + str(ip) + ': missing/mismatched alert id')
            return
        remove_owned(ip, cfg, state, 'wazuh')
    locked(transaction)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    cfg = settings()
    if len(argv) == 3 and argv[0] == '--cleanup':
        ip = acceptable_ip(argv[1], cfg)
        if ip:
            locked(lambda: recover(ip, argv[2], cfg))
        return
    message = json.loads(sys.stdin.readline())
    action = message.get('command')
    if action not in ('add', 'delete'):
        log('IGNORED unexpected action')
        return
    alert = message.get('parameters', {}).get('alert') or {}
    ip = acceptable_ip(alert.get('data', {}).get('srcip'), cfg)
    if not ip:
        log('IGNORED invalid, protected or excluded IP')
        return
    if action == 'add':
        if str(alert.get('rule', {}).get('id')) not in cfg['rules']:
            log('IGNORED unexpected rule')
            return
        if not str(alert.get('agent', {}).get('id') or '').isdigit():
            log('IGNORED absent agent id')
            return
        if alert.get('location') in cfg['excluded_log_sources']:
            log('IGNORED synthetic event')
            return
        print(json.dumps({'version': 1,
                          'origin': {'name': 'ssh-block-pilot', 'module': 'active-response'},
                          'command': 'check_keys',
                          'parameters': {'keys': [str(ip)]}}), flush=True)
        decision = json.loads(sys.stdin.readline()).get('command')
        if decision == 'abort':
            log('ABORT duplicate ' + str(ip))
        elif decision == 'continue':
            add(ip, alert, cfg)
        else:
            log('IGNORED unexpected check_keys decision')
    else:
        delete(ip, alert, cfg)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        try:
            log('ERROR ' + type(exc).__name__ + ': ' + str(exc)[:300])
        except Exception:
            pass
        sys.exit(1)
