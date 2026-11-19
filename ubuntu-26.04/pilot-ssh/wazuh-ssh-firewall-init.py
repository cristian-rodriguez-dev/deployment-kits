#!/usr/bin/env python3
"""Idempotent firewall chain bootstrap. No flush, prune or persistent DROP rules."""
import ipaddress
import json
from pathlib import Path
import subprocess
import sys

CFG = Path('/etc/wazuh-ssh-ar/config.json')


def execute(*args):
    return subprocess.run(args, text=True, capture_output=True, timeout=15, check=False)


def check(cmd, *args):
    result = execute(cmd, '-w', *args)
    if result.returncode:
        raise RuntimeError(f'{cmd} {args[0]} failed: {result.stderr[:250]}')
    return result.stdout


def exists(cmd, *args):
    return execute(cmd, '-w', '-C', *args).returncode == 0


def bootstrap(cfg):
    if cfg.get('chain') != 'WAZUH_SSH_BLOCK':
        raise ValueError('Unsupported firewall chain')
    port = int(cfg['ssh_port'])
    if port < 1 or port > 65535:
        raise ValueError('Invalid SSH port')
    networks = [ipaddress.ip_network(x, strict=False) for x in cfg['protected_networks']]
    networks += [ipaddress.ip_network(str(ipaddress.ip_address(x)))
                 for x in cfg.get('protected_ips', [])]
    if not any(x.version == 4 and x.is_loopback for x in networks):
        raise ValueError('IPv4 loopback protection is mandatory')
    for family, cmd in [(4, '/usr/sbin/iptables'), (6, '/usr/sbin/ip6tables')]:
        if family == 6 and not cfg['enable_ipv6']:
            continue
        ipnets = [str(n) for n in networks if n.version == family]
        if family == 6 and not any(n.is_loopback for n in networks if n.version == 6):
            raise ValueError('IPv6 loopback protection is mandatory')
        if execute(cmd, '-w', '-S', cfg['chain']).returncode:
            check(cmd, '-N', cfg['chain'])
        for net in reversed(ipnets):
            if not exists(cmd, cfg['chain'], '-s', net, '-j', 'RETURN'):
                check(cmd, '-I', cfg['chain'], '1', '-s', net, '-j', 'RETURN')
        if not exists(cmd, 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', cfg['chain']):
            check(cmd, '-I', 'INPUT', '1', '-p', 'tcp', '--dport', str(port), '-j', cfg['chain'])
        # Existing chains may contain unmanaged DROP rules. Never move or delete them;
        # fail if protection is not ahead of every DROP (fail closed for administration).
        rules = check(cmd, '-S', cfg['chain']).splitlines()
        drops = [i for i, line in enumerate(rules) if ' -j DROP' in line]
        for net in ipnets:
            positions = [i for i, line in enumerate(rules)
                         if ('-s ' + net) in line and ' -j RETURN' in line]
            if not positions or (drops and min(positions) > min(drops)):
                raise RuntimeError('Protected network after DROP: ' + net)


def main():
    cfg = json.loads(CFG.read_text(encoding='utf-8'))
    bootstrap(cfg)
    print('Wazuh SSH firewall initialized successfully')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)
