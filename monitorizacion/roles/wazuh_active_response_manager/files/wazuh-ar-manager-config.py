#!/usr/bin/env python3
"""Conservative Wazuh Docker-host XML edit: audit/apply/rollback, no service restarts.

Operates on the HOST file mounted as /var/ossec/etc/ossec.conf in the manager.
Only the named <command> and <active-response> blocks are managed.
"""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import xml.etree.ElementTree as ET

TARGET = 'ssh-block-pilot'


def check_xml(text):
    # Wazuh supports multiple ossec_config roots in a single file.
    stripped = re.sub(r'^\s*<\?xml[^>]+\?>', '', text, count=1)
    parsed = ET.fromstring('<wazuh-root>' + stripped + '</wazuh-root>')
    if not parsed.findall('ossec_config'):
        raise ValueError('No <ossec_config> root found')
    return parsed


def matches(text, tag, child, value):
    pattern = re.compile(r'(?ms)^[ \t]*<' + re.escape(tag) +
                         r'>.*?^[ \t]*</' + re.escape(tag) + r'>[ \t]*(?:\r?\n|$)')
    blocks = []
    for match in pattern.finditer(text):
        element = ET.fromstring(match.group(0).strip())
        if element.findtext(child) == value:
            blocks.append(match)
    return blocks


def desired(timeout, rule):
    command = ('  <command>\n'
               '    <name>ssh-block-pilot</name>\n'
               '    <executable>ssh-block-pilot.py</executable>\n'
               '    <timeout_allowed>yes</timeout_allowed>\n'
               '  </command>\n')
    response = ('  <active-response>\n'
                '    <disabled>no</disabled>\n'
                '    <command>ssh-block-pilot</command>\n'
                '    <location>local</location>\n'
                f'    <rules_id>{rule}</rules_id>\n'
                f'    <timeout>{timeout}</timeout>\n'
                '  </active-response>\n')
    return command, response


def normalize(block):
    element = ET.fromstring(block.strip())
    return {node.tag: (node.text or '').strip() for node in element}


def render(text, timeout, rule, allow_migration):
    command, response = desired(timeout, rule)
    blocks = [matches(text, 'command', 'name', TARGET),
              matches(text, 'active-response', 'command', TARGET)]
    if any(len(x) > 1 for x in blocks):
        raise ValueError('Duplicate target <command> or <active-response>; manual review required')
    for candidates, wanted in zip(blocks, (command, response)):
        if candidates and normalize(candidates[0].group(0)) != normalize(wanted) and not allow_migration:
            raise ValueError('Existing pilot differs; explicit migration approval required')
    modifications = [(candidates[0].start(), candidates[0].end(), wanted)
                     for candidates, wanted in zip(blocks, (command, response)) if candidates]
    for start, end, replacement in sorted(modifications, reverse=True):
        text = text[:start] + replacement + text[end:]
    missing = [wanted for candidates, wanted in zip(blocks, (command, response)) if not candidates]
    if missing:
        close = re.search(r'(?m)^\s*</ossec_config>\s*$', text)
        if not close:
            raise ValueError('Could not locate </ossec_config> insertion point')
        snippet = '  <!-- Wazuh SSH Active Response - deployment-kits -->\n' + ''.join(missing) + '\n'
        text = text[:close.start()] + snippet + text[close.start():]
    check_xml(text)
    return text


def backup_and_replace(path, new_text):
    original = path.read_bytes()
    props = path.stat()
    backup_dir = path.parent / '.wazuh-active-response-backups'
    backup_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(backup_dir, 0o700)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup = backup_dir / ('wazuh_manager.conf.' + stamp + '.bak')
    with backup.open('xb') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(original)
    fd, temporary = tempfile.mkstemp(dir=str(path.parent), prefix='.wazuh-ar-')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(new_text.encode('utf-8'))
            f.flush()
            os.fsync(f.fileno())
            os.fchmod(f.fileno(), stat.S_IMODE(props.st_mode))
            os.fchown(f.fileno(), props.st_uid, props.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return backup


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', required=True)
    parser.add_argument('--mode', choices=['audit', 'apply', 'rollback'], default='audit')
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--rule', default='5763')
    parser.add_argument('--allow-migration', action='store_true')
    parser.add_argument('--confirm-agents-ready', action='store_true')
    parser.add_argument('--backup')
    args = parser.parse_args()
    if not 1 <= args.timeout <= 86400 or not args.rule.isdigit():
        parser.error('Invalid timeout/rule')
    path = Path(args.file)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        parser.error('Use an existing absolute, regular host configuration file')
    current = path.read_text(encoding='utf-8')
    check_xml(current)
    if args.mode == 'rollback':
        if not args.backup or not args.confirm_agents_ready:
            parser.error('Rollback requires --backup and explicit confirmation')
        root = (path.parent / '.wazuh-active-response-backups').resolve()
        candidate = Path(args.backup).resolve()
        if candidate.parent != root or not candidate.is_file():
            parser.error('Backup must belong to the managed backup directory')
        target = candidate.read_text(encoding='utf-8')
        check_xml(target)
        backup = backup_and_replace(path, target)
        print('CHANGED rollback restored; previous version backed up at ' + str(backup))
        return
    proposed = render(current, args.timeout, args.rule,
                      args.allow_migration or args.mode == 'audit')
    counts = (len(matches(current, 'command', 'name', TARGET)),
              len(matches(current, 'active-response', 'command', TARGET)))
    if args.mode == 'audit':
        print('AUDIT command_count=%d response_count=%d desired=%s' %
              (counts[0], counts[1], 'yes' if proposed == current else 'no'))
        return
    if not args.confirm_agents_ready:
        parser.error('Apply requires --confirm-agents-ready')
    if proposed == current:
        print('UNCHANGED manager configuration already matches; no restart')
    else:
        backup = backup_and_replace(path, proposed)
        print('CHANGED manager config staged; backup=' + str(backup) + '; RESTART REQUIRED MANUALLY')


if __name__ == '__main__':
    main()
