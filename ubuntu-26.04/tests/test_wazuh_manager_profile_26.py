import subprocess
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools/wazuh_manager_profile.py'
PLAYBOOK = ROOT / 'playbooks/02_instalar_wazuh.yml'


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True)


def test_legacy_wazuh_manager_profile_is_idempotent(tmp_path):
    p = tmp_path / 'wazuh_manager.conf'
    initial = '''<ossec_config>
  <global><jsonout_output>yes</jsonout_output></global>
  <sca><enabled>no</enabled><interval>24h</interval></sca>
  <syscheck><disabled>yes</disabled><frequency>3600</frequency><directories>/etc</directories></syscheck>
</ossec_config>
<ossec_config><localfile><location>/var/log/syslog</location><log_format>syslog</log_format></localfile></ossec_config>
'''
    p.write_text(initial)
    assert run('--check', p).returncode == 1
    result = run('--apply', p)
    assert result.returncode == 0, result.stderr
    updated = p.read_text()
    root = ET.fromstring('<root>' + updated + '</root>')
    assert root.findtext('./ossec_config/sca/enabled') == 'yes'
    assert root.findtext('./ossec_config/sca/interval') == '12h'
    assert root.findtext('./ossec_config/syscheck/disabled') == 'no'
    assert root.findtext('./ossec_config/syscheck/frequency') == '43200'
    assert root.findtext('./ossec_config/syscheck/directories') == '/etc'
    assert root.findtext('./ossec_config/vulnerability-detection/enabled') == 'yes'
    assert root.findtext('./ossec_config/global/jsonout_output') == 'yes'
    assert root.findtext('./ossec_config/localfile/location') == '/var/log/syslog' or root.findtext('./ossec_config[2]/localfile/location') == '/var/log/syslog'
    assert (tmp_path / 'wazuh_manager.conf.pre-manager-profile').read_text() == initial
    assert run('--apply', p).returncode == 0
    assert run('--check', p).returncode == 0
    assert p.read_text() == updated


def test_refuses_duplicate_sections_and_does_not_write(tmp_path):
    p = tmp_path / 'wazuh_manager.conf'
    original = '<ossec_config><sca/><sca/></ossec_config>'
    p.write_text(original)
    assert run('--apply', p).returncode != 0
    assert p.read_text() == original


def test_job02_runs_only_initial_apply_and_checks_reruns():
    text = PLAYBOOK.read_text()
    assert 'wazuh_manager_profile.py --apply' in text
    assert 'wazuh_manager_profile.py --check' in text
    assert 'when: not var_wazuh_state.stat.exists' in text
    assert 'manager-original' not in text


def test_original_integration_and_pilot_stay_separate():
    integration = (ROOT / 'templates/integration/wazuh-triage-integration.xml').read_text()
    assert '<name>custom-security-triage</name>' in integration
    assert '<level>10</level>' in integration
    assert '<alert_format>json</alert_format>' in integration
    assert 'ssh-block-pilot' not in PLAYBOOK.read_text()
    assert 'ssh-block-pilot' not in (ROOT / 'playbooks/14_instalar_triage_bot.yml').read_text()
