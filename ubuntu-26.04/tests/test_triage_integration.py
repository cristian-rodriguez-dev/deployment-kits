from pathlib import Path
import json
import yaml
from jinja2 import Environment, StrictUndefined
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent


def test_real_bot_sources_and_no_private_runtime_files():
    bot = ROOT / 'triage-bot'
    assert (bot / 'app/main.py').is_file()
    assert (bot / 'app/wazuh_indexer.py').is_file()
    assert (bot / 'app/notification_format.py').is_file()
    assert (bot / 'app/observability_metrics.py').is_file()
    assert (bot / 'app/mail_notifier.py').is_file()
    assert (bot / 'app/telegram_notifier.py').is_file()
    assert (bot / 'wazuh/custom-security-triage').is_file()
    assert (bot / 'tests/test_observability_metrics.py').is_file()
    assert (bot / 'evaluation/cases_v1.json').is_file()
    assert not (bot / 'evaluation/reviews_local.json').exists()
    assert not list(bot.rglob('*.db'))
    assert not list(bot.rglob('*.sqlite*'))
    assert not list(bot.rglob('*.pem'))
    assert not list(bot.rglob('*.key'))
    assert not list(bot.rglob('*.bak*'))
    assert not (bot / 'access/auth.json').exists()
    assert not (bot / 'app/asset_inventory.json').exists()
    assert not (bot / '.env').exists()
    assert not (bot / '.local-secrets').exists()


def test_compose_and_webhook_contracts():
    bot = ROOT / 'triage-bot'
    service = yaml.safe_load((bot / 'compose.yml').read_text())['services']['triage-bot']
    assert service['ports'] == ['127.0.0.1:18080:8080']
    assert service['read_only'] is True
    assert 'triage-webhooks' in service['networks']
    assert yaml.safe_load((bot / 'compose.mail.yml').read_text())['services']['mail-notifier']['volumes'] == ['triage-data:/data']
    assert yaml.safe_load((bot / 'compose.telegram.yml').read_text())['services']['telegram-notifier']['volumes'] == ['triage-data:/data']
    assert yaml.safe_load((bot / 'compose.indexer.yml').read_text())['services']['triage-bot']['environment']['WAZUH_INDEXER_URL'] == 'https://wazuh.indexer:9200'
    integrator = (bot / 'wazuh/custom-security-triage').read_text()
    assert 'http://security-triage-bot:8080/webhook/wazuh' in integrator
    assert 'TOKEN_FILE' in integrator
    assert 'host-gateway' not in (bot / 'compose.indexer.yml').read_text()


def test_wazuh_role_read_only_and_reruns_keep_overlays():
    role = yaml.safe_load((ROOT / 'playbooks/14_instalar_triage_bot.yml').read_text())
    body = next(t['ansible.builtin.uri']['body'] for t in role[0]['tasks'] if t.get('name', '').startswith('Crear rol Indexer'))
    assert body['index_permissions'][0]['allowed_actions'] == ['read']
    assert body['index_permissions'][0]['index_patterns'] == ['wazuh-alerts-*', 'wazuh-monitoring-*']
    assert body['tenant_permissions'] == []
    assert 'compose.triage.yml' in (ROOT / 'playbooks/02_instalar_wazuh.yml').read_text()
    assert 'compose.triage-metrics.yml' in (ROOT / 'playbooks/04_instalar_prometheus.yml').read_text()
    assert 'docker compose down -v' not in (ROOT / 'playbooks/14_instalar_triage_bot.yml').read_text()
    assert 'docker compose down -v' not in (ROOT / 'playbooks/15_integrar_metricas_triage.yml').read_text()


def test_workflow_jobs_cohere():
    workflow = json.loads((ROOT / 'awx/workflow/workflow.json').read_text())
    jobs = yaml.safe_load((ROOT / 'awx/jobs.yml').read_text())['plantillas']
    ids = [x['id'] for x in workflow['nodes']]
    assert len(ids) == len(set(ids)) == 21
    assert ids[-4:] == ['14', '15', '16', '18']
    assert 'triage_secrets' in workflow['credentials']
    for i, n in enumerate(workflow['nodes']):
        assert n['after'] == ([ids[i - 1]] if i else [])
        assert (REPO / n['playbook']).is_file()
        matching = [x for x in jobs if x['id'] == n['id']]
        assert len(matching) == 1 and matching[0]['playbook'] == n['playbook']
    assert [x['id'] for x in jobs if x['id'] in ('06', '07')] == ['06', '07']


def test_wazuh_xml_and_template_syntax():
    integrations = ROOT / 'templates/integration'
    xml = ElementTree.fromstring((integrations / 'wazuh-triage-integration.xml').read_text())
    assert xml.findtext('name') == 'custom-security-triage'
    assert xml.findtext('alert_format') == 'json'
    assert xml.findtext('level') == '10'
    env = Environment(undefined=StrictUndefined)
    env.filters['bool'] = bool
    env.filters['ternary'] = lambda value, a, b: a if value else b
    env.filters['to_json'] = json.dumps
    fake = dict(
        triage_webhook_token='x' * 40, triage_metrics_token='y' * 40,
        triage_gemini_key='', triage_smtp_password='', triage_telegram_token='',
        triage_telegram_chat_id='', var_wazuh_project_name='wazuh',
        var_monitorizacion_network='monitorizacion', var_triage_bot_install_dir='/opt/security-triage-bot',
        triage_loki_ip=dict(stdout='10.43.0.1'), triage_wazuh_manager_networks=['default', 'triage-webhooks']
    )
    for f in integrations.glob('triage-*.j2'):
        content = env.from_string(f.read_text()).render(**fake)
        if f.name.endswith('.yml.j2'):
            assert yaml.safe_load(content), f.name
        else:
            assert 'WEBHOOK_TOKEN=' in content or 'MAIL_ENABLED=' in content or 'TELEGRAM_ENABLED=' in content, f.name
    assert 'GEMINI_MODEL=' not in env.from_string((integrations/'triage-env-main.j2').read_text()).render(**fake)


def test_all_managed_playbooks_parse_as_jinja():
    env = Environment()
    def strings(node):
        if isinstance(node, str):
            yield node
        elif isinstance(node, dict):
            for key, value in node.items():
                yield from strings(key)
                yield from strings(value)
        elif isinstance(node, list):
            for value in node:
                yield from strings(value)

    for p in (ROOT / 'playbooks').glob('*.yml'):
        parsed = yaml.safe_load(p.read_text())
        assert parsed
        if p.name.startswith(('14_', '15_', '16_')):
            for scalar in strings(parsed):
                if '{{' in scalar or '{%' in scalar:
                    env.parse(scalar)


def test_prometheus_queries_obey_the_real_bind_address():
    for name in ('15_integrar_metricas_triage.yml', '16_validar_triage.yml'):
        play = (ROOT / 'playbooks' / name).read_text()
        assert "var_prometheus_bind_address | default('127.0.0.1')" in play
        assert 'http://127.0.0.1:{{ var_prometheus_port }}' not in play
