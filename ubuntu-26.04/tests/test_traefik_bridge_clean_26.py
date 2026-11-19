"""Contrato offline del puente original en instalación limpia, sin servicios reales."""
from pathlib import Path
from hashlib import sha256
import json
import yaml
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
INTEGRATION = REPO / 'monitorizacion/integrations/traefik_wazuh_bridge'
JOB = ROOT / 'playbooks/09e_traefik_wazuh_bridge.yml'


def test_original_files_match_old_machine_and_query_contract():
    expected = {
        'bridge.py': '52a9757712f04b5156956bb586617f5763a4b8b2342409ab1496926ca31ef462',
        'traefik-wazuh-bridge.service': '829ffa444a4f5c7cf61f333203543cbfe88eb48ddd1245b1079ba1026156dee3',
        'traefik_rules.xml': '71954245f50c8768290bbb5149e5ba336e0733340693172808bf19654db12d32',
    }
    for name, digest in expected.items():
        assert sha256((INTEGRATION / name).read_bytes()).hexdigest() == digest
    env = Environment(undefined=StrictUndefined)
    env.filters['to_json'] = json.dumps
    config = json.loads(env.from_string((ROOT/'templates/integration/traefik-bridge-config.json.j2').read_text(encoding="utf-8")).render(traefik_loki_url='http://10.43.0.1:80'))
    assert sha256(config['query'].encode()).hexdigest() == '8360248a6e749b299356259046b5322aa9b5a0556c5fd2907bcdbe0fe41699ac'
    assert config['state_path'] == '/var/lib/traefik-wazuh-bridge/state.sqlite'
    assert config['max_output_bytes'] == 52428800
    assert config['window_seconds'] == 30
    assert config['poll_seconds'] == 15


def test_alloy_logs_have_required_original_label_and_web_no_extra_proxy():
    alloy = (ROOT/'templates/k3s/alloy.yaml.j2').read_text(encoding="utf-8")
    assert 'target_label = "app"' in alloy
    assert 'source_labels = ["__meta_kubernetes_pod_container_name"]' in alloy
    assert 'target_label = "namespace"' in alloy
    traefik = (ROOT/'templates/k3s/traefik-config.yaml').read_text(encoding="utf-8")
    assert 'access:' in traefik and 'enabled: true' in traefik and 'format: json' in traefik


def test_mount_and_manager_integrations_preserved_on_rerun():
    bridge = yaml.safe_load(JOB.read_text(encoding="utf-8"))[0]
    tasks = bridge['tasks']
    assert bridge['hosts'] == 'wazuh-servers'
    assert bridge['become'] is True
    assert any(t.get('name') == 'Validar consulta Loki del puente sin escribir eventos' and '--dry-run' in t['ansible.builtin.command']['argv'] for t in tasks)
    assert any(t.get('name') == 'Comprobar reglas preexistentes antes de copiar' for t in tasks)
    assert any(t.get('name') == 'Consultar JSONL existente sin tocar histórico' for t in tasks)
    assert any(t.get('name') == 'Registrar localfile JSONL en configuración de origen del Manager' for t in tasks)
    manager = (ROOT/'playbooks/02_instalar_wazuh.yml').read_text(encoding="utf-8")
    bot = (ROOT/'playbooks/14_instalar_triage_bot.yml').read_text(encoding="utf-8")
    assert 'compose.traefik.yml' in manager and 'compose.traefik.yml' in bot
    overlay = yaml.safe_load((ROOT/'templates/integration/traefik-wazuh-compose.yml').read_text(encoding="utf-8"))
    assert overlay['services']['wazuh.manager']['volumes'] == ['/srv/traefik-wazuh-bridge/events:/var/ossec/traefik-bridge:ro']
    assert 'docker compose down' not in JOB.read_text(encoding="utf-8")
    assert 'state: absent' not in JOB.read_text(encoding="utf-8")


def test_workflow_inserts_single_bridge_after_loki():
    workflow = json.loads((ROOT/'awx/workflow/workflow.json').read_text(encoding="utf-8"))
    ids = [n['id'] for n in workflow['nodes']]
    assert len(ids) == len(set(ids)) == 21
    assert ids.index('09E') == ids.index('09C') + 1
    assert workflow['nodes'][ids.index('09E')]['after'] == ['09C']
    assert workflow['nodes'][ids.index('10')]['after'] == ['09E']
