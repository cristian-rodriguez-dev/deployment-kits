from pathlib import Path
import json
import re
import yaml
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent


def test_entire_central_flow():
    manifest = json.loads((ROOT/'awx/workflow/workflow.json').read_text())
    ids = [n['id'] for n in manifest['nodes']]
    assert len(ids) == len(set(ids)) == 21
    for i,n in enumerate(manifest['nodes']):
        assert n['type'] == 'job'
        assert n['after'] == ([ids[i-1]] if i else [])
        assert (REPO/n['playbook']).is_file()
    assert '06' not in ids and '07' not in ids


def test_faqdn_routes_k3s_traefik_only():
    c = (ROOT/'templates/integration/ingress-octavio.yml.j2').read_text()
    for name in ('awx','grafana','wazuh','prometheus'):
        assert f'{name}.octavio.internal' in c
    assert c.count('kind: IngressRoute') == 4
    assert 'scheme: https' in c
    assert 'kind: Middleware' in c
    assert 'dk-prometheus-auth' in c
    install = (ROOT/'awx/bootstrap/install-awx.sh').read_text()
    assert '--disable traefik' not in install
    assert '--disable servicelb' not in install
    assert 'PROFILE_PATH' in install
    assert 'kernel.apparmor_restrict_unprivileged_unconfined=1' in install
    traefik = (ROOT/'templates/k3s/traefik-config.yaml').read_text()
    parsed = yaml.safe_load(traefik)
    assert parsed['kind'] == 'HelmChartConfig'
    assert parsed['metadata']['namespace'] == 'kube-system'
    assert 'accesslog.fields.queryparameters.defaultmode=drop' in traefik
    assert 'metrics:' in traefik and 'prometheus:' in traefik


def test_original_dashboards_preserved_with_distinct_uids():
    dashboards = list((REPO/'monitorizacion/dashboards').glob('*.json'))
    assert len(dashboards) == 16
    content = [json.loads(f.read_text(encoding='utf-8-sig')) for f in dashboards]
    assert {x['apiVersion'] for x in content} == {'dashboard.grafana.app/v2'}
    ids=[x['metadata']['name'] for x in content]
    assert len(ids)==len(set(ids))
    assert 'security-triage-observabilidad' in ids
    allowed = {'-- Grafana --','grafana','prometheus','wazuh','dg2lbe27nkcn4e','dg2ls1gqxzojkc','cg2sr4544ary8b','${ds_prometheus}'}
    seen=set()
    def walk(x):
        if isinstance(x,dict):
            if isinstance(x.get('datasource'),dict) and 'name' in x['datasource']:
                seen.add(x['datasource']['name'])
            for v in x.values():walk(v)
        elif isinstance(x,list):
            for y in x:walk(y)
    for d in content:walk(d['spec'])
    assert seen <= allowed, seen-allowed


def test_helm_template_yml_syntax():
    vars=yaml.safe_load((ROOT/'examples/variables_host_central.yml.example').read_text())
    vars.update({'var_prometheus_bind_address':'192.0.2.3','var_grafana_bind_address':'192.0.2.3',
                 'ubuntu26_prometheus_bind':'192.0.2.3','ubuntu26_grafana_bind':'192.0.2.3',
                 'ubuntu26_grafana_prometheus_url':'http://prometheus:9090',
                 'var_observability_access_ip':'192.0.2.3',
                 'var_wazuh_admin_password':'placeholder-only-for-render',
                 'var_wazuh_api_password':'placeholder-api-for-render',
                 'var_k3s_node_name':'example-node',
                 'ansible_host':'192.0.2.3',
                 'inventory_hostname':'example-node',
                 'var_wazuh_indexer_ca':'-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----',
                 'var_grafana_admin_user':'admin'})
    env=Environment(undefined=StrictUndefined)
    env.filters['to_json']=lambda obj: json.dumps(obj)
    for relative in ['grafana/docker-compose.yml.j2','grafana/datasources.yml.j2',
                     'grafana/wazuh-datasources.yml.j2','wazuh/compose.credentials.yml.j2',
                     'prometheus/docker-compose.yml.j2','prometheus/prometheus.yml.j2',
                     'k3s/kube-state-metrics.yaml.j2','k3s/loki.yaml.j2','k3s/alloy.yaml.j2',
                     'integration/ingress-octavio.yml.j2', 'integration/k3s-kubelet-rbac.yml.j2']:
        template=(ROOT/'templates'/relative).read_text()
        rendered=env.from_string(template).render(**vars)
        assert list(yaml.safe_load_all(rendered)), relative


def test_all_playbooks_parse_and_no_empty_secrets_in_git():
    for file in (ROOT/'playbooks').glob('*.yml'):
        assert isinstance(yaml.safe_load(file.read_text()),list),file
    assert not (ROOT/'playbooks/group_vars/all.yml').exists()
    assert not (ROOT/'acceso-https').exists()
    assert (ROOT/'awx/setup_inventory.py').exists()
    assert not list(ROOT.rglob('*.key'))
    assert not list(ROOT.rglob('*.pem'))
