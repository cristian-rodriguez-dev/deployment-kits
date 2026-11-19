from pathlib import Path
import json
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_shared_k3s():
    bootstrap = (ROOT / 'awx/bootstrap/install-awx.sh').read_text()
    job = (ROOT / 'playbooks/08_observabilidad_k3s.yml').read_text()
    assert '--disable traefik' not in bootstrap
    assert '--disable servicelb' not in bootstrap
    assert 'install_k3s()' in bootstrap
    assert 'get' in job
    assert 'awx-operator-controller-manager' in job
    assert 'get.k3s.io' not in job


def test_chain():
    m = json.loads((ROOT / 'awx/workflow/workflow.json').read_text())
    ids = ['00', '01', '02', '03', '04', '05', '08', '08B', '09A', '09B', '09D', '09C', '09E', '10', '11', '12', '13', '14', '15', '16', '18']
    assert [x['id'] for x in m['nodes']] == ids
    for i, job in enumerate(m['nodes']):
        assert job['after'] == (ids[i-1:i] if i else [])
        assert (ROOT.parent / job['playbook']).is_file()


def test_ports():
    job = (ROOT / 'playbooks/02_instalar_wazuh.yml').read_text()
    assert '127.0.0.1:9200:9200' in job
    assert 'var_observability_access_ip' in job
    assert 'default:' in job
    assert 'var_wazuh_dashboard_port' in job
    assert not (ROOT/'playbooks/group_vars/all.yml').exists()
    config = yaml.safe_load((ROOT/'examples/variables_host_central.yml.example').read_text())
    assert config['var_wazuh_dashboard_port'] == 5601
    assert config['var_prometheus_bind_address'] == '{{ var_observability_access_ip }}'
    assert config['var_grafana_bind_address'] == '{{ var_observability_access_ip }}'


def test_playbooks_valid_yaml():
    for f in (ROOT / 'playbooks').glob('*.yml'):
        plays=yaml.safe_load(f.read_text())
        assert isinstance(plays, list) and plays and isinstance(plays[0],dict)


def test_importer_py_compiles():
    p=ROOT/'awx/workflow/manage_workflow.py'
    compile(p.read_text(),str(p),'exec')
