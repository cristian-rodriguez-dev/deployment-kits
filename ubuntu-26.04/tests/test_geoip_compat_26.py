"""Contrato de GeoIP en el pipeline de alertas de Wazuh, sin tocar servicios."""
import json
from pathlib import Path

from jinja2 import Environment
import yaml

ROOT = Path(__file__).resolve().parents[1]
JOB = yaml.safe_load((ROOT / 'playbooks/11_geoip_wazuh.yml').read_text(encoding="utf-8"))[0]
TASKS = JOB['tasks']


def task_named(name):
    return next(item for item in TASKS if item['name'] == name)


def render(expr, **data):
    env = Environment()
    env.filters['to_json'] = lambda obj: json.dumps(obj)
    return env.from_string(expr).render(**data)


def test_geoip_matching_requires_original_field_and_destination():
    expression = task_named('Comprobar si existe el enriquecimiento exacto')['ansible.builtin.set_fact']['geoip_present']
    other_geoip = {'geoip': {'field': 'source.ip', 'target_field': 'source.geo'}}
    original_geoip = {'geoip': {'field': 'data.srcip', 'target_field': 'GeoLocation'}}
    assert render(expression, geoip_original={'processors': [other_geoip]}).strip() == 'False'
    assert render(expression, geoip_original={'processors': [other_geoip, original_geoip]}).strip() == 'True'
    assert render(expression, geoip_original={'processors': []}).strip() == 'False'


def test_simulation_uses_real_wazuh_filebeat_message_contract():
    body = task_named('Comprobar generación GeoLocation')['ansible.builtin.uri']['body']
    document = body['docs'][0]['_source']
    assert list(document) == ['message']
    event = json.loads(render(document['message']).strip())
    assert event['rule']['id'] == '5763'
    assert event['data']['srcip'] == '8.8.8.8'
    assert 'timestamp' in event
    assert body['pipeline']


def test_non_destructive_read_and_simulation():
    read = task_named('Leer pipeline original')['ansible.builtin.uri']
    simulate = task_named('Comprobar generación GeoLocation')['ansible.builtin.uri']
    assert read.get('method', 'GET') == 'GET'
    assert simulate['method'] == 'POST'
    assert '/_simulate' in simulate['url']
    assert 'status_code' in simulate
    restore = task_named('Respaldar pipeline antes del primer cambio')['ansible.builtin.copy']
    assert restore['force'] is False
