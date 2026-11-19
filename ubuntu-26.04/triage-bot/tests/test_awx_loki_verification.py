"""Pruebas offline del adaptador AWX read-only, sin acceso de red real."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from app.awx_loki_verification import (
    AWXReadOnlyConfig, AWXVerificationError, VerifiedLokiObservation,
    _BlockRedirects, _config_base, _fetch, _read_token,
    fetch_verified_observation, verify_snapshot,
)
from app.remediation_loki import propose_loki_diagnostic

NOW = datetime(2026, 11, 16, 13, 0, tzinfo=timezone.utc)
ISO = lambda t: t.isoformat().replace('+00:00', 'Z')


def config(token_file=Path('/tmp/awx_readonly_token'), **overrides):
    values = dict(base_url='https://awx.example.internal', token_file=token_file,
                  ca_file=None, job_template_id=119, inventory_id=9, project_id=4)
    values.update(overrides)
    return AWXReadOnlyConfig(**values)


def record(ready=True, *, observed_at=None):
    return {
        'version': 'loki-k3s-awx-diagnostic-v1', 'type': 'observation_only',
        'verified_provenance': False, 'requires_external_job_validation': True,
        'changes_kubernetes': False, 'changes_triage': False,
        'changes_notifications': False, 'execution_allowed': False,
        'observation': {
            'source': 'kubernetes_api', 'namespace': 'logging', 'pod': 'loki-0',
            'container': 'loki', 'pod_found': True, 'container_found': True,
            'ready': ready, 'observed_at_utc': ISO(observed_at or NOW - timedelta(seconds=30)),
        }
    }


def sample(ready=True):
    job_id = 800
    job = {
        'id': job_id, 'job_template': 119, 'inventory': 9, 'project': 4,
        'status': 'successful', 'job_type': 'run', 'launch_type': 'manual',
        'playbook': 'monitorizacion/playbooks/auditar_loki_k3s_remediacion.yml',
        'failed': False, 'limit': 'ansible_server',
        'started': ISO(NOW - timedelta(seconds=80)),
        'finished': ISO(NOW - timedelta(seconds=10)),
    }
    event = {
        'job': job_id, 'event': 'runner_on_ok',
        'event_data': {
            'host': 'ansible_server',
            'task': 'Mostrar solo observacion apta para revision manual',
            'res': {'msg': record(ready)},
        },
    }
    page = {'count': 1, 'next': None, 'results': [event]}
    return job, page


def verify(job, page, now=NOW):
    return verify_snapshot(job_id=800, job=job, events_page=page,
                           config=config(), now=now)


def error_code(f, expected):
    try:
        f()
    except AWXVerificationError as err:
        if err.code != expected:
            raise AssertionError(f'Esperado {expected}, recibido {err.code}')
    else:
        raise AssertionError(f'Esperado AWXVerificationError({expected})')


class SnapshotTests(unittest.TestCase):
    def test_healthy(self):
        job, page = sample()
        out = verify(job, page)
        self.assertIsInstance(out, VerifiedLokiObservation)
        self.assertIs(out.observation['ready'], True)
        self.assertEqual(out.job_id, 800)

    def test_not_ready(self):
        job, page = sample(False)
        out = verify(job, page)
        self.assertIs(out.observation['ready'], False)
        # El contrato anterior 19B sigue siendo consultivo incluso si se confirma la caída.
        result = propose_loki_diagnostic(
            incident_id=123,
            signal={'source': 'grafana', 'rule_uid': 'awx-critical-loki-notready',
                    'component': 'loki', 'status': 'firing'},
            observation=out.observation, observation_trusted=True, now=NOW,
        )
        self.assertEqual(result['status'], 'proposed')
        self.assertIs(result['execution_allowed'], False)

    def test_missing_pod_is_investigation(self):
        job, page = sample(None)
        obs = page['results'][0]['event_data']['res']['msg']['observation']
        obs.update(pod_found=False, container_found=False)
        out = verify(job, page)
        proposal = propose_loki_diagnostic(incident_id=12,
            signal={'source': 'grafana', 'rule_uid': 'awx-critical-loki-notready',
                    'component': 'loki', 'status': 'firing'},
            observation=out.observation, observation_trusted=True, now=NOW)
        self.assertEqual(proposal['status'], 'investigate')

    def test_wrong_template(self):
        job, page = sample(); job['job_template'] = 120
        error_code(lambda: verify(job, page), 'job_identity_mismatch')

    def test_wrong_project(self):
        job, page = sample(); job['project'] = 5
        error_code(lambda: verify(job, page), 'job_identity_mismatch')

    def test_wrong_inventory(self):
        job, page = sample(); job['inventory'] = 5
        error_code(lambda: verify(job, page), 'job_identity_mismatch')

    def test_bool_is_not_valid_id(self):
        job, page = sample(); job['id'] = True
        error_code(lambda: verify(job, page), 'job_identity_mismatch')

    def test_wrong_playbook(self):
        job, page = sample(); job['playbook'] = 'other.yml'
        error_code(lambda: verify(job, page), 'job_not_authorized_or_successful')

    def test_failed_job(self):
        job, page = sample(); job['status'] = 'failed'
        error_code(lambda: verify(job, page), 'job_not_authorized_or_successful')

    def test_non_manual_job(self):
        job, page = sample(); job['launch_type'] = 'scheduled'
        error_code(lambda: verify(job, page), 'job_not_authorized_or_successful')

    def test_wrong_limit(self):
        job, page = sample(); job['limit'] = 'all'
        error_code(lambda: verify(job, page), 'job_limit_mismatch')

    def test_stale_job(self):
        job, page = sample()
        error_code(lambda: verify(job, page, now=NOW + timedelta(minutes=6)),
                   'stale_or_invalid_job')

    def test_future_job(self):
        job, page = sample(); job['finished'] = ISO(NOW + timedelta(seconds=1))
        error_code(lambda: verify(job, page), 'stale_or_invalid_job')

    def test_bad_timestamp(self):
        job, page = sample(); job['started'] = '2026-11-16T13:00:00'
        error_code(lambda: verify(job, page), 'invalid_timestamp')

    def test_event_wrong_job(self):
        job, page = sample(); page['results'][0]['job'] = 801
        error_code(lambda: verify(job, page), 'event_identity_mismatch')

    def test_event_wrong_host(self):
        job, page = sample(); page['results'][0]['event_data']['host'] = 'other-host'
        error_code(lambda: verify(job, page), 'event_identity_mismatch')

    def test_no_observation_event(self):
        job, page = sample(); page['results'][0]['event_data']['task'] = 'Otra tarea'
        error_code(lambda: verify(job, page), 'observation_event_missing_or_duplicated')

    def test_duplicate_observation_events(self):
        job, page = sample(); page['results'].append(page['results'][0].copy()); page['count'] = 2
        error_code(lambda: verify(job, page), 'observation_event_missing_or_duplicated')

    def test_paginated_event_list_is_rejected(self):
        job, page = sample(); page['count'] = 2; page['next'] = '/api/v2/jobs/800/job_events/?page=2'
        error_code(lambda: verify(job, page), 'incomplete_job_events')

    def test_false_provenance_from_awx(self):
        job, page = sample(); page['results'][0]['event_data']['res']['msg']['verified_provenance'] = True
        error_code(lambda: verify(job, page), 'invalid_diagnostic_contract')

    def test_side_effects_not_allowed(self):
        job, page = sample(); page['results'][0]['event_data']['res']['msg']['execution_allowed'] = True
        error_code(lambda: verify(job, page), 'invalid_diagnostic_contract')

    def test_wrong_scope(self):
        job, page = sample(); page['results'][0]['event_data']['res']['msg']['observation']['pod'] = 'loki-1'
        error_code(lambda: verify(job, page), 'observation_scope_mismatch')

    def test_fake_boolean(self):
        job, page = sample(); page['results'][0]['event_data']['res']['msg']['observation']['ready'] = 'false'
        error_code(lambda: verify(job, page), 'invalid_observation')

    def test_observation_outside_job(self):
        job, page = sample(); page['results'][0]['event_data']['res']['msg']['observation']['observed_at_utc'] = ISO(NOW - timedelta(minutes=4))
        error_code(lambda: verify(job, page), 'observation_time_mismatch')

    def test_null_readiness_is_not_false(self):
        job, page = sample(None)
        out = verify(job, page)
        self.assertIsNone(out.observation['ready'])

    def test_missing_identity_value(self):
        job, page = sample(); del page['results'][0]['event_data']['res']['msg']['observation']['namespace']
        error_code(lambda: verify(job, page), 'invalid_observation')


class NetworkTests(unittest.TestCase):
    def test_https_required(self):
        error_code(lambda: _config_base(config(base_url='http://awx.example.internal')), 'invalid_awx_url')

    def test_userinfo_rejected(self):
        error_code(lambda: _config_base(config(base_url='https://admin:pwd@awx.example.internal')), 'invalid_awx_url')

    def test_absolute_token_file_required(self):
        error_code(lambda: _config_base(config(token_file=Path('token'))), 'invalid_config')

    def test_token_not_logged_or_returned_in_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'token'
            p.write_text('my-sample-secret-token\n', encoding='utf-8'); p.chmod(0o600)
            self.assertEqual(_read_token(p), 'my-sample-secret-token')
            p.write_text('secret token with spaces', encoding='utf-8')
            error_code(lambda: _read_token(p), 'token_unavailable')

    def test_world_readable_token_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'token'
            p.write_text('sample-token', encoding='utf-8')
            p.chmod(0o644)
            error_code(lambda: _read_token(p), 'unsafe_token_permissions')

    def test_symlink_token_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'token'
            p.write_text('sample-token', encoding='utf-8'); p.chmod(0o600)
            link = Path(tmp) / 'link'
            link.symlink_to(p)
            error_code(lambda: _read_token(link), 'unsafe_token_permissions')

    def test_read_only_api_paths(self):
        job, page = sample()
        class FakeResponse:
            status = 200
            def __init__(self, payload): self.stream = io.BytesIO(json.dumps(payload).encode())
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def read(self, n): return self.stream.read(n)

        class FakeOpener:
            def __init__(self): self.requests = []
            def open(self, req, timeout):
                self.requests.append(req)
                return FakeResponse(job if len(self.requests) == 1 else page)

        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / 'token'; file.write_text('test-token'); file.chmod(0o600)
            opened = FakeOpener()
            with patch('app.awx_loki_verification._opener', return_value=opened):
                result = fetch_verified_observation(job_id=800, config=config(token_file=file), now=NOW)
            self.assertIs(result.observation['ready'], True)
            self.assertEqual(len(opened.requests), 2)
            for req in opened.requests:
                self.assertEqual(req.get_method(), 'GET')
                self.assertIn('/api/v2/jobs/800/', req.full_url)
                self.assertEqual(req.get_header('Authorization'), 'Bearer test-token')

    def test_refuses_large_response(self):
        class FakeResponse:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def read(self, n): return b'x' * n
        opener = Mock()
        opener.open.return_value = FakeResponse()
        error_code(lambda: _fetch(opener, 'https://awx.internal/api/v2/jobs/1/', 'x'),
                   'awx_response_too_large')

    def test_redirect_handler_never_redirects(self):
        handler = _BlockRedirects()
        self.assertIsNone(handler.redirect_request(None, None, 302, 'redirect', {}, 'https://evil'))


if __name__ == '__main__':
    unittest.main()
