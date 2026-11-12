import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'monitorizacion/files/grafana_alerting_snapshot.py'
spec = importlib.util.spec_from_file_location('grafana_alerting_snapshot', SCRIPT)
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


def fake_fetch(name, required):
    responses = {
        'alert_rules': [{'uid':'a', 'title':'Host Down'}],
        'contact_points': [{'uid':'cp1','name':'Email', 'settings':{'secretValue':'REDACT_TEST_ONLY'}}],
        'policies': {'receiver':'Email'},
        'mute_timings': [],
        'templates': [],
        'alert_rules_export': {'apiVersion':1, 'groups':[]},
        'contact_points_export': {'apiVersion':1, 'contactPoints':[]},
        'policies_export': {'apiVersion':1,'policies':[]},
        'mute_timings_export': {'apiVersion':1,'muteTimes':[]},
    }
    return {'state': 'ok', 'body': responses[name]}


class SnapshotTests(unittest.TestCase):
    def test_endpoints_read_only_get(self):
        self.assertTrue(all(path.startswith('/api/') for path, _ in s.API.values()))
        self.assertEqual(len(s.API), 9)

    def test_canonical_hash_is_independent_of_dict_key_order(self):
        self.assertEqual(s.canonical({'b':2,'a':1}), s.canonical({'a':1,'b':2}))

    def test_capture_creates_private_complete_snapshot(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(s, 'check_private_dir'):
            root = Path(d)
            result = s.run('capture', root, 3000, 'test', 'test', fetch=fake_fetch)
            path = Path(result['snapshot'])
            self.assertTrue(path.exists())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), result['sha256_bytes'])
            self.assertEqual(set(json.loads(path.read_text())['endpoints']), set(s.API))
            self.assertEqual(result['categories']['alert_rules']['count'], 1)
            self.assertNotIn('REDACT_TEST_ONLY', json.dumps(result))

    def test_compare_same_returns_no_changes(self):
        baseline = {'schema':'grafana-alerting-snapshot-v1','endpoints':s.collect(fake_fetch)}
        with tempfile.TemporaryDirectory() as d, mock.patch.object(s,'check_private_dir'), mock.patch.object(s,'safe_read_snapshot',return_value=baseline):
            value=s.run('compare',Path(d),3000,'u','p',baseline=str(Path(d)/('alerting-20260101T000000Z-'+'a'*12+'.json')),expected_sha='f'*64,fetch=fake_fetch)
            self.assertEqual(value['status'], 'SIN CAMBIOS')

    def test_compare_changed_detects_contact_points(self):
        baseline={'schema':'grafana-alerting-snapshot-v1','endpoints':s.collect(fake_fetch)}
        baseline['endpoints']['contact_points']['body'][0]['name']='OLD'
        with tempfile.TemporaryDirectory() as d, mock.patch.object(s,'check_private_dir'), mock.patch.object(s,'safe_read_snapshot',return_value=baseline):
            value=s.run('compare',Path(d),3000,'u','p',baseline=str(Path(d)/('alerting-20260101T000000Z-'+'a'*12+'.json')),expected_sha='f'*64,fetch=fake_fetch)
            self.assertEqual(value['changed_categories'], ['contact_points'])

    def test_compare_requires_baseline(self):
        with tempfile.TemporaryDirectory() as d,mock.patch.object(s,'check_private_dir'):
            with self.assertRaises(s.SnapshotError):
                s.run('compare',Path(d),3000,'u','p',fetch=fake_fetch)

    def test_reference_rejects_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            p=root/('alerting-20260101T000000Z-'+'a'*12+'.json')
            p.write_text('{}')
            with self.assertRaises(s.SnapshotError):
                s.safe_read_snapshot(root,p,'0'*64)

    def test_reference_rejects_other_path(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with self.assertRaises(s.SnapshotError):
                s.safe_read_snapshot(root,root/'../secret.json','0'*64)

    def test_optional_unavailable(self):
        def fetch(name,required):
            return {'state':'unsupported','body':None} if not required else fake_fetch(name,required)
        result=s.collect(fetch)
        self.assertEqual(result['templates']['state'],'unsupported')
        self.assertEqual(result['alert_rules']['state'],'ok')

    def test_check_private_dir_rejects_user_dir(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d,0o700)
            if os.geteuid() != 0:
                with self.assertRaises(s.SnapshotError):
                    s.check_private_dir(Path(d))

    def test_local_client_uses_get_and_does_not_follow_proxy(self):
        class DummyResponse:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, size): return b'[]'
        class DummyOpener:
            def open(self, request, timeout=0):
                self.request = request
                return DummyResponse()
        dummy = DummyOpener()
        with mock.patch.object(s.urllib.request, 'build_opener', return_value=dummy) as builder:
            result = s.api_fetcher(3000, 'user', 'pass')('alert_rules', True)
        self.assertEqual(result['body'], [])
        self.assertEqual(dummy.request.get_method(), 'GET')
        self.assertTrue(dummy.request.full_url.startswith('http://127.0.0.1:3000/'))
        self.assertTrue(any(isinstance(x, s.urllib.request.ProxyHandler) for x in builder.call_args.args))

    def test_optional_404_does_not_abort_snapshot(self):
        error = s.urllib.error.HTTPError('http://127.0.0.1:3000/test', 404, 'not found', {}, None)
        class DummyOpener:
            def open(self, request, timeout=0):
                raise error
        with mock.patch.object(s.urllib.request, 'build_opener', return_value=DummyOpener()):
            result = s.api_fetcher(3000, 'user', 'pass')('templates', False)
            self.assertEqual(result['state'], 'unsupported')
            with self.assertRaises(s.SnapshotError):
                s.api_fetcher(3000, 'user', 'pass')('alert_rules', True)

    def test_no_redirect(self):
        with self.assertRaises(s.SnapshotError):
            s.NoRedirect().redirect_request(None,None,302,'redirect',{},'http://evil.example')


if __name__ == '__main__':
    unittest.main()
