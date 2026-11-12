"""Offline validation: python3 -m unittest discover -s tests -v"""
from __future__ import annotations

import importlib.util
from contextlib import closing
import json
import pathlib
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
FILE = ROOT / 'monitorizacion' / 'integrations' / 'traefik_wazuh_bridge' / 'bridge.py'
spec = importlib.util.spec_from_file_location('traefik_bridge', FILE)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class BridgeTests(unittest.TestCase):
    def sample(self, path='/dashboard', status=401, ip='198.51.100.24', method='GET'):
        return json.dumps({'RequestMethod': method, 'RequestPath': path,
                           'DownstreamStatus': status, 'ClientHost': ip,
                           'RouterName': 'default-security-triage-dashboard'})

    def cfg(self, temp):
        logs = temp / 'events'
        state = temp / 'state'
        logs.mkdir()
        state.mkdir()
        return {'loki_url': 'http://127.0.0.1:13100',
                'query': bridge.DEFAULT_QUERY,
                'output_path': str(logs / 'traefik.jsonl'),
                'state_path': str(state / 'state.sqlite'),
                'poll_seconds': 15, 'lag_seconds': 10, 'overlap_seconds': 20,
                'initial_lookback_seconds': 120, 'window_seconds': 30,
                'max_windows_per_poll': 12, 'limit': 1000,
                'max_output_bytes': 1024 * 1024}

    def test_json_minimal_and_query_removed(self):
        ev = bridge.translate({'app': 'traefik'}, '10', self.sample(path='/dashboard?password=secret'))
        self.assertEqual(ev['integration'], 'traefik_loki')
        self.assertEqual(ev['RequestPath'], '/dashboard')
        self.assertNotIn('secret', json.dumps(ev))
        self.assertEqual(ev['ClientHost'], '198.51.100.24')

    def test_benign_200_filtered(self):
        self.assertIsNone(bridge.translate({}, '10', self.sample('/dashboard', 200)))

    def test_sensitive_200_included(self):
        self.assertIsNotNone(bridge.translate({}, '10', self.sample('/.env', 200)))

    def test_invalid_input_filtered(self):
        self.assertIsNone(bridge.translate({}, '10', 'not json'))
        self.assertIsNone(bridge.translate({}, '10', json.dumps(['list'])))

    def test_deterministic_event_id(self):
        src = self.sample()
        self.assertEqual(bridge.event_id({'a': 'b'}, '123', src), bridge.event_id({'a': 'b'}, '123', src))
        self.assertNotEqual(bridge.event_id({'a': 'b'}, '123', src), bridge.event_id({'a': 'b'}, '124', src))

    def test_validate_paths(self):
        with tempfile.TemporaryDirectory() as td:
            temp = pathlib.Path(td)
            cfg = self.cfg(temp)
            path = temp / 'config.json'
            path.write_text(json.dumps(cfg))
            self.assertEqual(bridge.load_config(str(path))['limit'], 1000)
            cfg['state_path'] = str(temp / 'events' / 'bad.sqlite')
            path.write_text(json.dumps(cfg))
            with self.assertRaises(bridge.BridgeError):
                bridge.load_config(str(path))

    def test_cycle_deduplicates_across_polls_and_persists(self):
        with tempfile.TemporaryDirectory() as td:
            temp = pathlib.Path(td)
            cfg = self.cfg(temp)
            now = 1700000000000000000
            ts = now - 30000000000
            def fake_fetch(config, start, end):
                return [(ts, {'app': 'traefik', 'namespace': 'kube-system'}, self.sample())] if start <= ts <= end else []
            with patch.object(bridge, 'fetch_loki', side_effect=fake_fetch):
                bridge.cycle(cfg, now_ns=now)
                bridge.cycle(cfg, now_ns=now + 10000000000)
            rows = (temp / 'events' / 'traefik.jsonl').read_text().splitlines()
            self.assertEqual(len(rows), 1)
            with closing(sqlite3.connect(cfg['state_path'])) as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM seen').fetchone()[0], 1)

    def test_dry_run_does_not_write_files(self):
        with tempfile.TemporaryDirectory() as td:
            temp = pathlib.Path(td)
            cfg = self.cfg(temp)
            with patch.object(bridge, 'fetch_loki', return_value=[]):
                bridge.cycle(cfg, dry_run=True)
            self.assertFalse(pathlib.Path(cfg['state_path']).exists())
            self.assertFalse(pathlib.Path(cfg['output_path']).exists())

    def test_query_saturation_does_not_advance(self):
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as td:
            temp = pathlib.Path(td)
            cfg = self.cfg(temp)
            cfg['limit'] = 1
            now = 1700000000000000000
            ts = now - 30000000000
            response = {
                'status': 'success', 'data': {
                    'resultType': 'streams', 'result': [{
                        'stream': {'app': 'traefik', 'namespace': 'kube-system'},
                        'values': [[str(ts), self.sample()]]
                    }]
                }
            }
            reader = MagicMock()
            reader.__enter__.return_value = reader
            reader.__exit__.return_value = False
            reader.read.return_value = json.dumps(response).encode()
            with patch.object(bridge.urllib.request, 'urlopen', return_value=reader):
                with self.assertRaisesRegex(bridge.BridgeError, 'limit'):
                    bridge.cycle(cfg, now_ns=now)
            with closing(sqlite3.connect(cfg['state_path'])) as db:
                row = db.execute("SELECT value FROM settings WHERE key='cursor_ns'").fetchone()
                self.assertIsNotNone(row)
                self.assertLess(int(row[0]), ts, "Saturated window must not be skipped")
            output = pathlib.Path(cfg['output_path'])
            self.assertFalse(output.exists() and output.stat().st_size > 0,
                             "No selected events should be written from truncated page")

    def test_xml_rules_parse(self):
        import xml.etree.ElementTree as ET
        path = ROOT / 'monitorizacion/integrations/traefik_wazuh_bridge/traefik_rules.xml'
        root = ET.parse(path).getroot()
        self.assertEqual(root.attrib['name'], 'traefik_web,custom_detection,')
        ids = [node.attrib['id'] for node in root.findall('rule')]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 6)

    def test_helmchartconfig_declares_sanitization(self):
        content = (ROOT / 'monitorizacion/manifests/traefik-access-logs.helmchartconfig.yaml').read_text()
        self.assertIn('queryparameters.defaultmode=drop', content)
        self.assertIn('defaultmode: drop', content)


if __name__ == '__main__':
    unittest.main()
