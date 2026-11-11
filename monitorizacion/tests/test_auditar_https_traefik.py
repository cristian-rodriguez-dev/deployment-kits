import importlib.util
import pathlib
import unittest
from unittest import mock

path = pathlib.Path(__file__).resolve().parents[1] / 'scripts' / 'auditar_https_traefik.py'
spec = importlib.util.spec_from_file_location('https_audit', path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def obj(rule='Host(`grafana.lab.local`)'):
    return {
        'routes': {'items': [{'spec': {'routes': [{'match': rule}]}}]},
        'service': {'status': {'loadBalancer': {'ingress': [{'ip': '192.168.56.20'}]}}},
        'timeout': 2,
        'warn_days': 30,
    }


class HTTPSAuditTests(unittest.TestCase):
    def test_host_from_ingressroute(self):
        self.assertEqual(mod.candidate_route_hosts(obj()['routes']), ['grafana.lab.local'])

    def test_host_with_path_prefix(self):
        p = obj('Host(`grafana.lab.local`) && PathPrefix(`/ui`)')
        self.assertEqual(mod.candidate_route_hosts(p['routes']), ['grafana.lab.local'])

    def test_skip_public_ip(self):
        p = obj()
        p['service']['status']['loadBalancer']['ingress'][0]['ip'] = '8.8.8.8'
        out = mod.analyse(p)
        self.assertEqual(out['reason'], 'SIN_IP_INTERNA_EN_LOADBALANCER')
        self.assertEqual(out['tls_connection'], 'NO_EVALUADO')

    def test_no_route_hostname(self):
        p = obj('PathPrefix(`/`)')
        out = mod.analyse(p)
        self.assertEqual(out['reason'], 'HOST_AMBIGUO_O_NO_EXTRAIBLE')

    def test_skip_arbitrary_hostname_override(self):
        p = obj()
        p['hostname'] = 'other.example.com'
        out = mod.analyse(p)
        self.assertEqual(out['reason'], 'HOSTNAME_NO_PRESENTE_EN_INGRESSROUTE')

    @mock.patch.object(mod, 'http_probe', return_value={'http_status': 301, 'http_redirect': 'HTTPS_OBSERVADO'})
    @mock.patch.object(mod, 'tls_probe', return_value={'tls_connection': 'OK', 'trusted_by_host': 'NO'})
    def test_probe_one_safe_private_endpoint(self, tls, http):
        out = mod.analyse(obj())
        self.assertEqual(out['tls_connection'], 'OK')
        self.assertEqual(out['http_redirect'], 'HTTPS_OBSERVADO')
        tls.assert_called_once_with('192.168.56.20', 'grafana.lab.local', 2.0, 30)
        http.assert_called_once()

    @mock.patch.object(mod, 'http_probe')
    @mock.patch.object(mod, 'tls_probe')
    def test_ambiguous_host_skips_probe(self, tls, http):
        p = obj('Host(`grafana.lab.local`) || Host(`other.lab.local`)')
        self.assertEqual(mod.analyse(p)['reason'], 'HOST_AMBIGUO_O_NO_EXTRAIBLE')
        tls.assert_not_called()
        http.assert_not_called()

    def test_invalid_timeout(self):
        p = obj()
        p['timeout'] = 30
        with self.assertRaises(ValueError):
            mod.analyse(p)

    def test_no_secret_material_in_output(self):
        with mock.patch.object(mod, 'tls_probe', return_value={'tls_connection': 'OK'}), mock.patch.object(mod, 'http_probe', return_value={'http_status': 404, 'http_redirect': 'NO_OBSERVADO_EN_HEAD_RAIZ'}):
            result = mod.analyse(obj())
        serialized = str(result)
        self.assertNotIn('grafana.lab.local', serialized)
        self.assertNotIn('192.168.56.20', serialized)


if __name__ == '__main__':
    unittest.main()
