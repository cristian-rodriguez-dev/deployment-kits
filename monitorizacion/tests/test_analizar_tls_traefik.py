import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "analizar_tls_traefik.py"
spec = importlib.util.spec_from_file_location("analyze_traefik", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def sample_route(tls):
    return {"metadata": {"namespace": "apps", "name": "private-route"}, "spec": {"tls": tls, "routes": [{"middlewares": []}]}}


class TraefikSecurityTests(unittest.TestCase):
    def test_tls_secret_found_correct_type(self):
        payload = {"routes": {"items": [sample_route({"secretName": "tls"})]}, "secret_metadata_available": True, "secret_metadata": "apps\ttls\tkubernetes.io/tls\n"}
        got = mod.analyze(payload)
        self.assertEqual(got["tls_secrets_found_correct_type"], 1)
        self.assertTrue(got["tls_secret_references_consistent"])

    def test_missing_secret_not_silenced(self):
        payload = {"routes": {"items": [sample_route({"secretName": "tls"})]}, "secret_metadata_available": True}
        self.assertEqual(mod.analyze(payload)["tls_secrets_missing"], 1)

    def test_rbac_failure_does_not_claim_missing_secret(self):
        payload = {"routes": {"items": [sample_route({"secretName": "tls"})]}, "secret_metadata_available": False}
        got = mod.analyze(payload)
        self.assertEqual(got["tls_secrets_unchecked"], 1)
        self.assertEqual(got["tls_secrets_missing"], 0)

    def test_certresolver_without_secret_expected(self):
        payload = {"routes": {"items": [sample_route({"certResolver": "le"})]}, "secret_metadata_available": False}
        got = mod.analyze(payload)
        self.assertEqual(got["tls_cert_resolver"], 1)
        self.assertEqual(got["tls_secrets_unchecked"], 0)

    def test_empty_tls_is_default_not_missing(self):
        got = mod.analyze({"routes": {"items": [sample_route({})]}})
        self.assertEqual(got["tls_default_or_other"], 1)
        self.assertEqual(got["routes_with_tls"], 1)

    def test_no_tls_declared(self):
        got = mod.analyze({"routes": {"items": [{"metadata": {}, "spec": {}}]}})
        self.assertEqual(got["routes_without_tls"], 1)

    def test_classify_loadbalancer_without_disclosing_addresses(self):
        payload = {"traefik_service": {"spec": {"type": "LoadBalancer", "ports": [{"port": 443}, {"port": 80}]}, "status": {"loadBalancer": {"ingress": [{"ip": "192.168.56.20"}, {"ip": "8.8.8.8"}]}}}}
        got = mod.analyze(payload)
        self.assertEqual(got["service_loadbalancer_private_or_nonglobal"], 1)
        self.assertEqual(got["service_loadbalancer_global_ip"], 1)
        self.assertNotIn("192.168.56", str(got))

    def test_other_secret_type(self):
        payload = {"routes": {"items": [sample_route({"secretName": "tls"})]}, "secret_metadata_available": True, "secret_metadata": "apps\ttls\tOpaque\n"}
        self.assertEqual(mod.analyze(payload)["tls_secrets_wrong_type"], 1)


if __name__ == "__main__":
    unittest.main()
