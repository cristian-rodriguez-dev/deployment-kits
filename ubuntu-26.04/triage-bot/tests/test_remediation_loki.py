"""Pruebas locales: sin llamadas a Kubernetes, Grafana, AWX ni Gemini."""
import unittest
from datetime import datetime, timedelta, timezone

from app.remediation_loki import propose_loki_diagnostic

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
SIGNAL = {
    "source": "grafana", "rule_uid": "awx-critical-loki-notready",
    "component": "loki", "status": "firing",
}
OBS = {
    "source": "kubernetes_api", "namespace": "logging", "pod": "loki-0",
    "container": "loki", "pod_found": True, "container_found": True,
    "ready": False, "observed_at_utc": NOW.isoformat(),
}


class LokiDiagnosticTests(unittest.TestCase):
    def make(self, **kwargs):
        arguments = dict(incident_id=19, signal=SIGNAL, observation=OBS,
                         observation_trusted=True, now=NOW)
        arguments.update(kwargs)
        value = propose_loki_diagnostic(**arguments)
        self.assertIs(value["execution_allowed"], False)
        self.assertIs(value["requires_approval"], True)
        return value

    def test_verified_not_ready_proposes_only_diagnosis(self):
        value = self.make()
        self.assertEqual(value["status"], "proposed")
        self.assertEqual(value["action_id"], "diagnose_k3s_pod")
        self.assertEqual(value["target"], {"namespace": "logging", "pod": "loki-0", "container": "loki"})
        self.assertEqual(value["risk"], "low")

    def test_ready_service_not_action(self):
        value = self.make(observation={**OBS, "ready": True})
        self.assertEqual(value["status"], "no_action")
        self.assertIsNone(value["target"])

    def test_untrusted_observation_investigate(self):
        self.assertEqual(self.make(observation_trusted=False)["reason_code"], "untrusted_observation")

    def test_nonboolean_trust_denied(self):
        self.assertEqual(self.make(observation_trusted=1)["status"], "investigate")

    def test_missing_observation_investigate(self):
        self.assertEqual(self.make(observation=None)["reason_code"], "missing_observation")

    def test_missing_signal_investigate(self):
        self.assertEqual(self.make(signal=None)["reason_code"], "missing_signal")

    def test_unsupported_grafana_uid_not_action(self):
        signal = {**SIGNAL, "rule_uid": "other-rule"}
        self.assertEqual(self.make(signal=signal)["reason_code"], "unsupported_signal")

    def test_wazuh_signal_is_not_supported(self):
        self.assertEqual(self.make(signal={**SIGNAL, "source": "wazuh"})["status"], "no_action")

    def test_wrong_component_not_supported(self):
        self.assertEqual(self.make(signal={**SIGNAL, "component": "wazuh"})["status"], "no_action")

    def test_resolved_alert_not_action(self):
        self.assertEqual(self.make(signal={**SIGNAL, "status": "resolved"})["reason_code"], "signal_resolved")

    def test_unknown_alert_state_requires_investigation(self):
        self.assertEqual(self.make(signal={**SIGNAL, "status": "pending"})["status"], "investigate")

    def test_wrong_namespace_rejected(self):
        self.assertEqual(self.make(observation={**OBS, "namespace": "default"})["reason_code"], "observation_scope_mismatch")

    def test_wrong_pod_rejected(self):
        self.assertEqual(self.make(observation={**OBS, "pod": "another-pod"})["status"], "investigate")

    def test_wrong_container_rejected(self):
        self.assertEqual(self.make(observation={**OBS, "container": "nginx"})["status"], "investigate")

    def test_wrong_observation_source_rejected(self):
        self.assertEqual(self.make(observation={**OBS, "source": "prometheus"})["status"], "investigate")

    def test_missing_pod_requires_investigation(self):
        self.assertEqual(self.make(observation={**OBS, "pod_found": False})["reason_code"], "missing_target_in_kubernetes")

    def test_missing_container_requires_investigation(self):
        self.assertEqual(self.make(observation={**OBS, "container_found": False})["status"], "investigate")

    def test_unknown_readiness_requires_investigation(self):
        self.assertEqual(self.make(observation={**OBS, "ready": None})["reason_code"], "unknown_readiness")

    def test_string_false_readiness_rejected(self):
        self.assertEqual(self.make(observation={**OBS, "ready": "false"})["status"], "investigate")

    def test_stale_observation_rejected(self):
        obs = {**OBS, "observed_at_utc": (NOW - timedelta(seconds=301)).isoformat()}
        self.assertEqual(self.make(observation=obs)["reason_code"], "stale_or_future_observation")

    def test_future_observation_rejected(self):
        obs = {**OBS, "observed_at_utc": (NOW + timedelta(seconds=1)).isoformat()}
        self.assertEqual(self.make(observation=obs)["status"], "investigate")

    def test_at_maximum_age_accepted(self):
        obs = {**OBS, "observed_at_utc": (NOW - timedelta(seconds=300)).isoformat()}
        self.assertEqual(self.make(observation=obs)["status"], "proposed")

    def test_invalid_timestamp_rejected(self):
        self.assertEqual(self.make(observation={**OBS, "observed_at_utc": "yesterday"})["status"], "investigate")

    def test_naive_now_rejected(self):
        self.assertEqual(self.make(now=datetime(2026, 11, 16, 12, 0))["status"], "investigate")

    def test_bool_id_invalid(self):
        self.assertEqual(self.make(incident_id=True)["reason_code"], "invalid_input")

    def test_negative_id_invalid(self):
        self.assertEqual(self.make(incident_id=-1)["status"], "no_action")

    def test_never_modifies_inputs(self):
        s, o = SIGNAL.copy(), OBS.copy()
        self.make()
        self.assertEqual(s, SIGNAL)
        self.assertEqual(o, OBS)


if __name__ == "__main__":
    unittest.main()
