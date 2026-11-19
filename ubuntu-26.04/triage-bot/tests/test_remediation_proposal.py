"""Pruebas offline del contrato; no red, DB, contenedores ni AWX."""
import unittest
from datetime import datetime, timedelta, timezone

from app.remediation_proposal import propose

NOW = datetime(2026, 11, 16, 11, 0, tzinfo=timezone.utc)
ASSET = {"name": "servidor-lab", "department": "Sistemas"}
OBS = {
    "source": "systemd", "service": "alloy.service", "state": "failed",
    "host": "servidor-lab", "department": "Sistemas",
    "observed_at_utc": NOW.isoformat(),
}


class RemediationProposalTests(unittest.TestCase):
    def make(self, **overrides):
        params = dict(incident_id=19, asset=ASSET, identity_verified=True,
                      observation=OBS, now=NOW)
        params.update(overrides)
        return propose(**params)

    def assert_never_executes(self, value):
        self.assertFalse(value["execution_allowed"])
        self.assertTrue(value["requires_approval"])

    def test_verified_inactive_service_proposes_only_diagnosis(self):
        result = self.make()
        self.assertEqual(result["status"], "proposed")
        self.assertEqual(result["action_id"], "diagnose_service")
        self.assertEqual(result["target"]["service"], "alloy.service")
        self.assert_never_executes(result)

    def test_missing_evidence_requests_investigation(self):
        result = self.make(observation=None)
        self.assertEqual(result["status"], "investigate")
        self.assertIsNone(result["target"])
        self.assert_never_executes(result)

    def test_unverified_identity_no_target(self):
        result = self.make(identity_verified=False)
        self.assertEqual(result["status"], "investigate")
        self.assertIsNone(result["target"])
        self.assert_never_executes(result)

    def test_unknown_department_rejected(self):
        result = self.make(asset={"name": "servidor-lab", "department": "unknown"})
        self.assertEqual(result["reason_code"], "unverified_asset_identity")
        self.assert_never_executes(result)

    def test_disallowed_action_fails_closed(self):
        result = self.make(requested_action="restart_service")
        self.assertEqual(result["status"], "no_action")
        self.assertEqual(result["reason_code"], "action_not_allowed")
        self.assert_never_executes(result)

    def test_disallowed_service_fails_closed(self):
        result = self.make(observation={**OBS, "service": "sshd.service"})
        self.assertEqual(result["status"], "no_action")
        self.assert_never_executes(result)

    def test_active_service_no_action(self):
        result = self.make(observation={**OBS, "state": "active"})
        self.assertEqual(result["status"], "no_action")
        self.assert_never_executes(result)

    def test_scope_mismatch_blocks_proposal(self):
        result = self.make(observation={**OBS, "department": "Devs"})
        self.assertEqual(result["status"], "investigate")
        self.assert_never_executes(result)

    def test_stale_observation_blocks_proposal(self):
        value = (NOW - timedelta(minutes=6)).isoformat()
        result = self.make(observation={**OBS, "observed_at_utc": value})
        self.assertEqual(result["status"], "investigate")
        self.assert_never_executes(result)

    def test_future_observation_blocks_proposal(self):
        value = (NOW + timedelta(seconds=1)).isoformat()
        result = self.make(observation={**OBS, "observed_at_utc": value})
        self.assertEqual(result["status"], "investigate")
        self.assert_never_executes(result)

    def test_invalid_time_blocks_proposal(self):
        result = self.make(observation={**OBS, "observed_at_utc": "yesterday"})
        self.assertEqual(result["status"], "investigate")
        self.assert_never_executes(result)

    def test_ip_as_host_not_trusted(self):
        asset = {"name": "192.168.56.20", "department": "Sistemas"}
        obs = {**OBS, "host": asset["name"]}
        result = self.make(asset=asset, observation=obs)
        self.assertEqual(result["reason_code"], "unverified_asset_identity")
        self.assert_never_executes(result)

    def test_unknown_state_requires_investigation(self):
        result = self.make(observation={**OBS, "state": "mystery"})
        self.assertEqual(result["status"], "investigate")
        self.assert_never_executes(result)

    def test_bad_id_never_executes(self):
        result = self.make(incident_id=True)
        self.assertEqual(result["status"], "no_action")
        self.assert_never_executes(result)


if __name__ == "__main__":
    unittest.main()
