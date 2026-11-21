"""Unit tests for cross-host credential staging in verifier.adapters.lateral_ssh."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from verifier.adapters import RunContext
from verifier.adapters.lateral_ssh import lateral_ssh


class TestLateralSshStaging(unittest.TestCase):
    def test_local_key_uses_cp_without_cross_host_read(self):
        ctx = RunContext(
            host="web01",
            start_user="www-data",
            technique={
                "id": "T1021.004+T1550",
                "key_path": "/var/www/.ssh/id_rsa",
                "to_host": "app01",
                "to_user": "appuser",
            },
            canary_token="tok",
            canary_path="/root/.ascend_canary",
            run_id="r1",
            container_prefix="ascend-",
        )
        with patch("verifier.adapters.lateral_ssh.exec_as") as mock_exec, \
             patch("verifier.adapters.lateral_ssh.session_established", return_value=(True, "appuser")) as mock_sess:
            res = lateral_ssh(ctx)
        self.assertTrue(res.escalated)
        mock_exec.assert_not_called()
        mock_sess.assert_called_once()
        cmd = res.raw_cmd[2]
        self.assertIn("cp /var/www/.ssh/id_rsa $TMPKEY", cmd)
        self.assertIn("rm -f $TMPKEY", cmd)

    def test_cross_host_key_stages_via_base64_and_cleans_up(self):
        ctx = RunContext(
            host="ci01",
            start_user="ciuser",
            technique={
                "id": "T1021.004+T1550",
                "key_source_host": "web01",
                "key_source_user": "www-data",
                "key_source_path": "/var/www/.ssh/id_rsa",
                "to_host": "db01",
                "to_user": "dbuser",
            },
            canary_token="tok",
            canary_path="/root/.ascend_canary",
            run_id="r2",
            container_prefix="ascend-",
        )
        fake_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE\n-----END OPENSSH PRIVATE KEY-----\n"
        with patch("verifier.adapters.lateral_ssh.exec_as", return_value=(0, fake_key, "")) as mock_exec, \
             patch("verifier.adapters.lateral_ssh.session_established", return_value=(True, "dbuser")):
            res = lateral_ssh(ctx)
        self.assertTrue(res.escalated)
        mock_exec.assert_called_once_with(
            "web01", "www-data", ["cat", "/var/www/.ssh/id_rsa"], prefix="ascend-"
        )
        cmd = res.raw_cmd[2]
        self.assertIn("base64 -d > $TMPKEY", cmd)
        self.assertIn("chmod 600 $TMPKEY", cmd)
        self.assertIn("rm -f $TMPKEY", cmd)

    def test_cross_host_key_read_failure_returns_not_escalated(self):
        ctx = RunContext(
            host="ci01",
            start_user="ciuser",
            technique={
                "id": "T1021.004+T1550",
                "key_source_host": "web01",
                "key_source_user": "www-data",
                "key_source_path": "/var/www/.ssh/missing",
                "to_host": "db01",
                "to_user": "dbuser",
            },
            canary_token="tok",
            canary_path="/root/.ascend_canary",
            run_id="r3",
            container_prefix="ascend-",
        )
        with patch("verifier.adapters.lateral_ssh.exec_as", return_value=(1, "", "No such file")):
            res = lateral_ssh(ctx)
        self.assertFalse(res.escalated)
        self.assertEqual(res.status, "not_escalated")
        self.assertIn("failed to read harvested key", res.evidence)


if __name__ == "__main__":
    unittest.main()
