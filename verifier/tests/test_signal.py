"""Unit tests for verifier.signal — the ONE pass/fail decision.

These tests mock ``exec_as`` so they run without Docker.  The signal module
is the single most important thing to test, because a wrong verdict silently
corrupts every label.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Ensure the repo root is importable
ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from verifier.signal import credential_accessible, escalated  # noqa: E402


MOCK_TOKEN = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"


class TestEscalated(unittest.TestCase):
    """Test the canary-based escalation signal."""

    @patch("verifier.signal.exec_as")
    def test_positive_when_token_in_output(self, mock_exec):
        """If the canary token appears in stdout, escalation succeeded."""
        mock_exec.return_value = (0, f"some preamble\n{MOCK_TOKEN}\n", "")
        ok, evidence = escalated("app01", "appuser", ["sh", "-c", "test"], MOCK_TOKEN)
        self.assertTrue(ok)
        self.assertIn(MOCK_TOKEN, evidence)

    @patch("verifier.signal.exec_as")
    def test_negative_when_token_absent(self, mock_exec):
        """If the canary is not reached, escalation failed."""
        mock_exec.return_value = (1, "Permission denied", "cat: /root/.ascend_canary: Permission denied")
        ok, evidence = escalated("app01", "appuser", ["sh", "-c", "test"], MOCK_TOKEN)
        self.assertFalse(ok)
        self.assertIn("Permission denied", evidence)

    @patch("verifier.signal.exec_as")
    def test_negative_on_empty_output(self, mock_exec):
        """Empty output is a definitive negative."""
        mock_exec.return_value = (0, "", "")
        ok, evidence = escalated("app01", "appuser", ["sh", "-c", "test"], MOCK_TOKEN)
        self.assertFalse(ok)

    @patch("verifier.signal.exec_as")
    def test_evidence_truncated_to_400_chars(self, mock_exec):
        """Evidence should be at most 400 chars to keep records compact."""
        long_output = "x" * 1000 + MOCK_TOKEN
        mock_exec.return_value = (0, long_output, "")
        ok, evidence = escalated("app01", "appuser", ["sh", "-c", "test"], MOCK_TOKEN)
        self.assertTrue(ok)
        self.assertLessEqual(len(evidence), 400)

    @patch("verifier.signal.exec_as")
    def test_partial_token_is_negative(self, mock_exec):
        """A partial match of the token should not be treated as positive."""
        mock_exec.return_value = (0, MOCK_TOKEN[:10], "")
        ok, _ = escalated("app01", "appuser", ["sh", "-c", "test"], MOCK_TOKEN)
        self.assertFalse(ok)


class TestCredentialAccessible(unittest.TestCase):
    """Test the credential-read signal (T1552.001)."""

    @patch("verifier.signal.exec_as")
    def test_positive_when_private_key_readable(self, mock_exec):
        """Success when the file is readable and contains a key header."""
        mock_exec.return_value = (
            0,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nbase64data...\n-----END OPENSSH PRIVATE KEY-----\n",
            "",
        )
        ok, evidence = credential_accessible("web01", "www-data", "/var/www/.ssh/id_rsa")
        self.assertTrue(ok)

    @patch("verifier.signal.exec_as")
    def test_negative_when_permission_denied(self, mock_exec):
        """Failure when the file is not readable."""
        mock_exec.return_value = (1, "", "cat: /var/www/.ssh/id_rsa: Permission denied")
        ok, evidence = credential_accessible("web01", "www-data", "/var/www/.ssh/id_rsa")
        self.assertFalse(ok)
        self.assertIn("Permission denied", evidence)

    @patch("verifier.signal.exec_as")
    def test_negative_when_not_a_key(self, mock_exec):
        """A readable file that isn't a private key is a negative."""
        mock_exec.return_value = (0, "just some text file content\n", "")
        ok, _ = credential_accessible("web01", "www-data", "/var/www/.ssh/id_rsa")
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
