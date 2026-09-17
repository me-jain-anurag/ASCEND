"""Unit tests for verifier.scope — scope.yaml loading and validation.

These tests parse the real scope.yaml and verify schema enforcement.
No Docker required.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from verifier.scope import load  # noqa: E402

SCOPE_YAML = ROOT / "scope.yaml"


class TestScopeLoading(unittest.TestCase):
    """Test loading and validating the real scope.yaml."""

    def test_load_valid_scope(self):
        """The real scope.yaml should load without errors."""
        scope = load(SCOPE_YAML)
        self.assertGreater(len(scope.techniques), 0)
        self.assertEqual(scope.canary_path, "/root/.ascend_canary")
        self.assertEqual(scope.reset_mode, "recreate")

    def test_techniques_have_required_fields(self):
        """Every technique must have id, adapter, check, hosts, start_user."""
        scope = load(SCOPE_YAML)
        for t in scope.techniques:
            self.assertTrue(t.id, f"technique missing id")
            self.assertTrue(t.adapter, f"{t.id}: missing adapter")
            self.assertTrue(t.check, f"{t.id}: missing check")
            self.assertGreater(len(t.hosts), 0, f"{t.id}: empty hosts")
            self.assertTrue(t.start_user, f"{t.id}: missing start_user")

    def test_all_adapters_are_known(self):
        """Every adapter name must map to a registered adapter."""
        scope = load(SCOPE_YAML)
        known = {"config_abuse", "lateral_ssh", "anchor_cve"}
        for t in scope.techniques:
            self.assertIn(t.adapter, known, f"{t.id}: unknown adapter {t.adapter}")

    def test_technique_lookup_by_id(self):
        """scope.technique() should return the right entry."""
        scope = load(SCOPE_YAML)
        t = scope.technique("T1548.003")
        self.assertEqual(t.adapter, "config_abuse")
        self.assertIn("app01", t.hosts)

    def test_technique_lookup_raises_on_unknown(self):
        """scope.technique() should raise KeyError for unknown ids."""
        scope = load(SCOPE_YAML)
        with self.assertRaises(KeyError):
            scope.technique("T9999.999")

    def test_hosts_are_valid_inventory_hosts(self):
        """Every host in a technique's hosts list must exist in inventory."""
        scope = load(SCOPE_YAML)
        if scope.inventory_hosts:
            for t in scope.techniques:
                for h in t.hosts:
                    self.assertIn(h, scope.inventory_hosts,
                                  f"{t.id}: host {h} not in inventory")


class TestScopeValidation(unittest.TestCase):
    """Test that invalid scope files are rejected."""

    def _write_scope(self, content: str) -> Path:
        """Write a temporary scope.yaml and return its path."""
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8",
        )
        f.write(content)
        f.flush()
        return Path(f.name)

    def test_reject_missing_verifier_section(self):
        """A scope.yaml without a verifier section should fail."""
        path = self._write_scope("techniques:\n  T1548.001:\n    name: test\n")
        with self.assertRaises(ValueError):
            load(path)

    def test_reject_unknown_adapter(self):
        """A technique with an unknown adapter should fail at load time."""
        path = self._write_scope("""
inventory:
  hosts:
    app01: { role: app }
verifier:
  techniques:
    - id: T9999
      adapter: totally_fake
      check: canary
      hosts: [app01]
      start_user: appuser
""")
        with self.assertRaises(ValueError) as ctx:
            load(path)
        self.assertIn("unknown adapter", str(ctx.exception))

    def test_reject_empty_techniques(self):
        """An empty techniques list should fail."""
        path = self._write_scope("""
verifier:
  techniques: []
""")
        with self.assertRaises(ValueError):
            load(path)

    def test_reject_technique_missing_id(self):
        """A technique without an id should fail."""
        path = self._write_scope("""
verifier:
  techniques:
    - adapter: config_abuse
      check: sudo_rule
      hosts: [app01]
      start_user: appuser
""")
        with self.assertRaises(ValueError):
            load(path)

    def test_reject_invalid_host(self):
        """A technique targeting a host not in inventory should fail."""
        path = self._write_scope("""
inventory:
  hosts:
    web01: { role: web }
verifier:
  techniques:
    - id: T1548.003
      adapter: config_abuse
      check: sudo_rule
      hosts: [nonexistent_host]
      start_user: appuser
""")
        with self.assertRaises(ValueError) as ctx:
            load(path)
        self.assertIn("not in inventory", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
