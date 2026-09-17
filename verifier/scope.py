"""Load and validate the verifier section of scope.yaml.

The verifier refuses to run anything not listed in scope.yaml — that refusal
is what keeps the lab bounded and the results reproducible.  Changing scope is
a reviewed edit to this one file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


# ── Known adapter names — must match files in verifier/adapters/ ─────────────
_KNOWN_ADAPTERS = {"config_abuse", "lateral_ssh", "anchor_cve"}


@dataclass
class TechniqueSpec:
    """A single technique entry from the verifier config."""
    id: str
    adapter: str
    check: str
    hosts: list[str]
    start_user: str
    raw: dict[str, Any]       # the full YAML dict, passed through to adapters

    def __getitem__(self, key: str) -> Any:
        """Allow adapter code to read technique-specific fields by key."""
        return self.raw[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.raw.get(key, default)


@dataclass
class Scope:
    """Parsed and validated verifier configuration."""
    canary_path: str
    reset_mode: str
    compose_file: str
    container_prefix: str
    techniques: list[TechniqueSpec]
    inventory_hosts: set[str] = field(default_factory=set)

    # ── Lookup helpers ────────────────────────────────────────────────────
    def technique(self, technique_id: str) -> TechniqueSpec:
        """Return the TechniqueSpec for *technique_id*, or raise KeyError."""
        for t in self.techniques:
            if t.id == technique_id:
                return t
        raise KeyError(f"technique {technique_id!r} not in verifier scope")

    def host_start_user(self, host: str) -> str:
        """Return the start_user for *host* from the first technique that names it."""
        for t in self.techniques:
            if host in t.hosts:
                return t.start_user
        raise KeyError(f"host {host!r} not targeted by any verifier technique")


def load(path: str | Path = "scope.yaml") -> Scope:
    """Parse *path* and return a validated :class:`Scope`.

    Raises ``ValueError`` on schema violations so the verifier fails loudly
    at load time, not in the middle of a batch.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"scope file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if "verifier" not in raw:
        raise ValueError("scope.yaml has no 'verifier' section")

    v = raw["verifier"]

    # Collect known hosts from the inventory section
    inventory_hosts: set[str] = set()
    inv = raw.get("inventory", {})
    for h in inv.get("hosts", {}):
        inventory_hosts.add(h)

    canary_path = v.get("canary_path", "/root/.ascend_canary")
    reset_mode = v.get("reset_mode", "recreate")
    compose_file = v.get("compose_file", "lab/docker-compose.yml")
    container_prefix = v.get("container_prefix", "ascend-")

    techniques: list[TechniqueSpec] = []
    for entry in v.get("techniques", []):
        tid = entry.get("id")
        if not tid:
            raise ValueError(f"technique entry missing 'id': {entry}")

        adapter = entry.get("adapter")
        if adapter not in _KNOWN_ADAPTERS:
            raise ValueError(
                f"technique {tid}: unknown adapter {adapter!r}. "
                f"Known adapters: {', '.join(sorted(_KNOWN_ADAPTERS))}"
            )

        check = entry.get("check")
        if not check:
            raise ValueError(f"technique {tid}: missing 'check'")

        hosts = entry.get("hosts", [])
        if not hosts:
            raise ValueError(f"technique {tid}: 'hosts' is empty or missing")

        # Validate hosts against inventory when inventory is present
        if inventory_hosts:
            for h in hosts:
                if h not in inventory_hosts:
                    raise ValueError(
                        f"technique {tid}: host {h!r} not in inventory.hosts "
                        f"({', '.join(sorted(inventory_hosts))})"
                    )

        start_user = entry.get("start_user")
        if not start_user:
            raise ValueError(f"technique {tid}: missing 'start_user'")

        techniques.append(TechniqueSpec(
            id=tid,
            adapter=adapter,
            check=check,
            hosts=hosts,
            start_user=start_user,
            raw=dict(entry),
        ))

    if not techniques:
        raise ValueError("verifier.techniques is empty")

    return Scope(
        canary_path=canary_path,
        reset_mode=reset_mode,
        compose_file=compose_file,
        container_prefix=container_prefix,
        techniques=techniques,
        inventory_hosts=inventory_hosts,
    )
