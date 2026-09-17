"""Adapter registry — maps adapter names from scope.yaml to callables.

Every adapter is a function with the same signature:

    def adapter(ctx: RunContext) -> AdapterResult

The adapter's only freedom is how it triggers the technique.  It must decide
``escalated`` through ``signal.py``, not by reading its own tool's exit code.
This rule is what keeps every label honest and comparable across techniques.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class RunContext:
    """Everything an adapter needs to execute a technique."""
    host: str
    start_user: str
    technique: dict[str, Any]     # the scope.yaml entry (full dict)
    canary_token: str
    canary_path: str
    run_id: str
    container_prefix: str = "ascend-"


@dataclass
class AdapterResult:
    """What an adapter returns after executing a technique."""
    escalated: bool
    evidence: str                 # last lines of the deciding output
    raw_cmd: list[str]            # exactly what was executed, for reproducibility


# ── Registry ──────────────────────────────────────────────────────────────────

Adapter = Callable[[RunContext], AdapterResult]

_REGISTRY: dict[str, Adapter] = {}


def register(name: str):
    """Decorator to register an adapter function under *name*."""
    def wrap(fn: Adapter) -> Adapter:
        _REGISTRY[name] = fn
        return fn
    return wrap


def get(name: str) -> Adapter:
    """Look up a registered adapter by *name*.  Raises ``KeyError`` if unknown."""
    if name not in _REGISTRY:
        raise KeyError(
            f"no adapter {name!r} — add one in verifier/adapters/ "
            f"(registered: {', '.join(sorted(_REGISTRY))})"
        )
    return _REGISTRY[name]


# ── Import adapter modules so they register themselves on import ─────────────
# This must come AFTER the registry definition.

from verifier.adapters import config_abuse   # noqa: E402, F401
from verifier.adapters import lateral_ssh    # noqa: E402, F401
from verifier.adapters import anchor_cve     # noqa: E402, F401
