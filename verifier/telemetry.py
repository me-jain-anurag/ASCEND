"""Telemetry capture — stubbed until Falco is wired.

The verifier spec calls for per-run eBPF/Falco capture so the same execution
that yields a label also yields syscall-level evidence for the scorer's
features.  The interface is ready; only the Falco integration is deferred.

Usage:
    with capture(run_id, host) as cap:
        # ... run the adapter ...
    print(cap.path)   # "" until Falco is wired
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass


@dataclass
class Capture:
    """A completed (or stubbed) telemetry capture."""
    run_id: str
    host: str
    path: str = ""          # empty until Falco is wired


@contextmanager
def capture(run_id: str, host: str):
    """Context manager wrapping a telemetry capture window.

    Today this is a no-op.  When Falco is integrated, this will start a
    capture keyed to *run_id* on *host* at entry and stop it on exit.
    """
    cap = Capture(run_id=run_id, host=host)
    # TODO: start Falco capture here
    try:
        yield cap
    finally:
        # TODO: stop Falco capture, set cap.path to the output file
        pass
