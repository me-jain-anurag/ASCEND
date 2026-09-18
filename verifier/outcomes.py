"""Outcome record definition and JSONL persistence.

The verifier's only product is a stream of outcome records.  Two teammates
read them: the scorer (B) turns them into labels and features; the
environment-graph builder (B) sets ``verified_exploitable``.

Records are append-only, one JSON object per line, flushed per record so a
crashed batch keeps everything up to the crash.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


# ── Where outcomes go ────────────────────────────────────────────────────────
# Two separate streams, deliberately.
#
# BATCH_PATH is the labelled dataset the exploitability scorer trains on. It is
# produced by `python -m verifier batch` with a fixed seed, and is meant to be
# reproducible.
#
# LIVE_PATH is the audit trail of interactive runs from the dashboard's Verify
# button. These are demo clicks: the same technique repeated whenever someone
# presses the button. Letting them into the training set would silently
# reweight the dataset toward whatever was demonstrated most often, so they are
# recorded separately and the live file is not committed.
BATCH_PATH = "outcomes.jsonl"
LIVE_PATH = "verifier/runs/live.jsonl"


@dataclass
class Outcome:
    """A single verifier execution result."""

    run_id: str
    host: str
    technique: str
    scenario: str
    escalated: bool
    evidence: str
    raw_cmd: list[str]
    # "escalated" | "not_escalated" | "not_executable". `escalated` stays a
    # bool for the scorer's label column; `status` is what distinguishes a real
    # negative from a run that never happened. Only the first two are training
    # data — a not_executable row is a note about the lab, not about the host.
    status: str = "escalated"
    reason: str = ""
    telemetry_path: str = ""
    seed: int = 0
    kernel_version: str = ""
    host_facts_ref: str = ""
    lab_image_digest: str = ""
    ts: str = ""

    def __post_init__(self):
        if not self.ts:
            self.ts = (
                datetime.datetime.now(datetime.timezone.utc)
                .replace(microsecond=0)
                .isoformat()
            )


def append(outcome: Outcome, path: str | Path = BATCH_PATH) -> None:
    """Append *outcome* as a single JSON line to *path*.

    Creates the file if it doesn't exist.  Flush guarantees the record is
    durable before we return — a crash between runs loses nothing.
    """
    rec = asdict(outcome)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
        f.flush()


def load(path: str | Path = BATCH_PATH) -> list[dict[str, Any]]:
    """Read all outcome records from *path*."""
    p = Path(path)
    if not p.exists():
        return []
    records: list[dict[str, Any]] = []
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records
