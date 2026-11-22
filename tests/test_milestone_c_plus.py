"""Tests for Milestone C+: live-lab remediation executor, hot-add-host API,
SSE activity log endpoints, and live Docker variant runner dry-run.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "service"))

from fastapi.testclient import TestClient  # noqa: E402

from chokepoint.remediate import (  # noqa: E402
    execute_live_remediation,
    remediation_command_for_vector,
)
from eval.run_live_variants import main as live_variants_main  # noqa: E402
import main as service_main  # noqa: E402


def test_remediation_command_mapping_for_supported_techniques():
    assert remediation_command_for_vector({"technique": "T1552.001", "features": {"evidence": {"path": "/var/www/.ssh/id_rsa"}}}) == [
        "chmod", "0600", "/var/www/.ssh/id_rsa"
    ]
    assert remediation_command_for_vector({"technique": "T1548.001", "features": {"evidence": {"path": "/usr/bin/find"}}}) == [
        "chmod", "u-s", "/usr/bin/find"
    ]
    assert remediation_command_for_vector({"technique": "T1548.003", "features": {"evidence": {"policy_files": {"/etc/sudoers.d/appuser": "..."}}}}) == [
        "rm", "-f", "/etc/sudoers.d/appuser"
    ]


def test_execute_live_remediation_invokes_exec_as():
    with patch("verifier.lab.exec_as", return_value=(0, "", "")) as mock_exec:
        res = execute_live_remediation(
            "web01",
            {"technique": "T1552.001", "features": {"evidence": {"path": "/var/www/.ssh/id_rsa"}}},
        )
    assert res["applied_live"] is True
    assert res["command"] == ["chmod", "0600", "/var/www/.ssh/id_rsa"]
    mock_exec.assert_called_once()


def test_apply_remediation_live_lab_mode_returns_503_when_docker_down():
    client = TestClient(service_main.app)
    client.post("/api/reset")
    rem = client.get("/api/remediation").json()
    top_fix = rem["ranked_fixes"][0]["fix_id"]

    with patch("verifier.lab.exec_as", side_effect=FileNotFoundError("docker.sock missing")):
        resp = client.post("/api/remediation/apply", json={"fix_id": top_fix, "mode": "live_lab"})
    assert resp.status_code == 503
    assert "detail" in resp.json()


def test_apply_remediation_live_lab_mode_succeeds_with_mocked_container():
    client = TestClient(service_main.app)
    client.post("/api/reset")
    rem = client.get("/api/remediation").json()
    top_fix = rem["ranked_fixes"][0]["fix_id"]

    with patch("verifier.lab.exec_as", return_value=(0, "", "")):
        resp = client.post("/api/remediation/apply", json={"fix_id": top_fix, "mode": "live_lab"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["mode"] == "live_lab"
    assert data["live_execution"]["applied_live"] is True
    assert data["paths_remaining"] == 0
    client.post("/api/reset")


def test_hot_add_host_and_sse_events_log():
    client = TestClient(service_main.app)
    client.post("/api/reset")
    before = len(client.get("/api/network").json()["hosts"])

    add_resp = client.post(
        "/api/hosts/add",
        json={
            "hostname": "db02",
            "role": "database",
            "asset_value": 80,
            "weaknesses": ["accepts_shared_key", "nopasswd_sudo"],
        },
    )
    assert add_resp.status_code == 200, add_resp.text
    assert add_resp.json()["hosts_count"] == before + 1

    # Verify event log recorded the hot-add event and SSE stream works
    recent = client.get("/api/events/recent").json()["events"]
    assert any(ev["stage"] == "hot_add" and "db02" in ev["message"] for ev in recent)
    sse = client.get("/api/events")
    assert sse.status_code == 200
    assert "text/event-stream" in sse.headers["content-type"]
    assert "event: hot_add" in sse.text

    # Reset clears hot-added hosts cleanly
    client.post("/api/reset")
    assert len(client.get("/api/network").json()["hosts"]) == before


def test_live_variant_runner_dry_run():
    rc = live_variants_main(["--count", "3", "--seed", "1337", "--dry-run"])
    assert rc == 0


def test_real_cve_multimodal_model_scores_anchors_and_beats_cvss():
    from scorer.real_cve_inference import load_real_cve_benchmark, score_cve_record
    bench = load_real_cve_benchmark()
    assert bench is not None
    assert bench["dataset"]["total_cves"] >= 5000
    by_name = {r["name"]: r for r in bench["test_2024_results"]}
    ens = by_name["ASCEND Calibrated Multimodal Ensemble"]
    cvss = by_name["CVSS Base Continuous"]
    assert ens["pr_auc"] > cvss["pr_auc"] + 0.4
    assert ens["brier_score"] < cvss["brier_score"]

    dp = score_cve_record({"cve": "CVE-2022-0847"})
    pk = score_cve_record({"cve": "CVE-2021-4034"})
    assert dp is not None and 0.2 < dp["probability"] < 1.0
    assert pk is not None and 0.2 < pk["probability"] < 1.0

    client = TestClient(service_main.app)
    resp = client.get("/api/scores/cve-benchmark")
    assert resp.status_code == 200
    assert resp.json()["dataset"]["test_2024"]["n"] >= 2000
