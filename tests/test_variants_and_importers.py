"""Tests for Milestone B: runtime-mitigated catalogue entries, seeded variant
generator, hardened baseline blueprint, and Assessment-mode scanner importers.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "enumerator"))

from collectors.importers.scanner import (  # noqa: E402
    build_assessment_facts,
    import_lynis_audit,
    import_trivy_json,
)
from generator.blueprint import load_blueprint, validate  # noqa: E402
from generator.catalogue import load_host_types, load_weaknesses  # noqa: E402
from generator.emit import emit_compose, emit_seed  # noqa: E402
from generator.scope import emit_scope  # noqa: E402
from generator.variants import (  # noqa: E402
    blueprint_to_facts,
    generate_variants,
    materialize_variant_outcomes,
)
from pathfinder import enumerate_paths  # noqa: E402


def test_runtime_mitigated_weaknesses_are_in_catalogue():
    weaknesses = load_weaknesses()
    for wid in ("nopasswd_sudo_noexec", "suid_nosuid_mount", "ssh_key_blocked_allowusers"):
        assert wid in weaknesses, f"missing {wid}"
        assert weaknesses[wid]["kind"] == "runtime_mitigated"
        assert weaknesses[wid]["expected_outcome"] == "not_escalated"


def test_hardened_baseline_blueprint_yields_zero_paths_with_real_decoys():
    roles = load_host_types()
    weaknesses = load_weaknesses()
    bp = load_blueprint(ROOT / "generator" / "blueprints" / "hardened_baseline.yaml")
    assert validate(bp, roles=roles, weaknesses=weaknesses) == []
    facts, report = blueprint_to_facts(bp, roles=roles, weaknesses=weaknesses)
    assert facts["vectors"] == []
    assert enumerate_paths(facts) == []
    assert len(report["skipped"]) >= 2


def test_generate_variants_produces_40_valid_blueprints_with_disjoint_splits():
    variants = generate_variants(n=40, seed=1337)
    assert len(variants) == 40
    splits = {v["variant_id"]: v["split"] for v in variants}
    assert {"train", "val", "test"} == set(splits.values())
    # Reproducible with same seed
    variants2 = generate_variants(n=40, seed=1337)
    assert [v["variant_id"] for v in variants] == [v["variant_id"] for v in variants2]
    assert [v["hosts"] for v in variants] == [v["hosts"] for v in variants2]


def test_variant_emits_compose_seeds_and_scope_cleanly():
    roles = load_host_types()
    weaknesses = load_weaknesses()
    bp = generate_variants(n=5, seed=1337)[0]
    compose = emit_compose(bp, roles, weaknesses)
    assert "services:" in compose
    for h in bp["hosts"]:
        seed = emit_seed(h, roles, weaknesses)
        assert "ascend_canary" in seed
    scope_yaml = emit_scope(bp, roles, weaknesses)
    parsed = yaml.safe_load(scope_yaml)
    assert set(parsed["inventory"]["hosts"]) == {h["id"] for h in bp["hosts"]}


def test_variant_outcomes_have_both_classes_and_explicit_label_source():
    variants = generate_variants(n=40, seed=1337)
    outcomes = materialize_variant_outcomes(variants)
    assert len(outcomes) > 100
    assert all(o["label_source"] == "catalogue_ground_truth" for o in outcomes)
    statuses = {o["status"] for o in outcomes}
    assert {"escalated", "not_escalated", "not_executable"} <= statuses
    # Both classes present in train and test splits
    for sp in ("train", "test"):
        sp_rows = [o for o in outcomes if o["split"] == sp and o["status"] != "not_executable"]
        labels = {o["escalated"] for o in sp_rows}
        assert labels == {True, False}, f"split {sp} missing class: {labels}"


def test_trivy_and_lynis_importers_enforce_declared_provenance():
    kg = json.loads((ROOT / "knowledge_graph" / "pack.json").read_text())
    scope = yaml.safe_load((ROOT / "scope.yaml").read_text())

    trivy_sample = {
        "Results": [
            {
                "Target": "db01",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2022-0847",
                        "PkgName": "linux-image",
                        "InstalledVersion": "5.16.0",
                        "FixedVersion": "5.16.11",
                        "CVSS": {"nvd": {"V3Score": 7.8}},
                    },
                    {
                        "VulnerabilityID": "CVE-9999-0000",
                        "PkgName": "out-of-scope",
                        "Severity": "CRITICAL",
                    },
                ],
            }
        ]
    }
    t_vecs = import_trivy_json(trivy_sample, hostname="db01", knowledge_pack=kg)
    assert len(t_vecs) == 1
    assert t_vecs[0]["cve"] == "CVE-2022-0847"
    assert t_vecs[0]["features"]["provenance"] == "declared"
    assert t_vecs[0]["features"]["source_tool"] == "trivy"
    assert t_vecs[0]["verified_exploitable"] is None

    lynis_sample = {
        "sudo_rules": [
            {"user": "appuser", "binary": "/bin/tar", "nopasswd": True, "noexec": True},
            {"user": "appuser", "binary": "/bin/ls", "nopasswd": True, "noexec": False},
        ],
        "suid_binaries": [
            {"path": "/usr/bin/find", "nosuid_mount": False},
            {"path": "/usr/bin/passwd", "nosuid_mount": False},
        ],
        "readable_keys": [
            {"path": "/var/www/.ssh/id_rsa", "mode": "0644"},
            {"path": "/home/appuser/.ssh/id_rsa", "mode": "0600"},
        ],
    }
    l_vecs, skipped = import_lynis_audit(lynis_sample, hostname="app01", scope=scope, knowledge_pack=kg)
    assert len(l_vecs) == 3
    assert len(skipped) == 3  # /bin/ls, /usr/bin/passwd, 0600 key all declined
    assert all(v["features"]["provenance"] == "declared" for v in l_vecs)
    assert all(v["features"]["source_tool"] == "lynis" for v in l_vecs)
    assert all(v["verified_exploitable"] is None for v in l_vecs)

    facts = build_assessment_facts(
        hosts=[{"hostname": "app01", "role": "app", "os": "Debian 12", "kernel": "5.10.150", "asset_value": 30}],
        accounts=[],
        reachability=[],
        credentials=[],
        vectors=t_vecs + l_vecs,
        entry={"host": "app01", "account": "appuser", "privilege": "low"},
        crown_jewel={"host": "app01", "privilege": "root"},
    )
    assert facts["_meta"]["mode"] == "assessment"
    assert facts["_meta"]["execution_verified"] is False
