"""Tests for the weakness catalogue and the blueprint-driven lab generator.

These are offline unit tests on the generator's output; they do not build the
lab (that needs Docker). The parity target is that the current_lab blueprint
reproduces the hand-written lab/ hosts, networks, plants and negative controls.
"""

from __future__ import annotations

import pathlib

import pytest

import yaml

from generator.blueprint import load_blueprint, normalize_weaknesses, validate
from generator.catalogue import ROOT, load_host_types, load_weaknesses
from generator.emit import emit_compose, emit_seed
from generator.scope import (build_inventory, build_verifier_techniques,
                             emit_scope)

CURRENT_LAB = ROOT / "generator" / "blueprints" / "current_lab.yaml"
REPO_SCOPE = ROOT / "scope.yaml"


@pytest.fixture(scope="module")
def repo_scope():
    return yaml.safe_load(REPO_SCOPE.read_text())


@pytest.fixture(scope="module")
def roles():
    return load_host_types()


@pytest.fixture(scope="module")
def weaknesses():
    return load_weaknesses()


@pytest.fixture(scope="module")
def current_lab():
    return load_blueprint(CURRENT_LAB)


# ── catalogue ────────────────────────────────────────────────────────────────

def test_host_types_cover_the_four_roles(roles):
    assert {"web", "app", "ci", "database"} <= set(roles)
    assert roles["web"]["account"]["name"] == "www-data"
    assert roles["web"]["account"]["uid"] == 33
    assert roles["database"]["default_kernel"] == "5.16.0"
    assert roles["app"]["networks"] == ["dmz", "core"]


def test_weaknesses_load_and_have_techniques(weaknesses):
    expected = {
        "readable_ssh_key": "T1552.001",
        "nopasswd_sudo": "T1548.003",
        "accepts_shared_key": "T1550",
        "suid_binary": "T1548.001",
        "dirtypipe_kernel": "T1068",
        "docker_socket": "T1611",
    }
    for wid, tech in expected.items():
        assert wid in weaknesses, f"missing weakness {wid}"
        assert weaknesses[wid]["technique"] == tech


def test_dirtypipe_is_vm_only(weaknesses):
    assert weaknesses["dirtypipe_kernel"]["executable_in"] == "vm"
    assert weaknesses["dirtypipe_kernel"]["host_build"]["declared_kernel"] == "5.16.0"


def test_docker_socket_is_planned(weaknesses):
    assert weaknesses["docker_socket"]["status"] == "planned"


# ── blueprint validation ─────────────────────────────────────────────────────

def test_current_lab_blueprint_is_valid(current_lab, roles, weaknesses):
    assert validate(current_lab, roles, weaknesses) == []


def test_validate_rejects_unknown_role(roles, weaknesses):
    bp = {
        "hosts": [{"id": "x1", "role": "mainframe", "weaknesses": []}],
        "entry": {"host": "x1"},
        "crown_jewel": {"host": "x1"},
    }
    errors = validate(bp, roles, weaknesses)
    assert any("unknown role" in e for e in errors)


def test_validate_rejects_unknown_weakness(roles, weaknesses):
    bp = {
        "hosts": [{"id": "x1", "role": "web", "weaknesses": ["ghost_bug"]}],
        "entry": {"host": "x1"},
        "crown_jewel": {"host": "x1"},
    }
    assert any("unknown weakness" in e for e in validate(bp, roles, weaknesses))


def test_validate_rejects_planned_weakness(roles, weaknesses):
    bp = {
        "hosts": [{"id": "x1", "role": "web", "weaknesses": ["docker_socket"]}],
        "entry": {"host": "x1"},
        "crown_jewel": {"host": "x1"},
    }
    assert any("planned" in e for e in validate(bp, roles, weaknesses))


def test_validate_rejects_bad_entry_and_crown(roles, weaknesses):
    bp = {
        "hosts": [{"id": "x1", "role": "web", "weaknesses": []}],
        "entry": {"host": "nope"},
        "crown_jewel": {"host": "alsonope"},
    }
    errors = validate(bp, roles, weaknesses)
    assert any("entry.host" in e for e in errors)
    assert any("crown_jewel.host" in e for e in errors)


def test_normalize_weaknesses_accepts_str_and_map():
    out = normalize_weaknesses(["a", {"id": "b", "params": {"x": 1}}])
    assert out == [{"id": "a", "params": {}}, {"id": "b", "params": {"x": 1}}]


# ── seed emission ────────────────────────────────────────────────────────────

def _host(blueprint, hid):
    return next(h for h in blueprint["hosts"] if h["id"] == hid)


def test_web01_seed_plants_readable_key(current_lab, roles, weaknesses):
    seed = emit_seed(_host(current_lab, "web01"), roles, weaknesses)
    assert "ascend_user www-data 33" in seed
    assert "install -m 644 -o www-data -g www-data /tmp/keys/app_deploy_key /var/www/.ssh/id_rsa" in seed
    assert seed.rstrip().endswith("ascend_canary")


def test_app01_seed_has_sudo_rule_authorize_and_negative_control(current_lab, roles, weaknesses):
    seed = emit_seed(_host(current_lab, "app01"), roles, weaknesses)
    assert "ascend_user appuser 1001" in seed
    assert "appuser ALL=(root) NOPASSWD: /bin/tar" in seed
    # decoy negative control: NOPASSWD /bin/ls, which the collector must decline
    assert "appuser ALL=(root) NOPASSWD: /bin/ls" in seed
    assert "ascend_authorize appuser" in seed
    # store_correct_copy: true -> the 0600 negative-control copy is present
    assert "install -m 600 -o appuser -g appuser /tmp/keys/app_deploy_key /home/appuser/.ssh/id_rsa" in seed


def test_db01_seed_has_suid_and_authorize_but_no_negative_control(current_lab, roles, weaknesses):
    seed = emit_seed(_host(current_lab, "db01"), roles, weaknesses)
    assert "chmod u+s /usr/bin/find" in seed
    assert "ascend_authorize dbuser" in seed
    # store_correct_copy defaults false on db01 -> no 0600 copy planted
    assert "install -m 600 -o dbuser" not in seed


def test_ci01_seed_plants_nothing(current_lab, roles, weaknesses):
    seed = emit_seed(_host(current_lab, "ci01"), roles, weaknesses)
    assert "ascend_user ciuser 1003" in seed
    assert "NOPASSWD" not in seed
    assert "chmod u+s" not in seed


def test_kernel_payload_placeholder_not_substituted_in_seed(current_lab, roles, weaknesses):
    # dirtypipe has no seed fragment, so db01's seed must not carry a kernel plant.
    seed = emit_seed(_host(current_lab, "db01"), roles, weaknesses)
    assert "declared_kernel" not in seed  # that is a build arg, not a seed line


# ── compose emission ─────────────────────────────────────────────────────────

def test_compose_has_all_hosts_and_right_kernels(current_lab, roles, weaknesses):
    compose = emit_compose(current_lab, roles, weaknesses)
    for hid in ("web01", "app01", "ci01", "db01"):
        assert f"  {hid}:" in compose
        assert f"ROLE: {hid}" in compose
    # db01 kernel overridden by dirtypipe_kernel to 5.16.0; web01 keeps role default
    assert 'DECLARED_KERNEL: "5.16.0"' in compose
    assert 'DECLARED_KERNEL: "5.4.0"' in compose


def test_compose_networks_match_topology(current_lab, roles, weaknesses):
    compose = emit_compose(current_lab, roles, weaknesses)
    assert "name: ascend_dmz" in compose
    assert "name: ascend_core" in compose
    assert "internal: true" in compose
    # web01 is dmz-only, db01 is core-only, app01/ci01 dual-homed
    assert "  web01:" in compose and "networks: [dmz]" in compose
    assert "networks: [core]" in compose           # db01
    assert "networks: [dmz, core]" in compose      # app01 / ci01


# ── scope.yaml emission & parity with the hand-written scope.yaml ─────────────

def test_inventory_matches_repo_scope(current_lab, repo_scope):
    assert build_inventory(current_lab) == repo_scope["inventory"]


def _by_id(entries):
    return {e["id"]: e for e in entries}


def test_verifier_techniques_match_repo_scope(current_lab, roles, weaknesses, repo_scope):
    gen = _by_id(build_verifier_techniques(current_lab, roles, weaknesses))
    repo = _by_id(repo_scope["verifier"]["techniques"])
    assert set(gen) == set(repo), "verifier technique ids differ"
    for tid in repo:
        g, r = dict(gen[tid]), dict(repo[tid])
        # declared_kernel_note is human-readable prose; compare its presence, not text
        g.pop("declared_kernel_note", None)
        note_r = r.pop("declared_kernel_note", None)
        assert g == r, f"verifier entry {tid} differs:\n gen={g}\n repo={r}"
    # both must carry the kernel note for T1068
    assert repo_scope and _by_id(build_verifier_techniques(current_lab, roles, weaknesses))["T1068"].get("declared_kernel_note")


def test_lateral_entry_aggregates_reused_key_hosts(current_lab, roles, weaknesses):
    entries = _by_id(build_verifier_techniques(current_lab, roles, weaknesses))
    lat = entries["T1021.004+T1550"]
    assert lat["adapter"] == "lateral_ssh"
    assert lat["requires_unprivileged_start"] is False
    assert lat["hosts"] == ["web01", "app01", "db01"]
    assert lat["start_user"] == "www-data"
    assert lat["key_path"] == "/var/www/.ssh/id_rsa"
    assert lat["to_host"] == "app01" and lat["to_user"] == "appuser"


def test_decoy_produces_no_verifier_entry(current_lab, roles, weaknesses):
    entries = build_verifier_techniques(current_lab, roles, weaknesses)
    blob = repr(entries)
    assert "/bin/ls" not in blob
    # exactly five verifier entries (sudo, cred, lateral, suid, cve) — decoy excluded
    assert len(entries) == 5


def test_emit_scope_is_valid_and_keeps_static_sections(current_lab, roles, weaknesses):
    data = yaml.safe_load(emit_scope(current_lab, roles, weaknesses))
    for section in ("techniques", "rules", "remediation", "inventory", "verifier"):
        assert section in data, f"missing {section}"
    # runtime placeholder survives into the emitted sudo payload
    sudo = next(t for t in data["verifier"]["techniques"] if t["id"] == "T1548.003")
    assert "{canary}" in sudo["payload_template"]
    assert sudo["sudo_target"] == "/bin/tar"
