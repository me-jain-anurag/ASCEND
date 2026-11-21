"""Tests for the weakness catalogue and the blueprint-driven lab generator.

These are offline unit tests on the generator's output; they do not build the
lab (that needs Docker). The parity target is that the current_lab blueprint
reproduces the hand-written lab/ hosts, networks, plants and negative controls.
"""

from __future__ import annotations

import pathlib

import pytest

from generator.blueprint import load_blueprint, normalize_weaknesses, validate
from generator.catalogue import ROOT, load_host_types, load_weaknesses
from generator.emit import emit_compose, emit_seed

CURRENT_LAB = ROOT / "generator" / "blueprints" / "current_lab.yaml"


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
