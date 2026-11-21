"""Emit a lab's seed scripts and docker-compose from a validated blueprint.

Increment 1 emits the two things that make the lab buildable: per-host seed
scripts and the compose file. scope.yaml (inventory + verifier instances) is
emitted in a later increment; until then a generated lab reuses the repo's
static scope.yaml sections.
"""

from __future__ import annotations

from generator.blueprint import normalize_weaknesses

# The deploy keypair is staged into the image build context by bootstrap.sh and
# copied to /tmp/keys by the Dockerfile (COPY keys/ /tmp/keys/).
KEY_SRC = "/tmp/keys/app_deploy_key"
KEY_PUB = "/tmp/keys/app_deploy_key.pub"

# Named bridge networks. Unknown names fall back to ascend_<name>.
_NET_NAMES = {"dmz": "ascend_dmz", "core": "ascend_core"}


def _subst(text: str, ctx: dict) -> str:
    """Replace {key} tokens from ctx. Leaves unknown braces untouched (shell-safe)."""
    if not text:
        return ""
    out = text
    for k, v in ctx.items():
        out = out.replace("{" + k + "}", str(v))
    return out


def _host_context(host: dict, role_def: dict, weakness: dict, wparams: dict) -> dict:
    account = role_def["account"]
    ctx = {
        "host": host["id"],
        "user": account["name"],
        "uid": account["uid"],
        "home": account["home"],
        "key_src": KEY_SRC,
        "key_pub": KEY_PUB,
    }
    merged = dict(weakness.get("params") or {})
    merged.update(wparams or {})
    ctx.update(merged)
    return ctx


def emit_seed(host: dict, roles: dict, weaknesses: dict) -> str:
    """Return the bash seed script for one host."""
    role_def = roles[host["role"]]
    account = role_def["account"]
    lines = [
        "#!/bin/bash",
        "set -euo pipefail",
        "source /tmp/seed/common.sh",
        "",
        f"ascend_user {account['name']} {account['uid']}",
        "",
    ]

    for w in normalize_weaknesses(host.get("weaknesses")):
        wk = weaknesses[w["id"]]
        ctx = _host_context(host, role_def, wk, w["params"])
        seed = wk.get("seed")
        realism = wk.get("realism")

        # accepts_shared_key: the 0600 negative-control copy is only planted where
        # the blueprint sets store_correct_copy (app01), not everywhere.
        if wk["id"] == "accepts_shared_key" and not ctx.get("store_correct_copy"):
            realism = None

        if seed or realism:
            lines.append(f"# {wk['technique']} — {wk.get('title', wk['id'])} [{wk['id']}]")
        if seed:
            lines.append(_subst(seed, ctx).rstrip())
        if realism:
            lines.append(_subst(realism, ctx).rstrip())
        if seed or realism:
            lines.append("")

    lines.append("ascend_lock_passwords")
    lines.append("ascend_canary")
    lines.append("")
    return "\n".join(lines)


def _host_kernel_and_mounts(host: dict, role_def: dict, weaknesses: dict):
    kernel = role_def["default_kernel"]
    mounts: list[str] = []
    for w in normalize_weaknesses(host.get("weaknesses")):
        hb = weaknesses[w["id"]].get("host_build") or {}
        if hb.get("declared_kernel"):
            kernel = hb["declared_kernel"]
        mounts += hb.get("mounts") or []
    return kernel, mounts


def emit_compose(blueprint: dict, roles: dict, weaknesses: dict) -> str:
    """Return the docker-compose.yml for the whole blueprint."""
    hosts = blueprint.get("hosts") or []
    used_nets: set[str] = set()
    services: list[str] = []

    for h in hosts:
        role_def = roles[h["role"]]
        nets = h.get("networks") or role_def.get("networks") or []
        used_nets.update(nets)
        kernel, mounts = _host_kernel_and_mounts(h, role_def, weaknesses)

        svc = [
            f"  {h['id']}:",
            "    build:",
            "      context: .",
            "      dockerfile: Dockerfile",
            "      args:",
            f"        ROLE: {h['id']}",
            f'        DECLARED_KERNEL: "{kernel}"',
            f"    container_name: ascend-{h['id']}",
            f"    hostname: {h['id']}",
            f"    networks: [{', '.join(nets)}]",
            "    restart: unless-stopped",
        ]
        if mounts:
            svc.append("    volumes:")
            svc += [f'      - "{m}"' for m in mounts]
        services.append("\n".join(svc))

    net_lines = ["networks:"]
    for n in sorted(used_nets):
        net_lines += [
            f"  {n}:",
            f"    name: {_NET_NAMES.get(n, 'ascend_' + n)}",
            "    internal: true",
        ]

    return (
        "name: ascend-lab\n\nservices:\n\n"
        + "\n\n".join(services)
        + "\n\n"
        + "\n".join(net_lines)
        + "\n"
    )
