# `catalogue/` — the weakness catalogue

A weakness used to be spread across three places: a fragment in `lab/seed/<host>.sh`,
a rule + remediation + verifier entry in `scope.yaml`, and an adapter in
`verifier/adapters/`. Adding or moving one meant editing all three by hand. The
catalogue pulls each weakness into **one self-contained, parameterised unit** so
a lab can be described as data (a *blueprint*) and built by the generator
(`generator/`, see `docs/10` §4).

This is additive. The hand-written `lab/` still works; the generator reproduces
it from `generator/blueprints/current_lab.yaml` (parity).

## Files

```
host_types.yaml        role -> default account (name/uid/home), kernel, networks
weaknesses/*.yaml      one file per plantable weakness
```

## Weakness schema

| Field | Meaning |
|---|---|
| `id` | unique slug, also the filename |
| `title` / `summary` | human description |
| `technique` | ATT&CK ID (ties to `scope.yaml` rule + remediation) |
| `executable_in` | `container` \| `vm` \| `either` — `vm` means it can only be *executed* for real on a VM (e.g. kernel bugs) |
| `status` | `active` (default) or `planned` (defined but not yet plantable; the generator refuses to place it) |
| `needs` | prerequisites, e.g. `[account]` |
| `params` | default parameters a blueprint may override (binary, suid_path, …) |
| `seed` | bash fragment that plants it, run in the role seed script |
| `realism` | optional non-essential bash (decoy scripts, negative-control copies) |
| `host_build` | image/compose properties, not seed: `declared_kernel`, `mounts` |
| `cross_host` | true when the vector only emerges across ≥2 hosts (reused key) |
| `verify` | how the verifier runs it: `adapter`, `check`, `scope` (`local`\|`lateral`), `start_user`, `params` |

### Placeholders

Seed/realism fragments are expanded with the host's context before being written:
`{host} {user} {uid} {home} {key_src} {key_pub}` plus the weakness's own params
(`{binary} {suid_path} …`). `verify.params` keep runtime placeholders like
`{canary}` **unexpanded** — the verifier adapter fills those at run time.

## The entries today

| id | technique | executable_in | notes |
|---|---|---|---|
| `readable_ssh_key` | T1552.001 | either | finding is the 0644 mode, not the key |
| `nopasswd_sudo` | T1548.003 | either | param `binary` (default `/bin/tar`) |
| `decoy_nopasswd` | T1548.003 | either | **decoy** — NOPASSWD, no escape; must be declined |
| `accepts_shared_key` | T1550 (+T1021.004) | either | cross-host; reuse is the chokepoint |
| `suid_binary` | T1548.001 | either | param `suid_path` (default `/usr/bin/find`) |
| `dirtypipe_kernel` | T1068 | **vm** | declared kernel; real only on a VM |
| `docker_socket` | T1611 | either | **planned** — not yet wired |

Decoys (`kind: decoy`) are negative controls: planted so the collector must
examine them and decline to report them. They have no `verify` and never become a
vector; they feed the false-positive-rate metric (`docs/11` §5).

## Adding a weakness

1. Write `weaknesses/<id>.yaml` to the schema above.
2. Ensure its `technique` has a rule + remediation in `scope.yaml`.
3. If it needs a new verify adapter, add it under `verifier/adapters/`.
4. Reference it from a blueprint host's `weaknesses:` list.
