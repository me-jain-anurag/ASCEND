# `collectors/` — from a running lab to `facts.json`

```
lab hosts ──probes──► raw observations ──derive.py + scope.yaml──► facts.json
                                                                      │
                                                 enumerator ──► service ──► dashboard
```

```bash
python3 collectors/collect.py                 # collect from the Docker lab
python3 collectors/collect.py -v              # show each probe as it runs
python3 collectors/collect.py --save-raw /tmp/raw.json
python3 collectors/collect.py --from-raw collectors/fixtures/lab_capture.json
```

The last form runs **no probes and needs no Docker** — it replays a recorded
capture through the current rules. Use it to work on rules offline, and to see
exactly which findings a rule change adds or removes.

Writes `environment_graph/facts.json` and `environment_graph/collection_report.json`.

## The one design rule

**Probes observe. `derive.py` judges. `scope.yaml` decides.**

A probe reports `mode 0644, owner www-data, contains an ed25519 private key`. It
never reports "web01 is vulnerable". The decision that 0644 constitutes a
disclosure lives in `rules.cred_files` in `scope.yaml`, and the code that applies
it lives in one function in `derive.py`.

This is what makes a finding auditable: to see why ASCEND believes something is
exploitable you read one rule and one function, and the vector carries the raw
observation that triggered it in `features.evidence`.

## Layout

| File | Responsibility |
|---|---|
| `collect.py` | orchestration, CLI, assembly, the run report |
| `transport.py` | *how* a host is reached — `docker exec`, or local |
| `sshkeys.py` | SSH fingerprinting in pure Python (see below) |
| `derive.py` | raw observations → vectors, credentials, reachability |
| `probes/*.py` | one fact type each; no judgement |
| `fixtures/lab_capture.json` | a recorded capture of the reference lab |

Probes are handed a `Transport` and never shell out themselves, so the same
probe code runs against a container today and an SSH-reachable VM tomorrow.

## Why fingerprinting is done in Python

Credential reuse is the headline chokepoint, so the match behind it must be a
real cryptographic comparison — not a filename or comment guess. `sshkeys.py`
parses the `openssh-key-v1` container directly and computes
`SHA256:<base64(sha256(keyblob))>`, byte-identical to `ssh-keygen -lf`, which
`tests/test_pipeline.py` asserts against the real binary.

Consequences worth knowing:

- Target hosts need **no OpenSSH client** installed.
- The public blob is in clear even in a passphrase-protected key, so a key is
  always fingerprintable; `encrypted: true` is recorded separately.
- Legacy PEM keys (`BEGIN RSA PRIVATE KEY`) carry no public blob. They are
  reported without a fingerprint and cannot participate in reuse matching.

## Provenance

Every fact says where it came from.

| Value | Meaning |
|---|---|
| `observed` | a probe measured it on the live host |
| `declared` | an operator supplied it; no scan could produce it |

`declared` covers host roles and asset values — genuine business inputs — and,
in a container lab, per-host kernel versions. See `lab/README.md`.

## Verification status

Every vector the collector emits carries:

```json
{ "verified_exploitable": null, "config_exploitable": true }
```

`config_exploitable` means **the configuration the technique requires is
present**. It does *not* mean the exploit works here. Only `verifier/`, which
does not exist yet, can set `verified_exploitable`, and until then the honest
value is `null`. The enumerator reports the two separately as *config coverage*
and *precision*.

## What is collected

| Probe | Observes | Feeds |
|---|---|---|
| `accounts.py` | `/etc/passwd`, login-capable accounts only | accounts |
| `sudo.py` | `sudo -ln -U <user>` + raw `sudoers.d` | T1548.003 |
| `suid.py` | setuid-root binaries | T1548.001 |
| `kernel.py` | `uname -r` **and** the declared kernel | T1068 |
| `cred_files.py` | credential files, their modes, key fingerprints | T1552.001 |
| `ssh_keys.py` | every `authorized_keys` entry | credential reuse / T1550 |
| `ports.py` | listening TCP sockets, flagging loopback-only ones | reachability targets |
| `reachability.py` | real TCP connects, host → host | reachability edges |
| `docker_socket.py` | socket mounts, `docker` group | T1611 |

## Loopback listeners are not reachability targets

`ports.py` flags any listener bound to `127.0.0.0/8` or `::1`, and the
reachability sweep skips them: such a socket is reachable only from inside its
own network namespace, so probing it from another host buys a guaranteed
timeout.

In this lab that rule removes Docker's embedded DNS resolver on `127.0.0.11`,
which otherwise appears as an unexplained high-numbered port on every host and
doubles the reachability sweep (12 attempts down to 6). Wildcard binds
(`0.0.0.0`, `::`) are of course kept.

## The run report

`environment_graph/collection_report.json` records every reachability attempt
(including the failures and *why* they failed) and — more usefully — every
condition that was examined and **deliberately not reported**:

```
app01  T1552.001  /home/appuser/.ssh/id_rsa   mode 600 — readable only by its owner
app01  T1548.003  (root) NOPASSWD: /bin/ls    /bin/ls has no documented shell escape
app01  T1068      CVE-2022-0847               5.10.150 is at or above the 5.10 branch fix
web01  T1068      CVE-2022-0847               kernel 5.4.0 is below the affected range
```

A scanner that flags everything proves nothing. This section is the evidence
that the rules discriminate, and it is worth putting on a slide.

## Adding a new technique

1. Add it to `techniques:` in `scope.yaml`, naming the `evidence` it needs.
2. Add a `rules:` block with the condition that makes it a finding — and the
   condition that does not.
3. Write `probes/<evidence>.py` exposing `collect(host, tp, scope)`; report raw
   observations only.
4. Add a builder in `derive.py`. Append to `skipped` whenever you decline, with
   a reason a human can read.
5. Add a remediation template under `remediation:` so `chokepoint/` can cost it.
6. Extend `fixtures/lab_capture.json` with a positive **and** a negative case,
   and assert both in `tests/test_pipeline.py`.
