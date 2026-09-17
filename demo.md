# `demo.md` — running and demonstrating ASCEND

The runbook for the review. Doc 05 §2 asks for this file; this is it, plus the
testing pass you should do **before** standing in front of anyone.

No prior knowledge of the codebase is assumed. If you can open a terminal, you
can run this.

---

## TL;DR

```bash
.venv/bin/python tests/test_pipeline.py   # 1. prove the logic  -> 15 passed
bash lab/down.sh && bash lab/up.sh        # 2. rebuild the lab  -> ~2s cached
python3 collectors/collect.py             # 3. go look at it    -> 3 vectors
python3 enumerator/pathfinder.py           # 4. find the routes  -> 3 paths
.venv/bin/python service/main.py          # 5. API   :8000  (own terminal)
cd dashboard && npm run dev               # 6. UI    :5173  (own terminal)
```

---

## 1. What you are actually saying

Four sentences. Everything else is support for the third one.

1. **"Here's a small network."** A web server, an app server, a database. The
   database holds the valuable data.
2. **"An attacker landing on the web server can reach the database as root"** —
   and we found the routes *automatically*, by reading the machines' own
   configuration.
3. **"Here's the one cheapest fix that kills every route."** Not "patch
   everything" — "fix this one thing first."
4. **"Watch — we apply it and the routes disappear."** Demonstrated, not claimed.

## 2. How the pieces fit

```
lab/          3 Docker containers with real weaknesses planted in them
   |          "go look at those machines and write down what you see"
   v
collectors/   -> environment_graph/facts.json
   |          "given what's there, what could an attacker do?"
   v
enumerator/   -> the attack paths
   |          "which single fix kills the most paths?"
   v
chokepoint/   -> the ranked fixes
   |
   v
service/      serves all of it as JSON on :8000
dashboard/    draws it on :5173
```

Each arrow is a separate program, and that is the point. The collector does not
know what an "attack path" is; the enumerator does not know Docker exists. So
when the enumerator finds a path, it found it from **evidence**, not from a hint
someone planted for it.

---

## 3. One-time setup

| Need | Install |
|---|---|
| Docker Engine + Compose v2 | see [`lab/README.md`](lab/README.md#prerequisites--installing-docker) |
| Python packages | `python3 -m venv .venv && .venv/bin/pip install -r service/requirements.txt` |
| Node + npm (dashboard only) | `sudo apt-get install -y npm && cd dashboard && npm install` |

The enumerator alone needs **nothing** — standard library only. You can always
fall back to it if something else breaks.

---

## 4. Testing pass — do this before every demo

### Step 1 — prove the analysis is correct

```bash
.venv/bin/python tests/test_pipeline.py
```

Expect **`15 passed, 0 failed, 0 skipped`**, in about a second.

This runs offline against a recorded capture of the lab — no Docker needed. If
it fails, stop. Something is wrong in the logic, not in the lab, and no amount
of restarting containers will help.

### Step 2 — rebuild the lab from scratch

```bash
bash lab/down.sh
bash lab/up.sh
```

Destroy it first on purpose: it proves the lab is reproducible rather than
something that happens to work on your machine today. About 2 seconds once the
image layers are cached, a few minutes on the very first build.

### Step 3 — collect the facts

```bash
python3 collectors/collect.py
```

This walks into each container and reads its configuration. Expect:

- `3 hosts, 6 accounts, 1 credentials, 4 reachability edges, 3 vectors`
- a `** CREDENTIAL REUSE:` line naming `app_deploy_key` on 2 hosts
- `examined and NOT reported (4)`

### Step 4 — find the paths

```bash
python3 enumerator/pathfinder.py
```

Expect **3 attack paths**, config coverage `3/3`, precision `0/3`, and the
chokepoint ranking `3/3, 3/3, 2/3`.

### Step 5 — bring up the API and the dashboard

```bash
.venv/bin/python service/main.py     # terminal 1, port 8000
cd dashboard && npm run dev          # terminal 2, port 5173
```

Sanity check from a third terminal:

```bash
curl -s localhost:8000/api/status | python3 -m json.tool
```

### Pre-flight checklist

- [ ] `15 passed` from the test suite
- [ ] `3 vectors` and `4` declined conditions from the collector
- [ ] the `CREDENTIAL REUSE` line appears
- [ ] `3 attack paths` from the enumerator
- [ ] dashboard loads and shows 3 hosts
- [ ] you have run `POST /api/reset` (or clicked Reset) so no fix is left applied

---

## 5. The demo — about 4 minutes

### Beat 1 — "This is the lab" *(0:00, 30s)*

```bash
docker compose -f lab/docker-compose.yml ps
```

> "Three Linux machines on two isolated networks. No internet route, no ports
> exposed to my laptop. `web01` is where an attacker gets in. `db01` holds the
> data we care about."

### Beat 2 — "The weaknesses are real, not JSON we wrote" *(0:30, 45s)*

Pre-empts the first thing a sceptical panel thinks.

```bash
docker exec ascend-web01 ls -l /var/www/.ssh/id_rsa
docker exec ascend-app01 sudo -l -U appuser
```

> "A private SSH key, readable by every account on the box. And `appuser` can run
> `tar` as root with no password — `tar` can spawn a shell, so that rule *is* a
> root shell. We didn't write these into a config file. They are really on these
> machines."

### Beat 3 — "The collector goes and looks" *(1:15, 60s)*

**The strongest beat. Do not rush it.**

```bash
python3 collectors/collect.py
```

Point at three things in the output.

**(a) The credential-reuse line**

> "It found the private key on web01, fingerprinted it, and matched that
> fingerprint against every `authorized_keys` file on every machine. The same key
> opens app01 *and* db01. Nobody told it that — it is a cryptographic match, the
> same fingerprint `ssh-keygen` would print."

**(b) The reachability list — 4 edges, and no `web01 -> db01`**

> "It opened real TCP connections from inside each container, to each target's
> name and to every address it holds. web01 simply cannot reach the database.
> That's how it knows the network is segmented — not because we declared it."

**(c) The 4 declined conditions**

Read them aloud. This is the credibility beat.

> "This is the part I'd want to see if I were you. It found a NOPASSWD sudo rule
> for `/bin/ls` and said no — `ls` can't give you a shell. It found the *same*
> private key sitting on app01 and said no — that copy is mode 0600, only its
> owner can read it, and the finding is the permission, not the file. It found
> app01's 5.10 kernel and said no — that branch was patched at 5.10.102, even
> though it looks old next to the headline 5.16.11 fix. A scanner that flags
> everything proves nothing. Ours considered seven things and reports three."

### Beat 4 — "Here are the routes" *(2:15, 30s)*

```bash
python3 enumerator/pathfinder.py
```

Or the dashboard's Attack Paths tab, which is easier to read on a projector.

> "Three routes from a foothold on web01 to root on the database. Each step is a
> named MITRE ATT&CK technique — a harvested key, a sudo misconfiguration, a
> kernel exploit."

### Beat 5 — "Here's the cheapest fix" *(2:45, 30s)*

Dashboard → Remediation.

> "Three different fixes each kill all three paths. But patching the kernel costs
> 5 and deleting one file costs 1, so fix the key first. That ranking is
> computed: for every candidate we remove it from the data, re-run the whole
> path-finder, and count what's left."

### Beat 6 — "Watch" *(3:15, 30s)*

Click **Apply** on **fix-04**, the sudo fix.

Use the 2-of-3 fix, not the one that kills everything — a partial result is more
convincing than a clean sweep, because it shows the tool discriminating.

> "Two paths gone. One survives, because that route never used the sudo rule.
> This is not a filtered list — the path-finder genuinely re-ran against the
> patched configuration and could not build those two routes any more."

Then click **Reset**.

---

## 6. The questions you will get

**"Is that database kernel real?"**

No — and the tool says so itself, which is the answer.

> "Containers share the host's kernel, so three containers cannot genuinely run
> three different kernel versions. The lab *declares* db01's kernel, and every
> finding derived from it is tagged `provenance: declared` and printed with a
> `!`. Everything else — file permissions, sudo rules, key fingerprints, network
> reachability — is measured on the live machine. Switching to three VMs instead
> of containers makes the kernel measured too, with no code change."

**"Your precision is 0. Is it broken?"**

No. It is the honest number.

> "Config coverage is 3 of 3: the configuration each technique needs is present.
> Precision is 0 of 3 because precision means *we executed the technique and it
> worked*, and we have not built the execution verifier yet. We'd rather show you
> a zero than a placeholder. That's the next milestone."

**"Isn't this just BloodHound?"**

See doc 01 §6. Short version: BloodHound maps Active Directory relationships.
This reasons about Linux host configuration, and verifies by execution.

**"The network is tiny."**

> "It is. But the enumeration is a depth-first search over the attacker's
> (host, privilege) state space, and the remediation is greedy weighted
> set-cover — the same code runs unchanged on a larger fact set. Only the input
> grows."

**"Could you have planted the answer?"**

> "Run `python3 collectors/collect.py --from-raw collectors/fixtures/lab_capture.json`
> and change a rule in `scope.yaml`. The findings change accordingly. Nothing
> downstream of the collector knows what was planted."

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `permission denied ... docker.sock` | your user isn't in the `docker` group yet | `sudo usermod -aG docker "$USER"` then log out and back in |
| `no lab hosts found. Is the lab up?` | containers aren't running | `bash lab/up.sh` |
| `ModuleNotFoundError: uvicorn` | using system Python instead of the venv | `.venv/bin/python service/main.py` |
| `PyYAML is required to read scope.yaml` | missing dependency | `pip install pyyaml` |
| `npm: command not found` | Node package manager missing | `sudo apt-get install -y npm` |
| `Address already in use` on 8000 | a service is still running | `pkill -f service/main.py` |
| dashboard shows 0 paths | a fix is still applied from a previous run | `curl -X POST localhost:8000/api/reset` |
| collector reports 2 declined, not 4 | lab predates the negative controls | `bash lab/down.sh && bash lab/up.sh` to rebuild |

**No Docker at all?** The whole analysis still runs:

```bash
python3 collectors/collect.py --from-raw collectors/fixtures/lab_capture.json
python3 enumerator/pathfinder.py
```

That file is a real recording of a live lab run, so nothing downstream is faked.
Say so if you use it.

---

## 8. Cleaning up

```bash
bash lab/down.sh              # stop and remove the containers and networks
pkill -f service/main.py      # stop the API
# Ctrl-C the dashboard terminal
```

The lab keeps no state, so `down` then `up` is the complete reset.

---

## 9. What is not built yet — say this before you're asked

- **`verifier/`** — executes each technique in the lab to confirm it works. Until
  it exists, precision is 0 everywhere and every path shows *Unverified*. This is
  Semester-1 milestone S1-M4 and it is the next thing we build.
- **`scorer/`** — the machine-learning exploitability model (S1-M5).
- A single `docker compose up` that starts the analysis service and dashboard
  together.

Volunteering this is much stronger than being caught by it.
