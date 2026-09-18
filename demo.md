# `demo.md` — running and demonstrating ASCEND

The runbook for the review. Doc 05 §2 asks for this file; this is it, plus the
testing pass you should do **before** standing in front of anyone.

No prior knowledge of the codebase is assumed. If you can open a terminal, you
can run this.

---

## TL;DR

```bash
.venv/bin/python tests/test_pipeline.py   # 1. prove the logic  -> 22 passed
bash lab/down.sh && bash lab/up.sh        # 2. rebuild the lab  -> ~2s cached
python3 collectors/collect.py             # 3. go look at it    -> 3 vectors
python3 enumerator/pathfinder.py           # 4. find the routes  -> 3 paths
.venv/bin/python -m verifier check        # 5. lab healthy?     -> canary on 3 hosts
.venv/bin/python service/main.py          # 6. API   :8000  (own terminal)
cd dashboard && npm run dev               # 7. UI    :5173  (own terminal)
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

verifier/     goes back into the lab and RUNS each step, to prove the
              paths are real rather than merely reasoned
```

Each arrow is a separate program, and that is the point. The collector does not
know what an "attack path" is; the enumerator does not know Docker exists. So
when the enumerator finds a path, it found it from **evidence**, not from a hint
someone planted for it.

---

## 3. Setup (once per machine)

**Ubuntu / Debian**

```bash
curl -fsSL https://get.docker.com | sh
sudo apt-get install -y python3-venv nodejs npm
sudo usermod -aG docker "$USER"
```

**Arch** — `get.docker.com` has no Arch support, so install from the repos:

```bash
sudo pacman -S --needed docker docker-compose python nodejs npm
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

> **Now log out of your desktop and log back in.** Linux fixes your groups at
> login, so until you do, `docker` fails with *permission denied* — and it fails
> per-terminal, which is maddening to debug. Confirm with `docker ps` (no
> `sudo`). A new terminal is **not** enough; it must be a full logout.

Then the project dependencies, from the repo root:

```bash
python3 -m venv .venv
.venv/bin/pip install -r service/requirements.txt -r verifier/requirements.txt
cd dashboard && npm install && cd ..
```

Check it once, well before demo day:

```bash
.venv/bin/python tests/test_pipeline.py    # 22 passed
cd dashboard && npm run build && cd ..     # ✓ built
```

`.venv/bin/python` is the Python that has our packages. Plain `python3` will
fail with `ModuleNotFoundError` for anything except the path-finder, which
deliberately needs nothing.

---

## 4. Running it

Three terminals. Two of them stay open.

```bash
# Terminal 1 — build the lab, then analyse it
bash lab/down.sh && bash lab/up.sh     # 3 containers, ~2s once cached
python3 collectors/collect.py          # look at them -> facts.json
python3 enumerator/pathfinder.py       # find the routes -> 3 paths
.venv/bin/python -m verifier check     # canary reachable on all 3?

# Terminal 2 — the API (leave running)
.venv/bin/python service/main.py       # port 8000

# Terminal 3 — the dashboard (leave running)
cd dashboard && npm run dev            # port 5173
```

Open <http://localhost:5173>. The header should read **Backend Online**.

**Pre-flight:** `22 passed` · `verifier check` OK on 3 hosts · collector shows
`3 vectors` and `4` declined · `3 attack paths` · dashboard loads · you clicked
**Reset** so no fix is left applied from a rehearsal.

---

## 4b. What each module is for

| Module | What it is for |
|---|---|
| `scope.yaml` | Single source of truth: techniques in scope, evidence each needs, cost of each fix. Written by humans, read by the code. |
| `lab/` | The three fake machines, with weaknesses deliberately planted. |
| `collectors/` | Goes and looks at them; writes `facts.json`. |
| `knowledge_graph/` | Public reference data (ATT&CK, CVE, CWE) so findings are named properly. |
| `enumerator/` | Works out every route from foothold to crown jewel. |
| `chokepoint/` | Works out which fixes kill the most routes for the least effort. |
| `verifier/` | Goes back and **actually runs** each step, to prove the routes are real. |
| `service/` | Ties it together, serves JSON on port 8000. |
| `dashboard/` | Draws it. |
| `tests/` | Checks all of the above, including that nothing claims an execution that never happened. |

**Everything up to `enumerator/` is reasoning. `verifier/` is what checks that
reasoning against reality.** That split is the argument of the project.

---

## 5. The demo — about 5 minutes

Each beat below gives you three things: **what to do**, what is *actually*
happening underneath (for the technical question that follows), and the plain
sentence to say out loud.

---

### Beat 1 — "This is the lab" · 0:00, 30s

**Do:**

```bash
docker compose -f lab/docker-compose.yml ps
```

**Technically.** Three `debian:bookworm-slim` containers on *two* Docker bridge
networks, both marked `internal: true` — no route to the internet or your
campus network, and no ports published to the host. `app01` is deliberately
dual-homed: it sits on `ascend_dmz` with `web01` **and** on `ascend_core` with
`db01`. `web01` and `db01` share no network at all, so they cannot route to each
other. That segmentation is the thing the collector later has to *discover*
rather than be told.

**Say:** "Three Linux machines on two isolated networks — no internet, nothing
exposed to my laptop. `web01` is where an attacker gets in. `db01` holds the
data we care about."

---

### Beat 2 — "The weaknesses are real, not JSON we wrote" · 0:30, 45s

**Do:**

```bash
docker exec ascend-web01 ls -l /var/www/.ssh/id_rsa
docker exec ascend-app01 sudo -l -U appuser
```

**Technically.** The first prints `-rw-r--r--`, mode 0644 — an SSH *private* key
readable by every account on the box. The second asks `sudo` itself (not a
config file) what `appuser` may do, and it answers `(root) NOPASSWD: /bin/tar`.
`tar --checkpoint-action=exec=` runs an arbitrary command, so that rule is
equivalent to handing out a root shell. Both are genuine OS state, planted by
`lab/seed/*.sh` at image build.

**Say:** "A private SSH key readable by everyone on the box. And `appuser` can
run `tar` as root with no password — `tar` can spawn a shell, so that rule *is*
a root shell. We didn't write these into a config file. They're really on these
machines."

---

### Beat 3 — "The collector goes and looks" · 1:15, 60s

**The strongest beat. Don't rush it.**

**Do:**

```bash
python3 collectors/collect.py
```

**Technically.** Nine probes run over `docker exec`, reading `/etc/passwd`,
`sudo -ln -U`, setuid binaries, listening sockets and candidate credential
files. Every private key found is parsed as `openssh-key-v1` in pure Python and
reduced to a `SHA256:` fingerprint — byte-identical to `ssh-keygen -lf` — then
compared against every `authorized_keys` entry on every host. Reachability is
measured by opening **real TCP connections** from inside each source container,
to the target's DNS name *and* each of its addresses. `derive.py` then applies
the rules in `scope.yaml` to decide which raw observations amount to a weakness.

Point at three things:

**(a) The credential-reuse line.**
> "It found the private key on web01, fingerprinted it, and matched that
> fingerprint against every `authorized_keys` on every machine. The same key
> opens app01 *and* db01. Nobody told it that — it's a cryptographic match."

**(b) Only 4 reachability edges, and no `web01 → db01`.**
> "It opened real TCP connections from inside each container. web01 simply
> cannot reach the database. That's how it knows the network is segmented — we
> didn't declare it."

**(c) The 4 declined conditions.** Read them aloud.
> "This is the part I'd want to see if I were you. It found a NOPASSWD sudo rule
> for `/bin/ls` and said no — `ls` can't give you a shell. It found the *same*
> private key on app01 and said no — that copy is mode 0600, only its owner can
> read it, and the finding is the permission, not the file. It found app01's
> 5.10 kernel and said no — that branch was patched at 5.10.102. A scanner that
> flags everything proves nothing. Ours considered seven things and reports
> three."

---

### Beat 4 — "Here are the routes" · 2:15, 30s

**Do:** the Attack Paths tab (easier to read on a projector than the terminal).

**Technically.** A depth-first search over the attacker's *state*: the set of
`(host, privilege)` pairs held, plus the set of credentials held. Three move
types grow that set — harvest a credential from a readable file (T1552.001),
log in elsewhere with a held credential (T1021.004 + T1550), or escalate locally
(T1548.003, T1068). Every sequence ending at `db01:root` is recorded. Visited
states are pruned, so it terminates.

**Say:** "Three routes from a foothold on web01 to root on the database. Each
step is a named MITRE ATT&CK technique — a harvested key, a sudo
misconfiguration, a kernel exploit."

---

### Beat 5 — "And we don't just claim it — we run it" · 2:45, 75s

**This is the beat the whole project exists for.**

**Do:** click **Verify** (or `curl -X POST localhost:8000/api/verify`). Takes
about 10 seconds, because it is doing real work.

**Technically.** Each lab host carries a **canary**: `/root/.ascend_canary`,
mode 0400, containing a random secret regenerated at every build. Every
escalation technique ends by trying to read it. If the secret appears in stdout,
privilege genuinely escalated — that is the only criterion, identical across
techniques, so results are comparable. An adapter never decides its own result
from an exit code.

Lateral movement is checked differently but just as concretely: the adapter
copies the 0644 key to a private path, `chmod 600`, and SSHes — because OpenSSH
*refuses* a world-readable key, which is exactly the property that makes it a
finding. Success means a session actually opened as the expected user.

What comes back:

```
path-01  partial   3 of 4 steps verified
path-02  partial   2 of 3 steps verified
path-03  partial   3 of 4 steps verified
```

**Say (the part that passed):** "Everything so far was reasoning. Now we go and
do it. We read the exposed key as www-data, SSH'd to app01 with it and landed as
appuser, SSH'd on to db01 as dbuser, and used the sudo rule to become uid 0 on
app01. Eight of the eleven steps across these three routes were executed and
confirmed. Not asserted — executed."

**Say (the part that didn't) — do not skip this:** "The last step of every route
is the DirtyPipe kernel exploit, and it reports *not executable*, with the
reason. Containers share the host machine's kernel, so db01 doesn't really run
the vulnerable 5.16.0 our graph says it does. We could have made that green very
easily. We didn't, because a verifier that reports a success it didn't achieve
makes every other number we show you worthless. So the route is *partial*: we
haven't proven it, and we haven't disproven it either."

**If asked how you'd finish it:** a genuinely vulnerable kernel, which means the
three-VM fallback in docs/02 §6 rather than containers.

---

### Beat 6 — "Here's the cheapest fix" · 4:00, 30s

**Do:** the Remediation tab.

**Technically.** Greedy weighted set-cover over the enumerated paths. Each
candidate fix's effect is not inferred from the graph — it is **measured**: the
engine removes that fix from a copy of the facts, re-runs the real path-finder,
and diffs the surviving paths against the baseline. Candidates come in two
kinds, because they are genuinely different remediations: removing a vector, and
revoking a reused credential everywhere it is accepted.

**Say:** "Three different fixes each kill all three routes. But patching the
kernel costs 5 and deleting one file costs 1 — so fix the key first. That
ranking is computed: for every candidate we remove it, re-run the whole
path-finder, and count what's left."

---

### Beat 7 — "Watch" · 4:30, 30s

**Do:** click **Apply** on **fix-04** (the sudo fix — the 2-of-3 one, *not* the
one that kills everything). Then **Reset**.

**Why fix-04:** a clean sweep looks like a magic trick. A partial result shows
the tool discriminating, which is more convincing.

**Technically.** Applying a fix stores only the fix id. `/api/enumerate` then
re-runs the path-finder against facts with that vector removed. The two routes
are absent because they can no longer be *constructed* — nothing is filtered
from a list. Path ids stay pinned to the baseline enumeration, so the survivor
keeps its original id rather than being renumbered into a dead one.

**Say:** "Two routes gone. One survives, because that route never used the sudo
rule. This isn't a filtered list — the path-finder genuinely re-ran against the
patched configuration and couldn't build those two any more."

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

No, and it is worth explaining carefully, because the number is doing real work.

> "Precision counts paths we have proven end to end. Every one of our three paths
> finishes with the DirtyPipe kernel exploit, and that step cannot run in a
> container lab, so no path is fully proven — precision is 0 of 3. But that
> undersells what we verified: 8 of the 11 individual steps ran for real and
> succeeded. The three that didn't are all the same blocked step, and each one
> reports why. We call those paths *partial* rather than failed, because failing
> would claim the attack doesn't work, and we haven't shown that."

**"Couldn't you just make that last step pass?"**

Yes, trivially — and we deliberately removed the code that did.

> "An earlier version of our lab shipped a 'DirtyPipe exploit' that was really a
> setuid-root program calling setuid(0), with no exploit logic in it. It returned
> root because of its file permissions, on any kernel, and our verifier recorded
> T1068 as verified. We found it by removing the setuid bit: it then failed on
> an unchanged kernel, which proves the 'verification' was measuring a file mode.
> We deleted it, and the verifier now checks the running kernel before it will
> run anything. There's a test that fails the build if exploit binaries come
> back."

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
| `permission denied ... docker.sock` | that terminal's session predates `usermod -aG docker` | log out of the desktop and back in; or `newgrp docker` in **each** terminal |
| lab starts, but `/api/verify` returns 503 | the API terminal lacks Docker access, the lab terminal has it | same fix, applied to the API terminal — then restart the API |
| `docker: command not found` on Arch | `get.docker.com` does not support Arch | `sudo pacman -S --needed docker docker-compose && sudo systemctl enable --now docker` |
| `docker compose` unknown, `docker-compose` works | Compose v1 only | install the v2 plugin (§3.2); this project needs `docker compose` |
| `Cannot connect to the Docker daemon` | the service is not started (common on Arch) | `sudo systemctl enable --now docker` |
| `no lab hosts found. Is the lab up?` | containers are not running | `bash lab/up.sh` |
| `ModuleNotFoundError: uvicorn` / `docker` / `yaml` | used system `python3` instead of the venv | `.venv/bin/python ...` |
| `python3 -m venv` fails on Ubuntu | `python3-venv` not installed | `sudo apt-get install -y python3-venv` |
| `Address already in use` on 8000 | an old API process still holds the port | `pgrep -af "uvicorn\|service/main.py"` then `kill <pid>` — not `ss -ltnp`, which can name a wrapper |
| `npm: command not found` | Node not installed | Ubuntu `sudo apt-get install -y nodejs npm`; Arch `sudo pacman -S --needed nodejs npm` |
| dashboard loads but every panel errors | the API is not running | start it (§4 step 6); the header should read **Backend Online** |
| dashboard shows 0 paths | a fix is still applied from a rehearsal | click **Reset** |
| collector reports 2 declined, not 4 | the lab image predates the negative controls | `bash lab/down.sh && bash lab/up.sh` |
| `verifier check` cannot read the canary | the lab was built before the canary existed | `bash lab/down.sh && bash lab/up.sh` |
| `npm run dev` works but `npm run build` fails | dev mode skips type-checking | fix the reported TypeScript errors; always build once before demo day |

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

- **`verifier/`** — built, and running. What is *not* done inside it: syscall
  telemetry (`telemetry.py` is a stub with no Falco behind it), carrying a
  harvested credential between hops, and any real CVE exploit — which needs a
  genuinely vulnerable kernel, so it needs VMs rather than containers.
- **`scorer/`** — the machine-learning exploitability model (S1-M5).
- A single `docker compose up` that starts the analysis service and dashboard
  together.

Volunteering this is much stronger than being caught by it.
