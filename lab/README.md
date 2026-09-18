# `lab/` — the isolated Docker lab

Three Linux containers carrying real, planted weaknesses. The fact collectors
read this lab; the enumerator analyses what they find.

```
        [ ascend_dmz ]            [ ascend_core ]
   web01 ──────────► app01 ──────────────► db01
   entry             (dual-homed pivot)     crown jewel
   www-data          appuser                dbuser
```

Both networks are `internal: true` — **no route to the internet or the campus
network**, and no ports published to your machine. Nothing in here is reachable
from outside the Docker bridges.

## Prerequisites — installing Docker

You need Docker Engine and the Compose v2 plugin. Use Docker's official install
script:

```bash
curl -fsSL https://get.docker.com | bash
```

It detects the distribution, adds Docker's repository and installs Engine, the
CLI, containerd, buildx and the Compose plugin. It calls `sudo` itself, so run
it as your normal user.

`-fsSL` is worth keeping: without `-f`, curl prints an HTTP error page instead
of failing, and piping that into a shell is a bad day. Add `--dry-run` to see
what it would do without touching anything.

**This script does not support Arch.** There, install from the repositories
instead:

```bash
sudo pacman -S --needed docker docker-compose
sudo systemctl enable --now docker
```

The `systemctl` line matters on Arch: pacman installs the service without
starting it or enabling it at boot.

Then let your user reach the daemon:

```bash
sudo usermod -aG docker "$USER"
newgrp docker
```

Verify before going further — `lab/up.sh` needs all three to work:

```bash
docker --version
docker compose version        # must print v2.x
docker run --rm hello-world   # proves your user can reach the daemon
```

### Notes

- **The `docker` group is root-equivalent.** Anyone in it can start a privileged
  container and own the host — which is exactly the T1611 vector in `scope.yaml`.
  Adding yourself is normal on a development machine; do not do it on a shared
  one.
- **`newgrp docker` only affects the shell you run it in.** If `docker ps` still
  says "permission denied" in a new terminal, log out and back in.
- **Building needs the internet** (the base image and `apt-get install`). Only
  the *running* lab is isolated — both its networks are `internal: true`.
- **Any Docker install works.** The script is just the quickest route; your
  distribution's packages or Docker Desktop on macOS or Windows/WSL2 are equally
  fine, as long as `docker compose version` prints v2.x.

## Run it

```bash
bash lab/up.sh                  # generates the deploy key, builds, waits for sshd
python3 collectors/collect.py   # -> environment_graph/facts.json
python3 enumerator/pathfinder.py # -> the paths and chokepoints
bash lab/down.sh
```

`lab/up.sh` is idempotent. The lab holds no state, so tearing it down and
bringing it back up is the reset procedure (docs/02 §6).

## What is planted, and why

| Host | Weakness | Technique | Real? |
|---|---|---|---|
| `web01` | `/var/www/.ssh/id_rsa` at mode **0644** | T1552.001 | yes — a real file at a real mode |
| `app01` | `appuser ALL=(root) NOPASSWD: /bin/tar` | T1548.003 | yes — a real sudoers rule |
| `app01` + `db01` | the **same** deploy key in both `authorized_keys` | T1550 | yes — real key reuse |
| `db01` | declared kernel 5.16.0 → DirtyPipe | T1068 | **declared, not observed** |

Nothing tells the collector where these are. It finds the key by walking the
filesystem, finds the sudo rule by asking `sudo -l`, finds the reuse by
**fingerprinting the private key and matching it against every `authorized_keys`
on every host**, and finds the segmentation by opening real TCP connections.

### The one honest exception: the kernel

Containers share the host's kernel. Three containers therefore **cannot** run
three different kernel versions, and any tool claiming otherwise is lying.

So each image carries `/etc/ascend/declared_kernel`, and `probes/kernel.py`
reports **both** values:

```json
{ "observed_kernel": "7.2.6-x64v3-xanmod1",
  "declared_kernel": "5.16.0",
  "effective_kernel": "5.16.0",
  "provenance": "declared" }
```

Every vector derived from it carries `features.provenance: "declared"`, the
collector prints it with a `!` marker, and the evidence block spells out why.
Switching to the three-VM fallback in docs/02 §6 removes the declared file and
the same probe reports the kernel as `observed`, with no code change.

**If a reviewer asks "is that kernel real?", the answer is already on the
screen.** That is the point of carrying provenance rather than hiding it.

### Deliberate non-findings (negative controls)

Four conditions are planted specifically so the collector must examine them and
**decline to report them**. A scanner that flags everything proves nothing, and
these are the cases where a careless rule would produce a false positive:

| Host | Planted | Why it must NOT be reported |
|---|---|---|
| `app01` | the *same* deploy key at `/home/appuser/.ssh/id_rsa`, mode **0600** | app01 legitimately needs the key. The finding on web01 is the *permission*, not the presence of a key |
| `app01` | `appuser ALL=(root) NOPASSWD: /bin/ls` | NOPASSWD, but `ls` has no shell escape |
| `app01` | declared kernel **5.10.150** | DirtyPipe was fixed in 5.10.102, so this branch is patched — even though 5.10.150 is below the headline 5.16.11 |
| all | 10 Debian setuid-root binaries (`su`, `sudo`, `mount`, …) | distribution baseline, present on every Debian host |

A live run reports each of the first three by name, with its reason, in
`environment_graph/collection_report.json`:

```
app01  T1552.001  /home/appuser/.ssh/id_rsa   mode 600 — readable only by its owner
app01  T1548.003  (root) NOPASSWD: /bin/ls    /bin/ls has no documented shell escape
app01  T1068      CVE-2022-0847               5.10.150 is at or above the 5.10 branch fix
web01  T1068      CVE-2022-0847               kernel 5.4.0 is below the affected range
```

That table is worth a slide. It is the difference between "we found three
things" and "we considered seven and can say why four are not findings".

### Verified on a live run

```
web01 -> app01:22   open                    app01 is dual-homed on ascend_dmz
web01 -> db01 :22   dns_failure             no shared network, so no DNS
web01 -> 172.18.0.3 Network is unreachable  and no route to db01's real address
```

The probe tries the target's DNS name **and** every address it holds, so the
segmentation claim rests on a routing failure to a known IP, not merely on a
name that would not resolve.

## Files

```
docker-compose.yml   two internal networks, three services
Dockerfile           one image, parameterised by ROLE and DECLARED_KERNEL
entrypoint.sh        generate host keys, run sshd in the foreground
bootstrap.sh         generate the shared deploy keypair into keys/ (gitignored)
up.sh / down.sh      lifecycle
seed/common.sh       helpers: create accounts, authorize keys, lock passwords
seed/web01.sh        plants the world-readable key
seed/app01.sh        plants the NOPASSWD sudo rule, accepts the deploy key
seed/db01.sh         accepts the deploy key, declares the vulnerable kernel
```

`keys/` is gitignored and regenerated per clone. The keypair only ever
authenticates to throwaway containers, but it is still a private key and does
not belong in the repository.

## Adding a host

1. Add a service to `docker-compose.yml` with its own `ROLE`, and attach it to
   whichever networks it should reach.
2. Write `seed/<role>.sh`.
3. Add it to `inventory.hosts` in `scope.yaml` (role, asset value).
4. `bash lab/up.sh && python3 collectors/collect.py`.

No collector change is needed unless the host has a weakness of a kind no probe
covers yet — see `collectors/README.md`.
