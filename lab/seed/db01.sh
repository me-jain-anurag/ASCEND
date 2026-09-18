#!/bin/bash
set -euo pipefail
source /tmp/seed/common.sh

ascend_user dbuser 1002

# The SAME deploy key is accepted here too. This is the reuse that makes the
# key the chokepoint: one disclosure on web01 reaches BOTH app01 and db01.
ascend_authorize dbuser

# ── PLANTED VECTOR: T1068 — Exploitation for Privilege Escalation ────────────
# DECLARED, NOT OBSERVED. /etc/ascend/declared_kernel says 5.16.0, which is in
# the DirtyPipe (CVE-2022-0847) range. A container shares the host kernel, so
# this attribute cannot be genuine here; probes/kernel.py always reports the
# real `uname -r` next to it and tags the vector provenance: declared.
# The VM fallback in docs/02 section 6 makes this fact observed instead.
# BRING YOUR OWN BINARY — see lab/exploits/README.md.
#
# A real CVE-2022-0847 exploit binary dropped into lab/exploits/ is installed
# here as an ORDINARY executable. It is deliberately NOT setuid: an exploit that
# needs a setuid bit to reach root is not demonstrating the kernel bug, and the
# verifier would then be measuring the file mode. A previous version of this
# lab did exactly that and produced a fabricated "DirtyPipe verified" result.
#
# Containers share the host kernel, so this technique reports not_executable
# here whatever is installed. The three-VM fallback (docs/02 section 6) is what
# makes it runnable for real.
if [[ -f /tmp/exploits/exploit ]]; then
    install -d -m 755 /opt/exploits/CVE-2022-0847
    install -m 0755 -o root -g root /tmp/exploits/exploit /opt/exploits/CVE-2022-0847/exploit
fi

install -d -m 750 -o dbuser -g dbuser /var/lib/appdata
cat > /var/lib/appdata/README <<'EOF'
Customer records live here. This is the crown-jewel asset (asset_value 100,
declared in scope.yaml). Reading it requires root on db01.
EOF
chmod 640 /var/lib/appdata/README
chown root:root /var/lib/appdata/README

# ── PLANTED VECTOR: T1548.001 — Setuid/Setgid ────────────────────────────────
# A setuid-root `find`, the way a careless maintenance script leaves one behind.
#
# Unlike the kernel exploit above, this one a container CAN actually execute, so
# the verifier can walk a complete path to root on the crown jewel and prove it.
# It is a genuine weakness, not a prop: GTFOBins documents the escape, the
# collector detects it through rules.suid in scope.yaml (find is outside the
# Debian baseline and has a documented shell escape), and nothing tells the
# collector it is here.
#
# The escape needs `sh -p`: without it the shell drops the inherited euid and
# the attempt silently gains nothing.
cat > /usr/local/sbin/nightly-index <<'SCRIPT'
#!/bin/sh
# Nightly index of customer records. Runs from cron as root.
find /var/lib/appdata -type f -newer /etc/hostname
SCRIPT
chmod 755 /usr/local/sbin/nightly-index
chmod u+s /usr/bin/find

ascend_lock_passwords
ascend_canary
