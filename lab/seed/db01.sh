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
if [[ -f /tmp/exploits/exploit ]]; then
    install -d -m 755 /opt/exploits/CVE-2022-0847
    install -m 4755 -o root -g root /tmp/exploits/exploit /opt/exploits/CVE-2022-0847/exploit
fi

install -d -m 750 -o dbuser -g dbuser /var/lib/appdata
cat > /var/lib/appdata/README <<'EOF'
Customer records live here. This is the crown-jewel asset (asset_value 100,
declared in scope.yaml). Reading it requires root on db01.
EOF
chmod 640 /var/lib/appdata/README
chown root:root /var/lib/appdata/README

ascend_lock_passwords
ascend_canary
