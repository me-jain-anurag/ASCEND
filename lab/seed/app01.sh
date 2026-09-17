#!/bin/bash
set -euo pipefail
source /tmp/seed/common.sh

ascend_user appuser 1001

# The deploy key is accepted here — half of the credential reuse.
ascend_authorize appuser

# ── PLANTED VECTOR: T1548.003 — Sudo and Sudo Caching ────────────────────────
# appuser may run tar as root with no password. tar's --checkpoint-action flag
# executes an arbitrary command, so this rule is equivalent to a root shell.
# probes/sudo.py reports it because rules.sudo in scope.yaml lists /bin/tar as
# a shell-escape binary; a NOPASSWD rule for, say, /bin/ls would not be reported.
# The second rule is a NEGATIVE CONTROL. /bin/ls is also NOPASSWD, but it has
# no shell escape, so the collector must examine it and DECLINE to report it.
# A scanner that flags every NOPASSWD rule would emit a false positive here.
cat > /etc/sudoers.d/appuser <<'SUDOERS'
appuser ALL=(root) NOPASSWD: /bin/tar
appuser ALL=(root) NOPASSWD: /bin/ls
SUDOERS
chmod 0440 /etc/sudoers.d/appuser
visudo -cf /etc/sudoers.d/appuser

install -d -m 755 -o appuser -g appuser /opt/app
cat > /opt/app/reload.sh <<'EOF'
#!/bin/sh
# Rotate build artefacts. Needs root to write /var/backups, hence the sudo rule.
sudo /bin/tar -czf /var/backups/app-$(date +%F).tgz /opt/app
EOF
chmod 755 /opt/app/reload.sh
chown appuser:appuser /opt/app/reload.sh

# ── NEGATIVE CONTROL: the same deploy key, stored CORRECTLY ─────────────────
# app01 legitimately needs this key to reach db01, and here it is kept at mode
# 0600. The collector must find it, fingerprint it, notice it is the same key as
# the one exposed on web01 — and still not report it as a disclosure, because
# only its owner can read it. The finding on web01 is the permission, not the
# presence of the file.
install -d -m 700 -o appuser -g appuser /home/appuser/.ssh
install -m 600 -o appuser -g appuser /tmp/keys/app_deploy_key /home/appuser/.ssh/id_rsa

ascend_lock_passwords
