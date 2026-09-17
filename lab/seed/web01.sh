#!/bin/bash
set -euo pipefail
source /tmp/seed/common.sh

# Debian's www-data (uid 33) already exists with home /var/www and a nologin
# shell. Give it a real shell so it is a usable foothold account.
ascend_user www-data 33

# ── PLANTED VECTOR: T1552.001 — Unsecured Credentials in Files ───────────────
# The app deploy PRIVATE key is left readable by every account on the host.
# Mode 0644 is the whole finding: probes/cred_files.py reports it because it is
# other-readable, and would NOT report it at 0600.
install -d -m 755 -o www-data -g www-data /var/www/.ssh
install -m 644 -o www-data -g www-data /tmp/keys/app_deploy_key /var/www/.ssh/id_rsa

# A little realism: the deploy script that explains why the key is there.
cat > /var/www/deploy.sh <<'EOF'
#!/bin/sh
# Nightly build push. Runs as www-data from cron.
ssh -i /var/www/.ssh/id_rsa appuser@app01 '/opt/app/reload.sh'
EOF
chmod 755 /var/www/deploy.sh
chown www-data:www-data /var/www/deploy.sh

ascend_lock_passwords
ascend_canary
