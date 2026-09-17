#!/bin/bash
# Shared helpers for the per-role seed scripts.
set -euo pipefail

DEPLOY_KEY_PRIV=/tmp/keys/app_deploy_key
DEPLOY_KEY_PUB=/tmp/keys/app_deploy_key.pub
CANARY_TOKEN_FILE=/tmp/keys/.canary_token

# ascend_user <name> <uid> — create a login-capable account.
# The collector's account probe only reports accounts with a real login shell,
# so system accounts (nologin/false/sync) stay out of the environment graph.
ascend_user() {
    local name="$1" uid="$2"
    if id -u "$name" >/dev/null 2>&1; then
        usermod -s /bin/bash "$name"
    else
        useradd -m -u "$uid" -s /bin/bash "$name"
    fi
}

# ascend_authorize <user> — accept the shared app deploy key for this account.
# Calling this on more than one host is what creates the CREDENTIAL REUSE that
# probes/ssh_keys.py detects by fingerprint match. No host is told about it.
ascend_authorize() {
    local user="$1" home
    home="$(getent passwd "$user" | cut -d: -f6)"
    install -d -m 700 -o "$user" -g "$user" "$home/.ssh"
    cat "$DEPLOY_KEY_PUB" >> "$home/.ssh/authorized_keys"
    chmod 600 "$home/.ssh/authorized_keys"
    chown "$user:$user" "$home/.ssh/authorized_keys"
}

# Lock every password. The lab is key-only; there are no guessable passwords,
# because password guessing is explicitly out of scope (docs/01 section 4).
ascend_lock_passwords() {
    passwd -l root >/dev/null 2>&1 || true
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/'  /etc/ssh/sshd_config
}

# ascend_canary — plant a root-only file containing a per-build secret token.
# The execution verifier (A3) reads this file after running a technique. If the
# token appears in stdout, privilege genuinely escalated to root. The file is
# mode 0400 owned by root, so no unprivileged account can read it directly.
ascend_canary() {
    install -m 0400 -o root -g root "$CANARY_TOKEN_FILE" /root/.ascend_canary
}
