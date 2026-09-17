#!/usr/bin/env bash
# Generate the shared app deploy keypair the lab plants on web01 and accepts on
# app01 + db01. Run automatically by lab/up.sh; safe to run repeatedly.
#
# The key COMMENT is significant: collectors/probes/cred_files.py uses it as the
# cred_id in facts.json, falling back to a fingerprint hash if it is absent.
set -euo pipefail
KEYDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/keys"
mkdir -p "$KEYDIR"

if [[ -f "$KEYDIR/app_deploy_key" ]]; then
    echo "deploy key already present: $KEYDIR/app_deploy_key"
else
    ssh-keygen -t ed25519 -N '' -C 'app_deploy_key' -f "$KEYDIR/app_deploy_key" >/dev/null
    echo "generated deploy key: $KEYDIR/app_deploy_key"
fi
chmod 600 "$KEYDIR/app_deploy_key"
chmod 644 "$KEYDIR/app_deploy_key.pub"
ssh-keygen -lf "$KEYDIR/app_deploy_key.pub"

# ── Canary token for the execution verifier (A3) ─────────────────────────────
# A random secret planted as a root-only file on every host. The verifier's
# pass/fail decision reads this token after a technique runs: if the token
# appears in stdout, privilege genuinely escalated. Regenerated per lab build
# so a stale token from a previous build can never produce a false positive.
CANARY="$KEYDIR/.canary_token"
if [[ -f "$CANARY" ]]; then
    echo "canary token already present: $CANARY"
else
    python3 -c "import secrets; print(secrets.token_hex(16))" > "$CANARY"
    echo "generated canary token: $CANARY"
fi
chmod 600 "$CANARY"
