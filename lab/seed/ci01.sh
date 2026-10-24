#!/bin/bash
set -euo pipefail
source /tmp/seed/common.sh

# ci01 — the build/deploy server. Dual-homed (dmz + core) in docker-compose.yml,
# so it is a second route from web01 to db01 alongside app01.
#
# NO WEAKNESSES ARE PLANTED HERE YET. The host joins the topology with a normal
# account and the same baseline hardening as every other host, so the collector
# probes it, the reachability matrix includes it, and the enumerator sees it —
# but it adds no attack path until weaknesses are planted and documented in
# scope.yaml and lab/README.md.
ascend_user ciuser 1003

ascend_lock_passwords
ascend_canary
