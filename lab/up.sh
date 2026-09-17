#!/usr/bin/env bash
# Bring up the isolated lab and wait until every host answers on SSH.
set -euo pipefail
LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

bash "$LAB/bootstrap.sh"

echo "building and starting the lab..."
docker compose -f "$LAB/docker-compose.yml" up -d --build

echo -n "waiting for sshd on all three hosts"
for _ in $(seq 1 30); do
    ready=0
    for c in ascend-web01 ascend-app01 ascend-db01; do
        docker exec "$c" sh -c 'ss -ltn 2>/dev/null | grep -q ":22 "' 2>/dev/null && ready=$((ready+1))
    done
    [[ $ready -eq 3 ]] && { echo " ready."; break; }
    echo -n "."; sleep 1
done

echo
docker compose -f "$LAB/docker-compose.yml" ps
echo
echo "next:  python3 collectors/collect.py"
