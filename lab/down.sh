#!/usr/bin/env bash
# Tear the lab down. --volumes removes nothing persistent (the lab is stateless
# by design: docs/02 section 6, "containers reset in seconds").
set -euo pipefail
LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker compose -f "$LAB/docker-compose.yml" down --volumes --remove-orphans
echo "lab down."
