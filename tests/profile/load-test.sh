#!/usr/bin/env bash
#
# Run the load test inside the Linux profiling container.
#
# Usage (from the repo root):
#   composer test-load-docker
#   composer test-load-docker -- --seed-entries=5000 --clients=4
#   composer test-load-docker -- --persistent   # data in named volumes instead of memory
#
set -euo pipefail

compose_dir="$(cd "$(dirname "$0")" && pwd)"
compose=(-f "$compose_dir/docker-compose.yml")

# Rebuilds the arguments without the flags this script consumes.
for arg in "$@"; do
    shift
    case "$arg" in
        --persistent) compose+=(-f "$compose_dir/docker-compose.persistent.yml") ;;
        *)            set -- "$@" "$arg" ;;
    esac
done

docker compose "${compose[@]}" up -d --build --wait
docker exec freedsx-profile composer install --no-interaction --quiet
docker exec freedsx-profile composer test-load -- "$@"
