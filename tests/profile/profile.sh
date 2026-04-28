#!/usr/bin/env bash
# Usage:
#   tests/profile/profile.sh [--storage=sqlite] [--runner=swoole] [--clients=8]
#                            [--duration=30] [--warmup=3] [--seed-entries=2000]
#                            [--cpus=4] [--rate=249] [--port=10389]
#                            [--mix=search-sub=100]
#                            [--keep-up] [--no-build]
set -euo pipefail

cd "$(dirname "$0")/../.."
COMPOSE_FILE="tests/profile/docker-compose.yml"
SERVICE="freedsx"
CONTAINER="freedsx-profile"

STORAGE="sqlite"
RUNNER="swoole"
CLIENTS=8
DURATION=30
WARMUP=3
SEED_ENTRIES=2000
CPUS=4
RATE=249
PORT=10389
MIX="search-sub=100"
KEEP_UP=0
BUILD_ARG="--build"

for arg in "$@"; do
    case "$arg" in
        --storage=*)      STORAGE="${arg#*=}" ;;
        --runner=*)       RUNNER="${arg#*=}" ;;
        --clients=*)      CLIENTS="${arg#*=}" ;;
        --duration=*)     DURATION="${arg#*=}" ;;
        --warmup=*)       WARMUP="${arg#*=}" ;;
        --seed-entries=*) SEED_ENTRIES="${arg#*=}" ;;
        --cpus=*)         CPUS="${arg#*=}" ;;
        --rate=*)         RATE="${arg#*=}" ;;
        --port=*)         PORT="${arg#*=}" ;;
        --mix=*)          MIX="${arg#*=}" ;;
        --keep-up)        KEEP_UP=1 ;;
        --no-build)       BUILD_ARG="" ;;
        -h|--help)
            sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown arg: $arg" >&2
            exit 2
            ;;
    esac
done

OUT_DIR="tests/profile/out"
mkdir -p "$OUT_DIR"

echo "==> bringing up profile stack (cpus=$CPUS)"
PROFILE_CPUS="$CPUS" docker compose -f "$COMPOSE_FILE" up -d $BUILD_ARG --wait "$SERVICE"

echo "==> ensuring composer deps are installed"
docker exec "$CONTAINER" bash -lc 'test -f vendor/autoload.php || composer install --no-interaction --no-progress'

echo "==> stopping any prior server in the container"
docker exec "$CONTAINER" bash -lc "pkill -f 'ldap-backend-storage\.php' || true"
sleep 1

SERVER_CMD="php tests/bin/ldap-backend-storage.php tcp --storage=$STORAGE --runner=$RUNNER --port=$PORT"
if [[ "$SEED_ENTRIES" -gt 0 ]]; then
    SERVER_CMD="$SERVER_CMD --seed-entries=$SEED_ENTRIES"
fi

echo "==> starting server: $SERVER_CMD"
docker exec -d "$CONTAINER" bash -lc "$SERVER_CMD >/tmp/freedsx-server.log 2>&1"

echo "==> waiting for $PORT to listen"
docker exec "$CONTAINER" bash -lc "
    for i in \$(seq 1 100); do
        (echo > /dev/tcp/127.0.0.1/$PORT) >/dev/null 2>&1 && exit 0
        sleep 0.1
    done
    echo 'server did not start' >&2
    cat /tmp/freedsx-server.log >&2
    exit 1
"

LOAD_BACKEND="$STORAGE"
if [[ "$LOAD_BACKEND" == "json" || "$LOAD_BACKEND" == "memory" ]]; then
    : # passthrough
fi

LOAD_CMD="php tests/bin/ldap-load-test.php --server=external --backend=$LOAD_BACKEND --runner=$RUNNER --host=127.0.0.1 --port=$PORT --duration=$((DURATION + WARMUP + 5)) --warmup=$WARMUP --clients=$CLIENTS --seed-entries=0 --output=text"
if [[ -n "$MIX" ]]; then
    LOAD_CMD="$LOAD_CMD --mix=$MIX"
fi

echo "==> starting load generator (background): $LOAD_CMD"
docker exec -d "$CONTAINER" bash -lc "$LOAD_CMD >/tmp/freedsx-load.log 2>&1"

echo "==> warmup ${WARMUP}s before sampling"
sleep "$WARMUP"

echo "==> sampling for ${DURATION}s @ ${RATE}Hz"
PHPSPY_THREADS=64
if [[ "$RUNNER" == "pcntl" ]]; then
    PHPSPY_THREADS=$((CLIENTS * 16))
fi
docker exec "$CONTAINER" bash tests/profile/attach-phpspy.sh "$DURATION" "$RATE" /tmp/phpspy "$PHPSPY_THREADS"

echo "==> load generator output (tail):"
docker exec "$CONTAINER" tail -30 /tmp/freedsx-load.log || true

echo "==> copying flamegraph out"
docker cp "$CONTAINER:/tmp/phpspy.svg" "$OUT_DIR/phpspy.svg"
docker cp "$CONTAINER:/tmp/phpspy.folded" "$OUT_DIR/phpspy.folded"

echo "==> stopping server"
docker exec "$CONTAINER" bash -lc "pkill -f 'ldap-backend-storage\.php' || true"

if [[ "$KEEP_UP" -eq 0 ]]; then
    echo "==> tearing down profile stack (pass --keep-up to skip)"
    docker compose -f "$COMPOSE_FILE" down
fi

echo
echo "flamegraph: $OUT_DIR/phpspy.svg"
echo "folded:     $OUT_DIR/phpspy.folded"

if [[ "$(uname)" == "Darwin" ]]; then
    open "$OUT_DIR/phpspy.svg"
fi
