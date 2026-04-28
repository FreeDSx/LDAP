#!/usr/bin/env bash
# Samples the running ldap-backend-storage.php server (and any forked children)
# for $DURATION_S seconds at $RATE_HZ Hz, then renders a flamegraph.
#
# Usage (from inside the container, or via `docker exec freedsx-profile bash <this>`):
#   tests/profile/attach-phpspy.sh [duration_s=30] [rate_hz=249] [out_prefix=/tmp/phpspy] [threads=64]
#
# Output files:
#   ${out_prefix}.stacks   raw phpspy frames
#   ${out_prefix}.folded   collapsed stacks (one line per unique stack)
#   ${out_prefix}.svg      flamegraph
set -euo pipefail

DURATION_S="${1:-30}"
RATE_HZ="${2:-249}"
OUT="${3:-/tmp/phpspy}"
THREADS="${4:-64}"

PGREP_ARGS='-f ^php[[:space:]].*ldap-backend-storage\.php'

PIDS=$(pgrep $PGREP_ARGS || true)
if [[ -z "$PIDS" ]]; then
    echo "no ldap-backend-storage.php php process found — start the server first." >&2

    exit 1
fi

PID_COUNT=$(echo "$PIDS" | wc -w | tr -d ' ')
echo "phpspy tracing $PID_COUNT process(es) [$PIDS] for ${DURATION_S}s at ${RATE_HZ}Hz (threads=$THREADS)..."

# -H <hz>     : sample rate (>200 helps catch fast paths).
# -T <n>      : sampler thread pool — needs to comfortably exceed the number of
#               PHP worker processes/coroutines.
# -n 128      : max stack depth (deep call chains in the protocol layer).
# --pgrep     : keep auto-attaching to children forked mid-run (pcntl runner).
phpspy \
    -H "$RATE_HZ" \
    -T "$THREADS" \
    -n 128 \
    --pgrep="$PGREP_ARGS" \
    > "${OUT}.stacks" 2> "${OUT}.err" &

SPID=$!
sleep "$DURATION_S"
kill "$SPID" 2>/dev/null || true
wait "$SPID" 2>/dev/null || true

STACK_LINES=$(wc -l < "${OUT}.stacks")
echo "captured $STACK_LINES sample lines"
if [[ "$STACK_LINES" -lt 100 ]]; then
    echo "WARNING: very few samples — check that load was actually running and the server" >&2
    echo "         was busy during sampling. tail of phpspy stderr:" >&2
    tail -20 "${OUT}.err" >&2 || true
fi

echo "collapsing stacks..."
stackcollapse-phpspy.pl < "${OUT}.stacks" > "${OUT}.folded"

echo "rendering flamegraph..."
flamegraph.pl --title "FreeDSx server (sampled ${DURATION_S}s @ ${RATE_HZ}Hz, ${PID_COUNT} pid(s))" \
    --width 1600 \
    < "${OUT}.folded" > "${OUT}.svg"

echo "done:"
echo "  raw:     ${OUT}.stacks ($STACK_LINES frames)"
echo "  folded:  ${OUT}.folded ($(wc -l < "${OUT}.folded") unique stacks)"
echo "  flame:   ${OUT}.svg"
