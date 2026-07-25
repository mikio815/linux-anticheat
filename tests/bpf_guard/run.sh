#!/usr/bin/env bash
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DAEMON="$ROOT/target/debug/anticheat"
PROBE=/tmp/ac_bpf_guard_probe
VICTIM=/tmp/ac_bpf_guard_victim
PIDFILE=/tmp/ac_bpf_guard_victim.pid
DLOG=/tmp/ac_bpf_guard_daemon.log

cleanup() {
    [ -n "${DAEMON_PID:-}" ] && sudo kill "$DAEMON_PID" 2>/dev/null
    sudo rm -f "$PROBE" "$VICTIM" "$PIDFILE"
}
trap cleanup EXIT

echo "=== build bpf guard probe ==="
gcc -O0 -Wall -Wextra -o "$PROBE" "$HERE/bpf_guard_probe.c" || exit 1
gcc -O0 -Wall -Wextra -o "$VICTIM" "$ROOT/tests/ptrace_coverage/victim.c" || exit 1

[ -x "$DAEMON" ] || { echo "daemon not built: $DAEMON"; exit 1; }

echo "=== start daemon ==="
sudo pkill -f target/debug/anticheat 2>/dev/null
sudo rm -f "$PIDFILE" "$DLOG"
sudo "$DAEMON" "$VICTIM" "$PIDFILE" >"$DLOG" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 50); do [ -s "$PIDFILE" ] && break; sleep 0.1; done
[ -s "$PIDFILE" ] || { echo "victim did not start"; cat "$DLOG"; exit 1; }

for _ in $(seq 1 50); do
    PROG_ID="$(sed -nE 's/.*prog id=([0-9]+) protected.*/\1/p' "$DLOG" | head -n 1)"
    MAP_ID="$(sed -nE 's/.*map id=([0-9]+) protected.*/\1/p' "$DLOG" | head -n 1)"
    LINK_ID="$(sed -nE 's/.*link id=([0-9]+) protected.*/\1/p' "$DLOG" | head -n 1)"
    [ -n "$PROG_ID" ] && [ -n "$MAP_ID" ] && [ -n "$LINK_ID" ] && break
    sleep 0.1
done

if [ -z "${PROG_ID:-}" ] || [ -z "${MAP_ID:-}" ] || [ -z "${LINK_ID:-}" ]; then
    echo "failed to collect protected IDs"
    cat "$DLOG"
    exit 1
fi

echo "protected prog id=$PROG_ID map id=$MAP_ID link id=$LINK_ID"

echo "=== bpf guard probe ==="
sudo "$PROBE" "$PROG_ID" "$MAP_ID" "$LINK_ID"
