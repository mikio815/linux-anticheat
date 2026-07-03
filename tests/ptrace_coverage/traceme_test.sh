#!/usr/bin/env bash
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DAEMON="$ROOT/target/debug/anticheat"
VICTIM=/tmp/ac_victim_traceme
PIDFILE=/tmp/ac_traceme.pid
RESULT=/tmp/ac_traceme.result
DLOG=/tmp/ac_traceme_daemon.log

cleanup() {
    [ -n "${DAEMON_PID:-}" ] && sudo kill "$DAEMON_PID" 2>/dev/null
    sudo rm -f "$VICTIM" "$PIDFILE" "$RESULT"
}
trap cleanup EXIT

echo "=== build PTRACE_TRACEME victim ==="
gcc -O0 -o "$VICTIM" "$HERE/victim_traceme.c" || exit 1

[ -x "$DAEMON" ] || { echo "daemon not built: $DAEMON"; exit 1; }

echo "=== start daemon (launches protected TRACEME victim) ==="
sudo pkill -f target/debug/anticheat 2>/dev/null
sudo rm -f "$PIDFILE" "$RESULT" "$DLOG"
sudo "$DAEMON" "$VICTIM" "$PIDFILE" "$RESULT" >"$DLOG" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 50); do [ -s "$RESULT" ] && break; sleep 0.1; done
[ -s "$RESULT" ] || { echo "victim did not write TRACEME result"; cat "$DLOG"; exit 1; }

echo "=== victim result ==="
cat "$RESULT"

echo "=== daemon ring buffer log ==="
for _ in $(seq 1 20); do
    grep -q "ptrace blocked" "$DLOG" && break
    sleep 0.1
done
grep -c "ptrace blocked" "$DLOG" | xargs echo "ptrace-blocked events:"
grep "ptrace blocked" "$DLOG" | head

if grep -q "TRACEME: BLOCKED" "$RESULT"; then
    echo "RESULT: COVERED"
    exit 0
fi

echo "RESULT: NOT_COVERED"
exit 1
