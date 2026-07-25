#!/usr/bin/env bash
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DAEMON="$ROOT/target/debug/anticheat"
PROBE=/tmp/ac_wx_probe
CTRL_PIDFILE=/tmp/ac_wx_control.pid
CTRL_RESULT=/tmp/ac_wx_control.result
PROT_PIDFILE=/tmp/ac_wx_protected.pid
PROT_RESULT=/tmp/ac_wx_protected.result
DLOG=/tmp/ac_wx_daemon.log

cleanup() {
    [ -n "${DAEMON_PID:-}" ] && sudo kill "$DAEMON_PID" 2>/dev/null
    sudo rm -f "$PROBE" "$CTRL_PIDFILE" "$CTRL_RESULT" "$PROT_PIDFILE" "$PROT_RESULT"
}
trap cleanup EXIT

echo "=== build W^X probe ==="
gcc -O0 -Wall -Wextra -o "$PROBE" "$HERE/wx_probe.c" || exit 1

[ -x "$DAEMON" ] || { echo "daemon not built: $DAEMON"; exit 1; }

echo "=== unprotected control (expect RWX allowed, RX allowed) ==="
sudo rm -f "$CTRL_PIDFILE" "$CTRL_RESULT"
sudo "$PROBE" control "$CTRL_PIDFILE" "$CTRL_RESULT"
cat "$CTRL_RESULT"

echo "=== protected target (expect RWX blocked, RX allowed) ==="
sudo pkill -f target/debug/anticheat 2>/dev/null
sudo rm -f "$PROT_PIDFILE" "$PROT_RESULT" "$DLOG"
sudo "$DAEMON" "$PROBE" protected "$PROT_PIDFILE" "$PROT_RESULT" >"$DLOG" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 50); do [ -s "$PROT_RESULT" ] && break; sleep 0.1; done
[ -s "$PROT_RESULT" ] || { echo "protected probe did not finish"; cat "$DLOG"; exit 1; }

grep -E "PASS|FAIL" "$DLOG" || true
cat "$PROT_RESULT"
grep -q "RESULT: PASS" "$CTRL_RESULT" || exit 1
grep -q "RESULT: PASS" "$PROT_RESULT" || { cat "$DLOG"; exit 1; }
