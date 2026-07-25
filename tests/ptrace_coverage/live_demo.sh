#!/usr/bin/env bash
# Live showcase: the daemon runs attached to THIS terminal (AC_DEMO_FX=1),
# so every blocked attack prints a big banner the moment the kernel denies it.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DAEMON="$ROOT/target/debug/anticheat"
PIDFILE=/tmp/ac_live_victim.pid

cleanup() {
    [ -n "${DAEMON_PID:-}" ] && sudo kill "$DAEMON_PID" 2>/dev/null
    [ -n "${CTRL_PID:-}" ] && sudo kill "$CTRL_PID" 2>/dev/null
    sudo rm -f "$PIDFILE"
    # Show the cursor again if we hid it
    printf '\033[?25h'
}
trap cleanup EXIT

echo "=== build test binaries ==="
gcc -O0 -o "$HERE/victim" "$HERE/victim.c" || exit 1
gcc -O0 -o "$HERE/attacker" "$HERE/attacker.c" || exit 1

[ -x "$DAEMON" ] || { echo "daemon not built: $DAEMON"; exit 1; }

sudo pkill -f target/debug/anticheat 2>/dev/null
sudo rm -f "$PIDFILE"
sleep 0.5

echo "=== starting anti-cheat daemon (live) ==="
# stdout/stderr stay on this terminal: banners appear in real time
sudo AC_DEMO_FX=1 "$DAEMON" "$HERE/victim" "$PIDFILE" &
DAEMON_PID=$!

for _ in $(seq 1 50); do [ -s "$PIDFILE" ] && break; sleep 0.1; done
VICTIM_PID="$(cat "$PIDFILE" 2>/dev/null)"
[ -n "$VICTIM_PID" ] || { echo "victim did not start"; exit 1; }

sudo sleep 600 &
CTRL_PID=$!

sleep 1
echo
printf '\033[1m>>> attacking the PROTECTED game (pid=%s) <<<\033[0m\n' "$VICTIM_PID"
sleep 2
sudo "$HERE/attacker" PROTECTED "$VICTIM_PID"

sleep 2
echo
printf '\033[1m>>> same attacks against an UNPROTECTED process (pid=%s) <<<\033[0m\n' "$CTRL_PID"
sleep 2
sudo "$HERE/attacker" CONTROL "$CTRL_PID"

sleep 1
