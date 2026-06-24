#!/usr/bin/env bash
# Demonstrate on Lima that a single ptrace_access_check hook blocks all three vectors:
# ptrace / process_vm_writev / /proc/pid/mem.
# Compares a protected target (victim launched by the daemon) against an unprotected control sleeper.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DAEMON="$ROOT/target/debug/anticheat"
PIDFILE=/tmp/ac_victim.pid
DLOG=/tmp/ac_daemon.log

cleanup() {
    [ -n "${DAEMON_PID:-}" ] && sudo kill "$DAEMON_PID" 2>/dev/null
    [ -n "${CTRL_PID:-}" ] && sudo kill "$CTRL_PID" 2>/dev/null
    sudo rm -f "$PIDFILE"
}
trap cleanup EXIT

echo "=== build test binaries ==="
gcc -O0 -o "$HERE/victim" "$HERE/victim.c" || exit 1
gcc -O0 -o "$HERE/attacker" "$HERE/attacker.c" || exit 1

[ -x "$DAEMON" ] || { echo "daemon not built: $DAEMON"; exit 1; }

echo "=== start daemon (launches protected victim) ==="
# The pidfile is root-owned, so remove it with sudo. Also clean up any leftover daemon
sudo pkill -f target/debug/anticheat 2>/dev/null
sudo rm -f "$PIDFILE"
sudo "$DAEMON" "$HERE/victim" "$PIDFILE" >"$DLOG" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 50); do [ -s "$PIDFILE" ] && break; sleep 0.1; done
VICTIM_PID="$(cat "$PIDFILE" 2>/dev/null)"
[ -n "$VICTIM_PID" ] || { echo "victim did not start"; cat "$DLOG"; exit 1; }
echo "protected victim pid=$VICTIM_PID"

echo "=== start UNPROTECTED control sleeper ==="
sudo sleep 600 &
CTRL_PID=$!
echo "control pid=$CTRL_PID"

echo
echo "########## ATTACK protected victim (expect BLOCKED x3) ##########"
sudo "$HERE/attacker" PROTECTED "$VICTIM_PID"
echo
echo "########## ATTACK control sleeper (expect ALLOWED x3) ##########"
sudo "$HERE/attacker" CONTROL "$CTRL_PID"

echo
echo "=== daemon ring buffer log (expect 'ptrace blocked' for victim) ==="
grep -c "ptrace blocked" "$DLOG" | xargs echo "ptrace-blocked events:"
grep "ptrace blocked" "$DLOG" | head
