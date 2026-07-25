#!/usr/bin/env bash
# Manual playground: start the daemon with FX, then run real attack commands by hand.
# Usage: sudo bash tests/ptrace_coverage/manual_try.sh   (or run without sudo; it re-execs)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
DAEMON="$ROOT/target/debug/anticheat"
PIDFILE=/tmp/ac_manual.pid
DLOG=/tmp/ac_manual.log

sudo pkill -f target/debug/anticheat 2>/dev/null
sudo rm -f "$PIDFILE" "$DLOG"
sleep 0.5

gcc -O0 -o "$HERE/victim" "$HERE/victim.c"

sudo AC_DEMO_FX=1 "$DAEMON" "$HERE/victim" "$PIDFILE" >"$DLOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 50); do [ -s "$PIDFILE" ] && break; sleep 0.1; done
GPID="$(cat "$PIDFILE")"
echo "protected game pid=$GPID"
sleep 1

echo
echo "########## sudo strace -p $GPID ##########"
sudo strace -p "$GPID" 2>&1 | head -2

echo
echo "########## sudo head /proc/$GPID/maps ##########"
sudo head -n 1 "/proc/$GPID/maps" 2>&1

echo
echo "########## sudo $HERE/attacker MANUAL $GPID ##########"
gcc -O0 -o "$HERE/attacker" "$HERE/attacker.c"
sudo "$HERE/attacker" MANUAL "$GPID"

echo
echo "########## daemon log (BLOCKED banners are in $DLOG) ##########"
grep -c "ptrace blocked" "$DLOG" | xargs echo "blocked events:"

sudo kill "$DAEMON_PID" 2>/dev/null
sudo rm -f "$PIDFILE"
