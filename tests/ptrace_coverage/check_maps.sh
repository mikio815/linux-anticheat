#!/usr/bin/env bash
# Check whether root can read a protected game's /proc/<pid>/maps.
# If our ptrace_access_check hook also blocks maps reads, the daemon's own
# maps scan would break, so measure that behavior.
export PATH="$PATH:/usr/sbin"
HERE="$(cd "$(dirname "$0")" && pwd)"
DAEMON="$HERE/../../target/debug/anticheat"
PIDFILE=/tmp/ac_victim.pid
DLOG=/tmp/ac_daemon.log

sudo pkill -f target/debug/anticheat 2>/dev/null
sudo rm -f "$PIDFILE" "$DLOG"
sleep 0.5

sudo "$DAEMON" "$HERE/victim" "$PIDFILE" >"$DLOG" 2>&1 &
for _ in $(seq 1 50); do [ -s "$PIDFILE" ] && break; sleep 0.1; done
VICTIM="$(cat "$PIDFILE" 2>/dev/null)"
echo "protected victim pid=$VICTIM"

echo
echo "=== can root read the protected target's /proc/$VICTIM/maps ==="
if sudo head -n 3 "/proc/$VICTIM/maps" 2>/tmp/maps_err; then
    echo "RESULT: READABLE (maps scan possible)"
else
    echo "RESULT: BLOCKED ($(cat /tmp/maps_err)) -> caller exemption needed"
fi

echo
echo "=== compare: maps of an unprotected process (self) ==="
sudo head -n 1 /proc/self/maps >/dev/null 2>&1 && echo "self maps: READABLE"

sudo pkill -f target/debug/anticheat 2>/dev/null
sudo rm -f "$PIDFILE"
