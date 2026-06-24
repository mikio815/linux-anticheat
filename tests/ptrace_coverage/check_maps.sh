#!/usr/bin/env bash
# 保護対象ゲームの /proc/<pid>/maps を root が読めるか確認する。
# 我々の ptrace_access_check フックが maps 読み取りまで弾くと
# daemon 自身の maps スキャンが成立しなくなるため、その挙動を実測する。
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
echo "=== root が保護対象の /proc/$VICTIM/maps を読めるか ==="
if sudo head -n 3 "/proc/$VICTIM/maps" 2>/tmp/maps_err; then
    echo "RESULT: READABLE (maps スキャン可能)"
else
    echo "RESULT: BLOCKED ($(cat /tmp/maps_err)) → caller 免除が必要"
fi

echo
echo "=== 比較: 非保護プロセス (自分) の maps ==="
sudo head -n 1 /proc/self/maps >/dev/null 2>&1 && echo "self maps: READABLE"

sudo pkill -f target/debug/anticheat 2>/dev/null
sudo rm -f "$PIDFILE"
