#!/usr/bin/env bash
#
# Field test for the KM's eBPF integrity guard.
#
# The guard reports three things -- changed, moved, gone -- and only "gone" ever
# showed up on its own, because killing the daemon produces it for free. This
# drives the other two: it tampers with a live BPF program using jit_tamper and
# checks that the guard notices, and that it goes quiet again once the tamper is
# undone.
#
#   code   -> "JIT CODE CHANGED"  the JIT image was rewritten in place
#   func   -> "bpf_func moved"    the program was replaced wholesale
#   tramp  -> "CODE CHANGED"      the trampoline's call was pointed elsewhere
#   detach -> "UNHOOKED"          the shim's fentry site was reset to a nop
#
# The func phase also pins down something the field test turned up: repointing
# bpf_func does NOT neuter the hook. LSM programs are reached through a
# trampoline that calls the program at an address baked in when the trampoline
# was generated, so the field the guard watches is not the pointer the CPU
# follows. ptrace must still be blocked, and the run prints the call chain that
# explains why.
#
# Run this on the KM dev VM. It loads a module that deliberately corrupts kernel
# state.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
TAMPER="$HERE/jit_tamper.ko"
KM="$ROOT/kernel/anticheat.ko"
DAEMON="$ROOT/target/debug/anticheat"
VICTIM="$ROOT/tests/ptrace_coverage/victim"
ATTACKER="$ROOT/tests/ptrace_coverage/attacker"
PIDFILE=/tmp/ac_jit_tamper.pid
DLOG=/tmp/ac_jit_tamper_daemon.log
TARGET=ptrace_access_c

# The guard's interval is randomized around 5s, so it can be as wide as 6s.
# Anything shorter than this and a miss is indistinguishable from bad luck.
SETTLE=10

cleanup() {
    sudo rmmod jit_tamper 2>/dev/null
    sudo rmmod anticheat 2>/dev/null
    sudo pgrep -x anticheat | xargs -r sudo kill 2>/dev/null
    sudo rm -f "$PIDFILE"
}
trap cleanup EXIT

for f in "$KM" "$DAEMON" "$VICTIM" "$ATTACKER"; do
    [ -e "$f" ] || { echo "missing: $f"; exit 1; }
done

# Timestamp of the first dmesg line matching $1, as printk printed it. Both the
# tamper and the detection come from the kernel, so their difference is a real
# latency without any clock to reconcile.
ts() { sudo dmesg | grep -m1 -E "$1" | sed -E 's/^\[ *([0-9.]+)\].*/\1/'; }

gap() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", b - a }'; }

echo "=== build ==="
make -C "$HERE" >/dev/null || exit 1
make -C "$ROOT/kernel" >/dev/null || exit 1

cleanup
sleep 1

echo "=== start daemon + load KM ==="
sudo rm -f "$PIDFILE" "$DLOG"
sudo "$DAEMON" "$VICTIM" "$PIDFILE" >"$DLOG" 2>&1 &
for _ in $(seq 1 60); do [ -s "$PIDFILE" ] && break; sleep 0.2; done
[ -s "$PIDFILE" ] || { echo "victim did not start"; cat "$DLOG"; exit 1; }
PID="$(cat "$PIDFILE")"
echo "victim pid=$PID"

# Clean scans log at pr_debug. With every scan visible, a missing detection is
# distinguishable from a guard that stopped scanning at all.
sudo insmod "$KM" scan_interval_sec=5
echo 'module anticheat +p' | sudo tee /sys/kernel/debug/dynamic_debug/control >/dev/null
sleep 2

# The shim baseline decides what the detach phase can catch. A hook recorded as
# NOT ATTACHED here is one the guard will stay quiet about forever, so it is
# worth seeing before any tampering starts.
echo "--- LSM shim baseline ---"
sudo dmesg | grep -E 'anticheat: bpf_lsm_|already unattached|name list is stale'


phase() {
    local name="$1" detect="$2"; shift 2

    echo
    echo "=== $name ==="
    sudo dmesg -C
    sudo insmod "$TAMPER" target="$TARGET" "$@" || return 1
    sleep "$SETTLE"

    local t d
    t="$(ts 'jit_tamper: (patching|repointing|redirecting)')"
    d="$(ts "$detect")"
    if [ -z "$d" ]; then
        echo "FAIL: guard did not report '$detect'"
        sudo dmesg | grep -E 'jit_tamper|integrity scan'
        return 1
    fi
    echo "PASS: detected $(gap "$t" "$d")s after the tamper"
    sudo dmesg | grep -E 'jit_tamper: (patching|repointing|redirecting)|CHANGED|moved|is gone|integrity scan' | head -8
}

phase "code: rewrite the JIT image" 'JIT CODE CHANGED' mode=code
echo "--- the patched byte is inert, so the hook must still block ptrace ---"
sudo "$ATTACKER" tampered "$PID" 2>&1 | grep PTRACE_ATTACH
sudo rmmod jit_tamper
sleep "$SETTLE"
sudo dmesg | grep -qE 'CHANGED' && sudo dmesg -C
sleep "$SETTLE"
if sudo dmesg | grep -qE 'CHANGED|moved|is gone'; then
    echo "FAIL: guard still reporting after the patch was undone"
else
    echo "PASS: clean again after restore"
fi

phase "func: repoint bpf_func at a stub returning 0" 'bpf_func moved' mode=func
echo "--- the trampoline calls the program directly, so ptrace must STILL be blocked ---"
sudo "$ATTACKER" neutered "$PID" 2>&1 | grep PTRACE_ATTACH
sudo rmmod jit_tamper
sleep "$SETTLE"

# The attack that costs an attacker exactly what patching a JIT image costs, and
# that the program hashes alone could not see: the trampoline reaches the
# program through one call, and rewriting its rel32 points the hook at a stub
# that allows everything. Redirecting to a stub rather than to nothing is what
# makes this safe to run -- this trampoline fires constantly.
phase "tramp: redirect the trampoline's call at a stub" 'CODE CHANGED' mode=tramp
echo "--- the redirect is on the real path, so ptrace must now succeed ---"
sudo "$ATTACKER" redirected "$PID" 2>&1 | grep PTRACE_ATTACH
sudo rmmod jit_tamper
sleep "$SETTLE"

# The case the program-level checks cannot see. Everything they watch is
# untouched -- same program, same address, same bytes -- and the hook is gone
# anyway, because what was removed is the five-byte branch in vmlinux .text that
# reaches it. Catching this is what the shim window is for.
echo
echo "=== detach: nop the shim's fentry site ==="
sudo dmesg -C
sudo insmod "$TAMPER" target="$TARGET" mode=detach || exit 1
sleep 1
if sudo "$ATTACKER" detached "$PID" 2>&1 | grep -q ALLOWED; then
    echo "hook is GONE: ptrace now succeeds"
else
    echo "unexpected: ptrace is still blocked"
fi
sleep "$SETTLE"
T="$(ts 'jit_tamper: .*now reads')"
D="$(ts 'UNHOOKED')"
if [ -n "$D" ]; then
    echo "PASS: detected $(gap "$T" "$D")s after the hook was removed"
    sudo dmesg | grep -E 'UNHOOKED|integrity scan: ' | head -4
else
    echo "FAIL: the guard reported nothing while the hook was removed"
    sudo dmesg | grep -E 'integrity scan' | tail -3
fi
sudo rmmod jit_tamper
sleep 1
sudo "$ATTACKER" reattached "$PID" 2>&1 | grep PTRACE_ATTACH

echo
echo "=== done ==="
