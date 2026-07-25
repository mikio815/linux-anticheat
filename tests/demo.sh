#!/usr/bin/env bash
# Master demo: runs all anti-cheat scenarios in sequence.
# Run inside Lima as the normal user (each scenario uses sudo internally):
#   bash tests/demo.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

if [ ! -x "$ROOT/target/debug/anticheat" ]; then
    echo "daemon not built. run: cargo build --release --manifest-path ebpf/Cargo.toml && cargo build"
    exit 1
fi

pause() {
    echo
    if [ -t 0 ]; then
        printf '\033[1m>>> press Enter for the next scenario <<<\033[0m'
        read -r
    else
        sleep 2
    fi
}

banner() {
    echo
    echo "================================================================"
    echo "  $1"
    echo "================================================================"
    echo
}

[ -t 1 ] && clear || true
printf '\033[1;32m'
cat <<'EOF'
██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗     █████╗ ███╗   ██╗████████╗██╗       ██████╗██╗  ██╗███████╗ █████╗ ████████╗
██║     ██║████╗  ██║██║   ██║╚██╗██╔╝    ██╔══██╗████╗  ██║╚══██╔══╝██║      ██╔════╝██║  ██║██╔════╝██╔══██╗╚══██╔══╝
██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝     ███████║██╔██╗ ██║   ██║   ██║█████╗██║     ███████║█████╗  ███████║   ██║
██║     ██║██║╚██╗██║██║   ██║ ██╔██╗     ██╔══██║██║╚██╗██║   ██║   ██║╚════╝██║     ██╔══██║██╔══╝  ██╔══██║   ██║
███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗    ██║  ██║██║ ╚████║   ██║   ██║      ╚██████╗██║  ██║███████╗██║  ██║   ██║
╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝       ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝
EOF
printf '\033[0m\n'
printf '\033[1m  kernel-level anti-cheat: LSM BPF live demo\033[0m\n'

banner "ENVIRONMENT"
uname -a
printf 'active LSMs: '
cat /sys/kernel/security/lsm
pause

banner "SCENARIO 1/5: block cheat memory access"
echo "game process (protected) vs sleeper (unprotected):"
echo "ptrace / /proc/pid/mem / process_vm_readv / process_vm_writev"
bash "$HERE/ptrace_coverage/live_demo.sh"
pause

banner "SCENARIO 2/5: block PTRACE_TRACEME anti-debug"
bash "$HERE/ptrace_coverage/traceme_test.sh"
pause

banner "SCENARIO 3/5: W^X enforcement (deny mprotect WRITE+EXEC)"
bash "$HERE/memory_protection/run.sh"
pause

banner "SCENARIO 4/5: self-defense of the eBPF programs (bpf() guard)"
bash "$HERE/bpf_guard/run.sh"
pause

banner "SCENARIO 5/5: injection detection (maps scanner)"
bash "$HERE/ptrace_coverage/inject_test.sh"

banner "DEMO FINISHED"
