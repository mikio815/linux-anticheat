# anticheat

A kernel-level anti-cheat for Linux consoles (Steam Deck and the like). LSM BPF does the detection, with a thin kernel module and a thin hypervisor layered on top.

Targeting consoles, not general-purpose desktops, is what makes this viable: the vendor pins the whole boot chain, so Secure Boot, Kernel Lockdown, a self-hosted hypervisor, and TPM attestation all hold.

## Architecture

Four layers, top to bottom:

- Userspace daemon — fork-exec launcher for the game, event consumer, server communication
- LSM BPF — main detection: ptrace blocking, W^X enforcement, bpf() monitoring
- Thin kernel module — guards eBPF: JIT hash verification, detach monitoring, DKOM detection, VDSO verification, VM detection
- Thin hypervisor (BitVisor base) — makes JIT pages execute-only via NPT, blocking physmap writes

Detection lives in eBPF because the verifier proves memory safety up front, keeping the attack surface small. eBPF can't verify its own integrity, so the kernel module audits it from the outside; the hypervisor blocks the physmap write path that root retains below the page tables.

## Requirements

- Linux kernel 5.17+
- `CONFIG_DEBUG_INFO_BTF=y`
- `CONFIG_BPF_LSM=y`, with `bpf` in the `lsm=` kernel parameter
- Rust nightly + `bpf-linker`

## Build & run

```bash
cargo install bpf-linker
make
sudo ./target/debug/anticheat <game_binary> [args...]
```

Built and run inside an aarch64 Linux VM (Lima); `bpf-linker` doesn't run on macOS.
