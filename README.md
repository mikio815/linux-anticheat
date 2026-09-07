# anticheat

Work in progress. A kernel-level anti-cheat for Linux consoles (Steam Deck and the like).

Targeting consoles, not general-purpose desktops, is what makes this viable: the vendor pins the whole boot chain, so Secure Boot, Kernel Lockdown, a self-hosted hypervisor, and TPM attestation all hold.

## Architecture

Four layers, top to bottom:

- Userspace daemon — fork-exec launcher for the game, event consumer, server communication
- LSM BPF — main detection: ptrace blocking, W^X enforcement, `bpf()` monitoring
- Thin kernel module — guards eBPF from outside it, since eBPF can't verify its own integrity
- Thin hypervisor (BitVisor base, Intel VMX/EPT) — write-protects static kernel regions (`.text`, JIT pages), blocking the physmap write path root retains below the page tables

## Requirements

- Linux kernel 5.17+, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF_LSM=y` (`bpf` in `lsm=`)
- Rust nightly + `bpf-linker`

## Build & run

```bash
cargo install bpf-linker
make
sudo ./target/debug/anticheat <game_binary> [args...]
```

The thin kernel module builds separately, out-of-tree, on x86_64:

```bash
cd kernel && make
sudo insmod anticheat.ko
```
