.PHONY: all ebpf daemon vmlinux clean

all: ebpf daemon

# Generate Rust bindings for task_struct (run on a Linux host with BTF = Lima)
# Regenerate if a kernel update changes the layout
vmlinux:
	aya-tool generate task_struct > ebpf/src/vmlinux.rs

# Build the eBPF program for bpfel-unknown-none (needs nightly + build-std)
ebpf:
	cd ebpf && cargo build --release

# Build the userspace daemon (ebpf must be built first)
daemon: ebpf
	cargo build

clean:
	cd ebpf && cargo clean
	cargo clean
