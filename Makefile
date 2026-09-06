.PHONY: all ebpf daemon vmlinux clean

all: ebpf daemon

KERNEL_RELEASE := $(shell uname -r)
VMLINUX_RS     := ebpf/src/vmlinux.rs
VMLINUX_STAMP  := ebpf/src/.vmlinux-kernel

# vmlinux.rs is generated from the running kernel's BTF and is valid ONLY for
# that kernel. rustc's BPF target cannot emit CO-RE relocations, so field
# offsets are baked in at compile time and nothing patches them at load time --
# the verifier only checks that an offset is a legal field boundary for the
# target's BTF, it does not correct it. A stale vmlinux.rs therefore reads the
# wrong fields: pointer reads are caught by the verifier, but scalar reads
# (tgid, start_time) load silently and the protection compares garbage.
#
# So this is not a "regenerate if you feel like it" step. Every build checks the
# stamp and regenerates when the running kernel differs.
vmlinux:
	@if [ ! -f $(VMLINUX_RS) ] || \
	    [ "$$(cat $(VMLINUX_STAMP) 2>/dev/null)" != "$(KERNEL_RELEASE)" ]; then \
		echo "vmlinux.rs: generating for kernel $(KERNEL_RELEASE)"; \
		aya-tool generate task_struct > $(VMLINUX_RS); \
		echo "$(KERNEL_RELEASE)" > $(VMLINUX_STAMP); \
	else \
		echo "vmlinux.rs: current for kernel $(KERNEL_RELEASE)"; \
	fi

# Build the eBPF program for bpfel-unknown-none (needs nightly + build-std)
ebpf: vmlinux
	cd ebpf && cargo build --release

# Build the userspace daemon (ebpf must be built first)
daemon: ebpf
	cargo build

clean:
	cd ebpf && cargo clean
	cargo clean
	rm -f $(VMLINUX_RS) $(VMLINUX_STAMP)
