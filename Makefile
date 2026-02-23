.PHONY: all ebpf daemon clean

all: ebpf daemon

# eBPF プログラムを bpfel-unknown-none 向けにビルド (nightly + build-std が必要)
ebpf:
	cd ebpf && cargo build --release

# userspace daemon をビルド (ebpf が先にビルドされている必要がある)
daemon: ebpf
	cargo build

clean:
	cd ebpf && cargo clean
	cargo clean
