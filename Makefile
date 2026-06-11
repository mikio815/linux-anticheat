.PHONY: all ebpf daemon vmlinux clean

all: ebpf daemon

# task_struct の Rust バインディングを生成 (BTF のある Linux = Lima 上で実行)
# カーネル更新でレイアウトが変わったら再生成する
vmlinux:
	aya-tool generate task_struct > ebpf/src/vmlinux.rs

# eBPF プログラムを bpfel-unknown-none 向けにビルド (nightly + build-std が必要)
ebpf:
	cd ebpf && cargo build --release

# userspace daemon をビルド (ebpf が先にビルドされている必要がある)
daemon: ebpf
	cargo build

clean:
	cd ebpf && cargo clean
	cargo clean
