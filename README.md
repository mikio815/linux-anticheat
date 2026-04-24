# anticheat

Linux向けのアンチチート
LSM BPFをベースにKMと適当なthin hypervisorを組み合わせる予定です

## 構成

```
ebpf/      eBPF プログラム (aya)
daemon/    ユーザースペース daemon (Rust)
common/    eBPF・daemon 共通型定義
```

## 動作概要

daemonがゲームバイナリをfork-execで起動し、自身と子プロセスを保護対象として登録する
daemonが終了するとゲームもSIGKILLで落ちる

## 要件

- Linux kernel 5.17+
- `CONFIG_DEBUG_INFO_BTF=y`
- `CONFIG_BPF_LSM=y`、`lsm=` カーネルパラメータに `bpf` を含むこと
- Rust nightly + `bpf-linker`

## ビルド

```bash
cargo install bpf-linker

make
```

## 実行

```bash
sudo ./target/debug/anticheat <game_binary> [args...]

# 例
sudo ./target/debug/anticheat /usr/bin/mygame
```

## 開発環境

aarch64 Linux VM
