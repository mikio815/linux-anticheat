# anticheat

Linuxコンシューマー機向けのカーネルレベルアンチチートです。LSM BPFを検出のメインに据え薄いカーネルモジュールと薄いハイパーバイザーを重ねるハイブリッド構成になっています。

## なぜLinux向けか

WindowsにはEACやVanguardのようなカーネルレベルアンチチートがありますが、Linux向けはほぼ存在しません。ディストロやカーネルをユーザーが自由に選べるためブートチェーンを固定できず、カーネル構造体のオフセットも頻繁に変わるからです。

対象をSteam Deckのようなコンシューマー機に絞ると前提が変わります。ベンダーがハードウェアからカーネルまで構成を固定できるため、UEFI Secure Boot、Kernel Lockdown、自前ハイパーバイザー、TPM Remote Attestationがすべて成立します。ブートローダーからカーネルモジュールまで署名済みであることを保証できてはじめて、カーネルレベルの防御は意味を持ちます。

## アーキテクチャ

上から下へ4層で構成します。

- Userspace daemon: ゲームのfork-execランチャ、イベント受信、サーバー通信
- LSM BPF: 検出のメインロジック　ptrace遮断、W^X強制、bpf()監視など
- Thin Kernel Module: eBPFの検証　JITハッシュ検証、detach監視、DKOM検出、VDSO検証、VM検出
- Thin Hypervisor (BitVisor base): NPTでJITページをexecute-only化し、physmap書き込みを遮断

検出ロジックの大部分をeBPFに置いている理由として、eBPFはverifierがメモリ安全性を事前検証するため巨大なカーネルドライバとして実装される既存アンチチートよりattack surfaceが小さく、ゲーム中のクラッシュも起こしにくくなると考えています。

eBPFは自分自身のJITコードやMapの改ざんを検証できないため、カーネルモジュールが外部から整合性を監査します。さらにroot持ちはDirect Physical Map経由でJITコードを書き換えられるため、ハイパーバイザーがNPTでページテーブルより下の物理レベルから書き込みを遮断します。


## 要件

- Linux kernel 5.17+
- `CONFIG_DEBUG_INFO_BTF=y`
- `CONFIG_BPF_LSM=y`、`lsm=`カーネルパラメータに`bpf`を含むこと
- Rust nightly + `bpf-linker`

## ビルド・実行

```bash
cargo install bpf-linker
make

sudo ./target/debug/anticheat <game_binary> [args...]
```

## 開発環境

aarch64 Linux VM (Lima) 
