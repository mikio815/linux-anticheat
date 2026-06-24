#![no_std]
#![no_main]

use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, RingBuf};
use anticheat_common::ProcessKey;

// aya-tool generate task_struct > src/vmlinux.rs で生成 (make vmlinux)
#[allow(warnings)]
#[rustfmt::skip]
mod vmlinux;

mod lsm_bpf;
mod lsm_ptrace;
mod sched_exec;

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// 保護対象プロセス (tgid + start_time) → 1u8。eBPF が exec 観測時に登録する。
// PID 再利用しても start_time が異なるため誤保護が起きず、終了時の削除も不要。
#[map]
pub static PROTECTED_PROCS: HashMap<ProcessKey, u8> = HashMap::with_max_entries(256, 0);

// daemon 自身の coarse 保護 (tgid 単体)。daemon の lifetime 未確定のため簡易版。
#[map]
pub static PROTECTED_TGIDS: HashMap<u32, u8> = HashMap::with_max_entries(16, 0);

// 監視役 (daemon) の tgid。保護対象への正規アクセス (maps/mem スキャン) を許可するため、
// caller がここにあれば ptrace フックを素通りさせる。
#[map]
pub static MONITOR_TGIDS: HashMap<u32, u8> = HashMap::with_max_entries(4, 0);

// exec 登録トリガ + 伝播。親 tgid がここにあれば子を PROTECTED_PROCS に登録し、
// その子 tgid もここへ追加してサブプロセス木全体を追従する。
#[map]
pub static WATCH_TGIDS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

// 保護対象カーネル link ID → 1u8
#[map]
pub static PROTECTED_LINKS: HashMap<u32, u8> = HashMap::with_max_entries(16, 0);

// 保護対象カーネル prog ID → 1u8
#[map]
pub static PROTECTED_PROGS: HashMap<u32, u8> = HashMap::with_max_entries(16, 0);

// 保護対象カーネル map ID → 1u8
#[map]
pub static PROTECTED_MAPS: HashMap<u32, u8> = HashMap::with_max_entries(16, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
