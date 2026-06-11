#![no_std]
#![no_main]

use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, RingBuf};

// aya-tool generate task_struct > src/vmlinux.rs で生成 (make vmlinux)
#[allow(warnings)]
#[rustfmt::skip]
mod vmlinux;

mod lsm_bpf;
mod lsm_ptrace;

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// 保護対象 tgid → 1u8
#[map]
pub static PROTECTED_PROCS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

// 保護対象カーネル link ID → 1u8
#[map]
pub static PROTECTED_LINKS: HashMap<u32, u8> = HashMap::with_max_entries(16, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
