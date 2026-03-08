#![no_std]
#![no_main]

use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, RingBuf};

mod lsm_ptrace;

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// 保護対象 pid → 1u8
#[map]
pub static PROTECTED_PROCS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

// caller TID → target pid (tracepoint と LSM フックの橋渡し)
#[map]
pub static PTRACE_ATTEMPTS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
