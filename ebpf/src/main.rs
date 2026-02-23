#![no_std]
#![no_main]

use aya_bpf::macros::map;
use aya_bpf::maps::RingBuf;

mod lsm_ptrace;

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
