use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::lsm,
    programs::LsmContext,
};

use crate::{PROTECTED_LINKS, PROTECTED_MAPS, PROTECTED_PROGS};

const BPF_PROG_GET_FD_BY_ID: i32 = 13;
const BPF_MAP_GET_FD_BY_ID: i32 = 14;
const BPF_LINK_GET_FD_BY_ID: i32 = 30;

// LSM hook for the bpf() syscall.
// We guard the path to obtaining an FD, not detach itself.
// If an attacker cannot get an FD for our prog/map/link from its ID,
// detach / link_update / map tampering are all blocked for lack of an FD.
// The daemon keeps the FDs it grabbed at startup, so it is unaffected.
#[lsm(hook = "bpf")]
pub fn bpf_hook(ctx: LsmContext) -> i32 {
    match unsafe { try_bpf(ctx) } {
        Ok(ret) => ret,
        // fail-open: bpf() is a syscall the daemon itself uses heavily.
        // Blocking every bpf() on a probe-read failure would kill the daemon,
        // so let it through when undecidable. We only guard FD acquisition for specific IDs.
        Err(_) => 0,
    }
}

unsafe fn try_bpf(ctx: LsmContext) -> Result<i32, i64> {
    let cmd: i32 = ctx.arg(0);

    // Only GET_FD_BY_ID commands. The first u32 of attr is prog_id / map_id / link_id.
    let target = match cmd {
        BPF_PROG_GET_FD_BY_ID => &PROTECTED_PROGS,
        BPF_MAP_GET_FD_BY_ID => &PROTECTED_MAPS,
        BPF_LINK_GET_FD_BY_ID => &PROTECTED_LINKS,
        _ => return Ok(0),
    };

    // attr is a pointer already copied into the kernel
    let attr: *const u32 = ctx.arg(1);
    let id = bpf_probe_read_kernel(attr)?;

    if target.get(&id).is_some() {
        return Ok(-1); // EPERM
    }

    Ok(0)
}
