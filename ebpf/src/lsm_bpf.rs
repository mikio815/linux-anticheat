use aya_ebpf::{
    bindings::{bpf_cmd, bpf_prog_type},
    helpers::bpf_probe_read_kernel,
    macros::lsm,
    programs::LsmContext,
};

use crate::{PROTECTED_LINKS, PROTECTED_MAPS, PROTECTED_PROGS};

// LSM hook for the bpf() syscall.
// We guard protected-object FD acquisition and deny later BPF LSM loads.
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
    let cmd: u32 = ctx.arg(0);
    // Read as i64: an i32 read makes aya emit a zero-extending truncation,
    // which turns a negative errno into a large positive value and loses the
    // [-4095, 0] range the verifier tracks for this argument. Kernel 7.1
    // rejects the resulting return value; older verifiers let it through.
    let retval: i64 = ctx.arg(3);
    if retval != 0 {
        return Ok(-1); // something already denied; keep it denied
    }

    // attr is a pointer already copied into the kernel
    let attr: *const u32 = ctx.arg(1);

    // Prevent a later BPF LSM program from overriding this hook's denial.
    if cmd == bpf_cmd::BPF_PROG_LOAD {
        let prog_type = bpf_probe_read_kernel(attr)?;
        if prog_type == bpf_prog_type::BPF_PROG_TYPE_LSM {
            return Ok(-1); // EPERM
        }
        return Ok(0);
    }

    // Only GET_FD_BY_ID commands. The first u32 of attr is prog_id / map_id / link_id.
    let target = match cmd {
        bpf_cmd::BPF_PROG_GET_FD_BY_ID => &PROTECTED_PROGS,
        bpf_cmd::BPF_MAP_GET_FD_BY_ID => &PROTECTED_MAPS,
        bpf_cmd::BPF_LINK_GET_FD_BY_ID => &PROTECTED_LINKS,
        _ => return Ok(0),
    };

    let id = bpf_probe_read_kernel(attr)?;

    if target.get(&id).is_some() {
        return Ok(-1); // EPERM
    }

    Ok(0)
}
