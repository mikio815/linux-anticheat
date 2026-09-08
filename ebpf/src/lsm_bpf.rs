use aya_ebpf::{
    bindings::{bpf_cmd, bpf_prog_type},
    macros::lsm,
    programs::LsmContext,
};

use crate::vmlinux::bpf_attr;
use crate::{GUARDED_ATTACH_IDS, PROTECTED_LINKS, PROTECTED_MAPS, PROTECTED_PROGS};

// LSM hook for the bpf() syscall.
// We guard protected-object FD acquisition and deny later BPF LSM loads.
// If an attacker cannot get an FD for our prog/map/link from its ID,
// detach / link_update / map tampering are all blocked for lack of an FD.
// The daemon keeps the FDs it grabbed at startup, so it is unaffected.
#[lsm(hook = "bpf")]
pub fn bpf_hook(ctx: LsmContext) -> i32 {
    match unsafe { try_bpf(ctx) } {
        Ok(ret) => ret,
        // fail-open: bpf() is a syscall the daemon itself uses heavily, so an
        // undecidable case must not turn into a denial that kills it. Only FD
        // acquisition for specific IDs and LSM loads aimed at our hooks are guarded.
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

    // attr is already a kernel copy, and the verifier types this argument as
    // PTR_TO_BTF_ID for union bpf_attr, so the fields below are plain loads.
    // bpf_probe_read_kernel() would read the same bytes, but its helper proto is
    // withdrawn under lockdown=confidentiality (LOCKDOWN_BPF_READ_KERNEL) and the
    // program then fails to load at all rather than degrading.
    let attr: *const bpf_attr = ctx.arg(1);

    if cmd == bpf_cmd::BPF_PROG_LOAD {
        let load = &(*attr).__bindgen_anon_3;
        if load.prog_type != bpf_prog_type::BPF_PROG_TYPE_LSM {
            return Ok(0);
        }
        // Deny only LSM programs aimed at the hooks this anti-cheat owns. A
        // blanket deny is both wider and narrower than it looks: it breaks
        // unrelated BPF LSM users (see GUARDED_ATTACH_IDS), and it never bought
        // what its old comment claimed -- a second program on the same hook
        // cannot turn a denial into an allow, because the trampoline stops at the
        // first non-zero return and the verifier confines LSM returns to
        // [-4095, 0]. This stays as a guard against attach paths not yet
        // enumerated, not as the thing that makes the denial stick.
        // Copied to the stack first: passing &load.attach_btf_id hands the
        // helper a pointer into a PTR_TO_BTF_ID object, and the verifier rejects
        // that because a map lookup is allowed to write through its key pointer.
        let attach_id = load.attach_btf_id;
        if GUARDED_ATTACH_IDS.get(&attach_id).is_some() {
            return Ok(-1); // EPERM
        }
        return Ok(0);
    }

    // Only GET_FD_BY_ID commands. prog_id / map_id / link_id share one union.
    let target = match cmd {
        bpf_cmd::BPF_PROG_GET_FD_BY_ID => &PROTECTED_PROGS,
        bpf_cmd::BPF_MAP_GET_FD_BY_ID => &PROTECTED_MAPS,
        bpf_cmd::BPF_LINK_GET_FD_BY_ID => &PROTECTED_LINKS,
        _ => return Ok(0),
    };

    let id = (*attr).__bindgen_anon_6.__bindgen_anon_1.prog_id;

    if target.get(&id).is_some() {
        return Ok(-1); // EPERM
    }

    Ok(0)
}
