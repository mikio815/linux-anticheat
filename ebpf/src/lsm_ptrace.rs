use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::lsm,
    programs::LsmContext,
};
use anticheat_common::{ProcessKey, PtraceEvent};

use crate::vmlinux::task_struct;
use crate::{EVENTS, MONITOR_TGIDS, PROTECTED_PROCS, PROTECTED_TGIDS};

#[lsm(hook = "ptrace_access_check")]
pub fn ptrace_access_check(ctx: LsmContext) -> i32 {
    match unsafe { try_ptrace_access_check(ctx) } {
        Ok(ret) => ret,
        Err(_) => -1, // Fail-Closed
    }
}

unsafe fn try_ptrace_access_check(ctx: LsmContext) -> Result<i32, i64> {
    let retval: i32 = ctx.arg(2);
    if retval != 0 {
        return Ok(retval);
    }

    // Safety: child is a valid task_struct passed by the LSM hook (PTR_TO_BTF_ID).
    // The verifier rewrites field reads into probe reads.
    let child: *const task_struct = ctx.arg(0);
    let target_tgid = (*child).tgid as u32;
    let leader = if (*child).group_leader.is_null() {
        child
    } else {
        (*child).group_leader
    };

    let key = ProcessKey {
        pid: target_tgid,
        _pad: 0,
        start_time: (*leader).start_time,
    };

    // PROTECTED_PROCS keys on (tgid+start_time), robust against PID reuse.
    // PROTECTED_TGIDS is the daemon's own coarse protection (tgid only).
    if PROTECTED_PROCS.get(&key).is_none() && PROTECTED_TGIDS.get(&target_tgid).is_none() {
        return Ok(0);
    }

    let caller_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Allow the monitor (daemon) its legitimate access to targets (maps/mem scans)
    if MONITOR_TGIDS.get(&caller_tgid).is_some() {
        return Ok(0);
    }

    if let Some(mut entry) = EVENTS.reserve::<PtraceEvent>(0) {
        // Safety: writing into the reserved region
        (*entry.as_mut_ptr()).caller_pid = caller_tgid;
        (*entry.as_mut_ptr()).target_pid = target_tgid;
        entry.submit(0);
    }

    Ok(-1) // -EPERM
}
