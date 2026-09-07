use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task_btf},
    macros::lsm,
    programs::LsmContext,
};
use anticheat_common::{EventHeader, PtraceEvent, EVENT_PTRACE_BLOCKED};

use crate::vmlinux::task_struct;
use crate::{now_ns, task_is_protected, EVENTS, MONITOR_TGIDS};

#[lsm(hook = "ptrace_access_check")]
pub fn ptrace_access_check(ctx: LsmContext) -> i32 {
    match unsafe { try_ptrace_access_check(ctx) } {
        Ok(ret) => ret,
        Err(_) => -1, // Fail-Closed
    }
}

#[lsm(hook = "ptrace_traceme")]
pub fn ptrace_traceme(ctx: LsmContext) -> i32 {
    match unsafe { try_ptrace_traceme(ctx) } {
        Ok(ret) => ret,
        Err(_) => -1, // Fail-Closed
    }
}

unsafe fn try_ptrace_access_check(ctx: LsmContext) -> Result<i32, i64> {
    // Read as i64: an i32 read makes aya emit a zero-extending truncation,
    // which turns a negative errno into a large positive value and loses the
    // [-4095, 0] range the verifier tracks for this argument. Kernel 7.1
    // rejects the resulting return value; older verifiers let it through.
    let retval: i64 = ctx.arg(2);
    if retval != 0 {
        return Ok(-1); // something already denied; keep it denied
    }

    // Safety: child is a valid task_struct passed by the LSM hook (PTR_TO_BTF_ID).
    // The verifier rewrites field reads into probe reads.
    let child: *const task_struct = ctx.arg(0);
    if !task_is_protected(child) {
        return Ok(0);
    }
    let target_tgid = (*child).tgid as u32;

    let caller_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Allow the monitor (daemon) its legitimate access to targets (maps/mem scans)
    if MONITOR_TGIDS.get(&caller_tgid).is_some() {
        return Ok(0);
    }

    if let Some(mut entry) = EVENTS.reserve::<PtraceEvent>(0) {
        // Writing the whole struct initializes the padding too, so no
        // uninitialized kernel memory reaches userspace
        entry.write(PtraceEvent {
            header: EventHeader::new(EVENT_PTRACE_BLOCKED, now_ns()),
            caller_pid: caller_tgid,
            target_pid: target_tgid,
        });
        entry.submit(0);
    }

    Ok(-1) // -EPERM
}

unsafe fn try_ptrace_traceme(ctx: LsmContext) -> Result<i32, i64> {
    // Read as i64: an i32 read makes aya emit a zero-extending truncation,
    // which turns a negative errno into a large positive value and loses the
    // [-4095, 0] range the verifier tracks for this argument. Kernel 7.1
    // rejects the resulting return value; older verifiers let it through.
    let retval: i64 = ctx.arg(1);
    if retval != 0 {
        return Ok(-1); // something already denied; keep it denied
    }

    // Safety: bpf_get_current_task_btf() returns PTR_TO_BTF_ID, so the verifier
    // rewrites field reads into probe reads.
    let task = bpf_get_current_task_btf() as *const task_struct;
    if task.is_null() {
        return Ok(0);
    }

    if !task_is_protected(task) {
        return Ok(0);
    }
    let target_tgid = (*task).tgid as u32;

    let parent: *const task_struct = ctx.arg(0);
    let caller_tgid = if parent.is_null() {
        0
    } else {
        (*parent).tgid as u32
    };

    if let Some(mut entry) = EVENTS.reserve::<PtraceEvent>(0) {
        // Writing the whole struct initializes the padding too, so no
        // uninitialized kernel memory reaches userspace
        entry.write(PtraceEvent {
            header: EventHeader::new(EVENT_PTRACE_BLOCKED, now_ns()),
            caller_pid: caller_tgid,
            target_pid: target_tgid,
        });
        entry.submit(0);
    }

    Ok(-1) // -EPERM
}
