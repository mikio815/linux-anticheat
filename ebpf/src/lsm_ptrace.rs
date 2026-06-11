use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::lsm,
    programs::LsmContext,
};
use anticheat_common::PtraceEvent;

use crate::vmlinux::task_struct;
use crate::{EVENTS, PROTECTED_PROCS};

#[lsm(hook = "ptrace_access_check")]
pub fn ptrace_access_check(ctx: LsmContext) -> i32 {
    match unsafe { try_ptrace_access_check(ctx) } {
        Ok(ret) => ret,
        Err(_) => -1, // Fail-Closed
    }
}

unsafe fn try_ptrace_access_check(ctx: LsmContext) -> Result<i32, i64> {
    // Safety: child は LSM フックが渡す有効な task_struct (PTR_TO_BTF_ID)。
    // フィールド read は verifier が probe read に変換する
    let child: *const task_struct = ctx.arg(0);
    let target_tgid = (*child).tgid as u32;

    if PROTECTED_PROCS.get(&target_tgid).is_none() {
        return Ok(0);
    }

    let caller_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if let Some(mut entry) = EVENTS.reserve::<PtraceEvent>(0) {
        // Safety: reserve した領域に書き込む
        (*entry.as_mut_ptr()).caller_pid = caller_tgid;
        (*entry.as_mut_ptr()).target_pid = target_tgid;
        entry.submit(0);
    }

    Ok(-1) // -EPERM
}
