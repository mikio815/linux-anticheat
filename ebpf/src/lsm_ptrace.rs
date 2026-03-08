use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{lsm, tracepoint},
    programs::{LsmContext, TracePointContext},
};
use anticheat_common::PtraceEvent;

use crate::{EVENTS, PROTECTED_PROCS, PTRACE_ATTEMPTS};

// sys_enter_ptrace トレースポイントで ptrace の target pid を syscall 引数から読む。
// task_struct を触らずに済むため CO-RE 不要。
// tracepoint format (syscalls/sys_enter_ptrace):
//   offset 16: request (8 bytes)
//   offset 24: pid     (8 bytes)  ← target pid
#[tracepoint]
pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
    unsafe { handle_enter_ptrace(ctx) }.unwrap_or(0)
}

unsafe fn handle_enter_ptrace(ctx: TracePointContext) -> Result<u32, i64> {
    let target_pid = ctx.read_at::<u64>(24)? as u32;
    let caller_tid = (bpf_get_current_pid_tgid() & 0xffff_ffff) as u32;
    PTRACE_ATTEMPTS.insert(&caller_tid, &target_pid, 0)?;
    Ok(0)
}

// ptrace_access_check LSM フック: PTRACE_ATTEMPTS から target pid を取り出して判定する
#[lsm(hook = "ptrace_access_check")]
pub fn ptrace_access_check(ctx: LsmContext) -> i32 {
    match unsafe { try_ptrace_access_check(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_ptrace_access_check(_ctx: LsmContext) -> Result<i32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let caller_pid = (pid_tgid >> 32) as u32;
    let caller_tid = (pid_tgid & 0xffff_ffff) as u32;

    let target_pid = match PTRACE_ATTEMPTS.get(&caller_tid) {
        Some(p) => *p,
        None => return Ok(0),
    };

    if PROTECTED_PROCS.get(&target_pid).is_none() {
        let _ = PTRACE_ATTEMPTS.remove(&caller_tid);
        return Ok(0);
    }

    let _ = PTRACE_ATTEMPTS.remove(&caller_tid);

    if let Some(mut entry) = EVENTS.reserve::<PtraceEvent>(0) {
        // Safety: reserve した領域に書き込む
        (*entry.as_mut_ptr()).caller_pid = caller_pid;
        (*entry.as_mut_ptr()).target_pid = target_pid;
        entry.submit(0);
    }

    Ok(-1) // -EPERM
}
