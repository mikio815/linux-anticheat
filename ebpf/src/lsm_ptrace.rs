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
    // Safety: child は LSM フックが渡す有効な task_struct (PTR_TO_BTF_ID)。
    // フィールド read は verifier が probe read に変換する
    let child: *const task_struct = ctx.arg(0);
    let target_tgid = (*child).tgid as u32;

    let key = ProcessKey {
        pid: target_tgid,
        _pad: 0,
        start_time: (*child).start_time,
    };

    // PROTECTED_PROCS は (tgid+start_time) で PID 再利用に強い。
    // PROTECTED_TGIDS は daemon 自身の coarse 保護 (tgid 単体)。
    if PROTECTED_PROCS.get(&key).is_none() && PROTECTED_TGIDS.get(&target_tgid).is_none() {
        return Ok(0);
    }

    let caller_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // 監視役 (daemon) は保護対象への正規アクセス (maps/mem スキャン) を許可
    if MONITOR_TGIDS.get(&caller_tgid).is_some() {
        return Ok(0);
    }

    if let Some(mut entry) = EVENTS.reserve::<PtraceEvent>(0) {
        // Safety: reserve した領域に書き込む
        (*entry.as_mut_ptr()).caller_pid = caller_tgid;
        (*entry.as_mut_ptr()).target_pid = target_tgid;
        entry.submit(0);
    }

    Ok(-1) // -EPERM
}
