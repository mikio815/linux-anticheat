use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::lsm,
    programs::LsmContext,
};
use anticheat_common::PtraceEvent;

use crate::{EVENTS, PROTECTED_PROCS};

// task_struct::tgid のバイトオフセット。CO-RE 非対応のため固定値。
// 変更時は Lima 上で以下で再確認すること:
// bpftool btf dump file /sys/kernel/btf/vmlinux | grep -m1 -A600 '\[205\]' | grep tgid
// bits_offset を 8 で割った値 (例: bits_offset=12768 → 1596)
// ref: aya-rs/aya#349
const TGID_OFFSET: usize = 1596;

#[lsm(hook = "ptrace_access_check")]
pub fn ptrace_access_check(ctx: LsmContext) -> i32 {
    match unsafe { try_ptrace_access_check(ctx) } {
        Ok(ret) => ret,
        Err(_) => -1, // Fail-Closed: 読み取り失敗も拒否
    }
}

unsafe fn try_ptrace_access_check(ctx: LsmContext) -> Result<i32, i64> {
    // Safety: child は LSM フックが保証する有効なカーネルポインタ
    let child: *const u8 = ctx.arg(0);
    let target_tgid =
        bpf_probe_read_kernel(child.add(TGID_OFFSET) as *const u32)?;

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
