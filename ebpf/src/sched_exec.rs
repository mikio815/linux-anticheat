use aya_ebpf::{
    helpers::bpf_get_current_task_btf,
    macros::tracepoint,
    programs::TracePointContext,
};
use anticheat_common::ProcessKey;

use crate::vmlinux::task_struct;
use crate::{PROTECTED_PROCS, WATCH_TGIDS};

// On exec, if the parent is watched, register self as protected and propagate watch to self.
// This tracks the game's whole fork-exec descendant process tree.
#[tracepoint]
pub fn sched_process_exec(_ctx: TracePointContext) -> u32 {
    unsafe { try_exec() };
    0
}

unsafe fn try_exec() {
    // Safety: bpf_get_current_task_btf() returns PTR_TO_BTF_ID, so the verifier
    // rewrites field reads into probe reads (same as LSM arguments).
    let task = bpf_get_current_task_btf() as *const task_struct;
    if task.is_null() {
        return;
    }

    let tgid = (*task).tgid as u32;
    let parent = (*task).real_parent;
    if parent.is_null() {
        return;
    }
    let parent_tgid = (*parent).tgid as u32;

    if WATCH_TGIDS.get(&parent_tgid).is_none() && WATCH_TGIDS.get(&tgid).is_none() {
        return;
    }

    let key = ProcessKey {
        pid: tgid,
        _pad: 0,
        start_time: (*task).start_time,
    };
    let _ = PROTECTED_PROCS.insert(&key, &1u8, 0);
    let _ = WATCH_TGIDS.insert(&tgid, &1u8, 0);
}
