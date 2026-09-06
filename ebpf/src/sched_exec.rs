use aya_ebpf::{
    helpers::bpf_get_current_task_btf,
    macros::tracepoint,
    programs::TracePointContext,
};
use anticheat_common::{ProcessKey, ProtFlags, MAP_ID_PROTECTED_PROCS, MAP_ID_WATCH_TGIDS};

use crate::vmlinux::task_struct;
use crate::{report_map_full, PROTECTED_PROCS, WATCH_TGIDS};

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
    let leader = if (*task).group_leader.is_null() {
        task
    } else {
        (*task).group_leader
    };
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
        start_time: (*leader).start_time,
    };
    if PROTECTED_PROCS.insert(&key, &ProtFlags::present(), 0).is_err() {
        report_map_full(MAP_ID_PROTECTED_PROCS, tgid);
    }
    if WATCH_TGIDS.insert(&tgid, &ProtFlags::present(), 0).is_err() {
        report_map_full(MAP_ID_WATCH_TGIDS, tgid);
    }
}
