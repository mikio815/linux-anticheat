use aya_bpf::{helpers::bpf_get_current_pid_tgid, macros::lsm, programs::LsmContext};
use anticheat_common::PtraceEvent;

use crate::EVENTS;

#[lsm(hook = "ptrace_access_check")]
pub fn ptrace_access_check(_ctx: LsmContext) -> i32 {
    let caller_pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if let Some(mut entry) = unsafe { EVENTS.reserve::<PtraceEvent>(0) } {
        unsafe {
            (*entry.as_mut_ptr()).caller_pid = caller_pid;
            (*entry.as_mut_ptr()).target_pid = 0; // Phase 2: task_struct から取得
        }
        entry.submit(0);
    }

    -1
}
