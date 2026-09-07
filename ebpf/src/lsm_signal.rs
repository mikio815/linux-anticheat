use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::lsm,
    programs::LsmContext,
};
use anticheat_common::{EventHeader, SignalEvent, EVENT_SIGNAL_TO_PROTECTED};

use crate::vmlinux::task_struct;
use crate::{now_ns, task_is_protected, EVENTS, MONITOR_TGIDS};

// Signals that end or freeze a process. Killing the daemon unloads every eBPF
// program with it -- the FD closes, the refcount drops, and the kernel tears the
// programs down through the ordinary path. That never goes near the bpf()
// syscall, so the bpf hook cannot see it. Stop signals matter too: a frozen
// daemon stops consuming the ring buffer.
const SIGINT: i64 = 2;
const SIGQUIT: i64 = 3;
const SIGABRT: i64 = 6;
const SIGKILL: i64 = 9;
const SIGTERM: i64 = 15;
const SIGSTOP: i64 = 19;
const SIGTSTP: i64 = 20;

// security_task_kill(p, info, sig, cred) -- arg(4) is the accumulated return value.
//
// Report only: this records who aimed a lethal signal at a protected process and
// does not block it. Blocking needs a policy decision (systemd must still be able
// to stop the service, the test harness signals the daemon, and a root attacker
// has other ways in), so the ambiguous case is reported rather than denied.
#[lsm(hook = "task_kill")]
pub fn task_kill(ctx: LsmContext) -> i32 {
    match unsafe { try_task_kill(ctx) } {
        Ok(ret) => ret,
        // Fail-open: this hook fires on every signal in the system and only
        // reports, so a failure here must not start denying signals.
        Err(_) => 0,
    }
}

unsafe fn try_task_kill(ctx: LsmContext) -> Result<i32, i64> {
    let retval: i64 = ctx.arg(4);
    if retval != 0 {
        return Ok(-1); // something already denied; keep it denied
    }

    // Cheapest check first: this hook fires on every signal delivery, and most
    // signals are not the ones worth a ring buffer record.
    let sig: i64 = ctx.arg(2);
    match sig {
        SIGINT | SIGQUIT | SIGABRT | SIGKILL | SIGTERM | SIGSTOP | SIGTSTP => {}
        _ => return Ok(0),
    }

    let target: *const task_struct = ctx.arg(0);
    if !task_is_protected(target) {
        return Ok(0);
    }

    let target_tgid = (*target).tgid as u32;
    let caller_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // The daemon signals the game on its own exit, and a protected process
    // signalling itself or a sibling is normal. Neither is worth reporting.
    if caller_tgid == target_tgid || MONITOR_TGIDS.get(&caller_tgid).is_some() {
        return Ok(0);
    }

    if let Some(mut entry) = EVENTS.reserve::<SignalEvent>(0) {
        // Writing the whole struct initializes the padding too, so no
        // uninitialized kernel memory reaches userspace
        entry.write(SignalEvent {
            header: EventHeader::new(EVENT_SIGNAL_TO_PROTECTED, now_ns()),
            caller_pid: caller_tgid,
            target_pid: target_tgid,
            sig: sig as u32,
            _pad: 0,
        });
        entry.submit(0);
    }

    Ok(0)
}
