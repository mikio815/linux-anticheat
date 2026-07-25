use aya_ebpf::{
    helpers::bpf_get_current_task_btf,
    macros::lsm,
    programs::LsmContext,
};
use anticheat_common::ProcessKey;

use crate::vmlinux::task_struct;
use crate::{PROTECTED_PROCS, PROTECTED_TGIDS};

const PROT_WRITE: u64 = 0x2;
const PROT_EXEC: u64 = 0x4;

#[lsm(hook = "file_mprotect")]
pub fn file_mprotect(ctx: LsmContext) -> i32 {
    match unsafe { try_file_mprotect(ctx) } {
        Ok(ret) => ret,
        Err(_) => -1, // Fail-Closed
    }
}

unsafe fn try_file_mprotect(ctx: LsmContext) -> Result<i32, i64> {
    let retval: i32 = ctx.arg(3);
    if retval != 0 {
        return Ok(retval);
    }

    let reqprot: u64 = ctx.arg(1);
    let prot: u64 = ctx.arg(2);
    if !has_wx(reqprot) && !has_wx(prot) {
        return Ok(0);
    }

    if !current_is_protected() {
        return Ok(0);
    }

    Ok(-1) // -EPERM
}

fn has_wx(prot: u64) -> bool {
    (prot & PROT_WRITE != 0) && (prot & PROT_EXEC != 0)
}

unsafe fn current_is_protected() -> bool {
    let task = bpf_get_current_task_btf() as *const task_struct;
    if task.is_null() {
        return false;
    }

    let tgid = (*task).tgid as u32;
    if PROTECTED_TGIDS.get(&tgid).is_some() {
        return true;
    }

    let leader = if (*task).group_leader.is_null() {
        task
    } else {
        (*task).group_leader
    };

    let key = ProcessKey {
        pid: tgid,
        _pad: 0,
        start_time: (*leader).start_time,
    };

    PROTECTED_PROCS.get(&key).is_some()
}
