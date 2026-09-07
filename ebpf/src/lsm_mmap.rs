use aya_ebpf::{
    helpers::bpf_get_current_task_btf,
    macros::lsm,
    programs::LsmContext,
};
use crate::vmlinux::task_struct;
use crate::task_is_protected;

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
    // Read as i64: an i32 read makes aya emit a zero-extending truncation,
    // which turns a negative errno into a large positive value and loses the
    // [-4095, 0] range the verifier tracks for this argument. Kernel 7.1
    // rejects the resulting return value; older verifiers let it through.
    let retval: i64 = ctx.arg(3);
    if retval != 0 {
        return Ok(-1); // something already denied; keep it denied
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

// security_mmap_file(file, reqprot, prot, flags) -- arg(4) is the accumulated return value.
// This fires for anonymous mappings too (file == NULL), which is exactly the gap
// file_mprotect cannot cover: mmap(PROT_READ|PROT_WRITE|PROT_EXEC) needs no later
// mprotect call, so W^X enforced only at mprotect is trivially bypassed.
#[lsm(hook = "mmap_file")]
pub fn mmap_file(ctx: LsmContext) -> i32 {
    match unsafe { try_mmap_file(ctx) } {
        Ok(ret) => ret,
        Err(_) => -1, // Fail-Closed
    }
}

unsafe fn try_mmap_file(ctx: LsmContext) -> Result<i32, i64> {
    // Read as i64: an i32 read makes aya emit a zero-extending truncation,
    // which turns a negative errno into a large positive value and loses the
    // [-4095, 0] range the verifier tracks for this argument. Kernel 7.1
    // rejects the resulting return value; older verifiers let it through.
    let retval: i64 = ctx.arg(4);
    if retval != 0 {
        return Ok(-1); // something already denied; keep it denied
    }

    // Check the prot bits before the map lookup: this hook fires on every mmap in
    // the system and almost none of them ask for W+X, so the common path is two
    // register compares
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
    task_is_protected(bpf_get_current_task_btf() as *const task_struct)
}
