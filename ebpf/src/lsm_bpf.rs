use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::lsm,
    programs::LsmContext,
};

use crate::PROTECTED_LINKS;

const BPF_LINK_DETACH: i32 = 33;

// bpf() syscall の LSM フック
// BPF_LINK_DETACH でアンチチートのリンクを切ろうとしたら EPERM
#[lsm(hook = "bpf")]
pub fn bpf_hook(ctx: LsmContext) -> i32 {
    match unsafe { try_bpf(ctx) } {
        Ok(ret) => ret,
        Err(_) => -1, // Fail-Closed
    }
}

unsafe fn try_bpf(ctx: LsmContext) -> Result<i32, i64> {
    let cmd: i32 = ctx.arg(0);
    if cmd != BPF_LINK_DETACH {
        return Ok(0);
    }

    // attr はカーネルにコピー済みのポインタ
    // BPF_LINK_DETACH の場合、union の先頭 4 バイトが link_id
    let attr: *const u32 = ctx.arg(1);
    let link_id = bpf_probe_read_kernel(attr)?;

    if PROTECTED_LINKS.get(&link_id).is_some() {
        return Ok(-1); // EPERM
    }

    Ok(0)
}
