use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::lsm,
    programs::LsmContext,
};

use crate::{PROTECTED_LINKS, PROTECTED_MAPS, PROTECTED_PROGS};

const BPF_PROG_GET_FD_BY_ID: i32 = 13;
const BPF_MAP_GET_FD_BY_ID: i32 = 14;
const BPF_LINK_GET_FD_BY_ID: i32 = 30;

// bpf() syscall の LSM フック。
// 守るのは detach そのものではなく FD の入手経路。
// 攻撃者が我々の prog/map/link の FD を ID から取得できなければ、
// detach / link_update / map 改ざんは FD が無い時点で塞がる。
// daemon は起動時に握った FD を保持し続けるので影響を受けない。
#[lsm(hook = "bpf")]
pub fn bpf_hook(ctx: LsmContext) -> i32 {
    match unsafe { try_bpf(ctx) } {
        Ok(ret) => ret,
        // fail-open: bpf() は daemon 自身が多用する syscall。
        // probe read 失敗で全 bpf() を止めると daemon が自滅するため、
        // 判定不能時は通す。守る対象は特定 ID の FD 入手のみに限定する。
        Err(_) => 0,
    }
}

unsafe fn try_bpf(ctx: LsmContext) -> Result<i32, i64> {
    let cmd: i32 = ctx.arg(0);

    // GET_FD_BY_ID 系のみ対象。attr の先頭 u32 が prog_id / map_id / link_id。
    let target = match cmd {
        BPF_PROG_GET_FD_BY_ID => &PROTECTED_PROGS,
        BPF_MAP_GET_FD_BY_ID => &PROTECTED_MAPS,
        BPF_LINK_GET_FD_BY_ID => &PROTECTED_LINKS,
        _ => return Ok(0),
    };

    // attr はカーネルにコピー済みのポインタ
    let attr: *const u32 = ctx.arg(1);
    let id = bpf_probe_read_kernel(attr)?;

    if target.get(&id).is_some() {
        return Ok(-1); // EPERM
    }

    Ok(0)
}
