use anyhow::{Context, Result};
use aya::{Btf, Ebpf};
use aya::programs::{Lsm, TracePoint};

pub fn load(obj_bytes: &'static [u8]) -> Result<Ebpf> {
    let btf = Btf::from_sys_fs().context("BTF not available")?;

    let mut bpf = Ebpf::load(obj_bytes)?;

    // (eBPF function name, LSM hook name = BTF type name)
    for (prog_name, hook_name) in &[
        ("ptrace_access_check", "ptrace_access_check"),
        ("ptrace_traceme", "ptrace_traceme"),
        ("file_mprotect", "file_mprotect"),
        ("bpf_hook", "bpf"),
    ] {
        let lsm: &mut Lsm = bpf
            .program_mut(prog_name)
            .with_context(|| format!("{prog_name} not found"))?
            .try_into()?;
        lsm.load(hook_name, &btf)?;
        lsm.attach()?;
    }

    let exec: &mut TracePoint = bpf
        .program_mut("sched_process_exec")
        .context("sched_process_exec not found")?
        .try_into()?;
    exec.load()?;
    exec.attach("sched", "sched_process_exec")?;

    Ok(bpf)
}
