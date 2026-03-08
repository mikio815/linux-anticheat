use anyhow::{Context, Result};
use aya::{Ebpf, Btf};
use aya::programs::{Lsm, TracePoint};

pub fn load(obj_bytes: &'static [u8]) -> Result<Ebpf> {
    let btf = Btf::from_sys_fs().context("BTF not available")?;

    let mut bpf = Ebpf::load(obj_bytes)?;

    let tp: &mut TracePoint = bpf
        .program_mut("sys_enter_ptrace")
        .context("sys_enter_ptrace not found")?
        .try_into()?;
    tp.load()?;
    tp.attach("syscalls", "sys_enter_ptrace")?;

    let lsm: &mut Lsm = bpf
        .program_mut("ptrace_access_check")
        .context("ptrace_access_check not found")?
        .try_into()?;
    lsm.load("ptrace_access_check", &btf)?;
    lsm.attach()?;

    Ok(bpf)
}
