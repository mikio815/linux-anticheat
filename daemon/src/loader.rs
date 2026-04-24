use anyhow::{Context, Result};
use aya::{Ebpf, Btf};
use aya::programs::Lsm;

pub fn load(obj_bytes: &'static [u8]) -> Result<Ebpf> {
    let btf = Btf::from_sys_fs().context("BTF not available")?;

    let mut bpf = Ebpf::load(obj_bytes)?;

    let lsm: &mut Lsm = bpf
        .program_mut("ptrace_access_check")
        .context("ptrace_access_check not found")?
        .try_into()?;
    lsm.load("ptrace_access_check", &btf)?;
    lsm.attach()?;

    Ok(bpf)
}
