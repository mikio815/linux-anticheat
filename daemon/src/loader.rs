use anyhow::{Context, Result};
use aya::{Bpf, Btf};
use aya::programs::Lsm;

pub fn load(obj_bytes: &'static [u8]) -> Result<Bpf> {
    let btf = Btf::from_sys_fs().context("BTF not available")?;

    let mut bpf = Bpf::load(obj_bytes)?;

    let prog: &mut Lsm = bpf
        .program_mut("ptrace_access_check")
        .context("ptrace_access_check not found")?
        .try_into()?;
    prog.load("ptrace_access_check", &btf)?;
    prog.attach()?;

    Ok(bpf)
}
