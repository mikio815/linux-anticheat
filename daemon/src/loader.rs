use anyhow::{Context, Result};
use aya::{Btf, Ebpf};
use aya::programs::Lsm;

pub fn load(obj_bytes: &'static [u8]) -> Result<Ebpf> {
    let btf = Btf::from_sys_fs().context("BTF not available")?;

    let mut bpf = Ebpf::load(obj_bytes)?;

    // (eBPF 関数名, LSM フック名 = BTF 型名)
    for (prog_name, hook_name) in &[
        ("ptrace_access_check", "ptrace_access_check"),
        ("bpf_hook", "bpf"),
    ] {
        let lsm: &mut Lsm = bpf
            .program_mut(prog_name)
            .with_context(|| format!("{prog_name} not found"))?
            .try_into()?;
        lsm.load(hook_name, &btf)?;
        lsm.attach()?;
    }

    Ok(bpf)
}
