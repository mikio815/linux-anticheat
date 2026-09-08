use anyhow::{Context, Result};
use aya::maps::HashMap as BpfHashMap;
use aya::{Btf, Ebpf};
use aya::programs::{Lsm, RawTracePoint};
use aya_obj::btf::BtfKind;
use anticheat_common::ProtFlags;

pub fn load(obj_bytes: &'static [u8]) -> Result<Ebpf> {
    let btf = Btf::from_sys_fs().context("BTF not available")?;

    let mut bpf = Ebpf::load(obj_bytes)?;

    // (eBPF function name, LSM hook name = BTF type name)
    let hooks: &[(&str, &str)] = &[
        ("ptrace_access_check", "ptrace_access_check"),
        ("ptrace_traceme", "ptrace_traceme"),
        ("file_mprotect", "file_mprotect"),
        ("mmap_file", "mmap_file"),
        ("task_kill", "task_kill"),
        ("bpf_hook", "bpf"),
    ];

    // Tell the bpf hook which attach targets are ours, before it can deny
    // anything. Same lookup aya does for Lsm::load, so the ids match exactly what
    // an attach to one of these hooks puts in bpf_attr.attach_btf_id.
    {
        let mut guarded: BpfHashMap<_, u32, ProtFlags> =
            BpfHashMap::try_from(bpf.map_mut("GUARDED_ATTACH_IDS").context("GUARDED_ATTACH_IDS missing")?)?;
        for (_, hook_name) in hooks {
            let id = btf
                .id_by_type_name_kind(&format!("bpf_lsm_{hook_name}"), BtfKind::Func)
                .with_context(|| format!("bpf_lsm_{hook_name} not in vmlinux BTF"))?;
            guarded.insert(id, ProtFlags::present(), 0)?;
        }
    }

    for (prog_name, hook_name) in hooks {
        let lsm: &mut Lsm = bpf
            .program_mut(prog_name)
            .with_context(|| format!("{prog_name} not found"))?
            .try_into()?;
        lsm.load(hook_name, &btf)?;
        lsm.attach()?;
    }

    let exec: &mut RawTracePoint = bpf
        .program_mut("sched_process_exec")
        .context("sched_process_exec not found")?
        .try_into()?;
    exec.load()?;
    exec.attach("sched_process_exec")?;

    Ok(bpf)
}
