use anyhow::{Context, Result};
use aya::maps::{HashMap, MapData, RingBuf};
use log::info;
use std::fs;
use tokio::io::unix::{AsyncFd, AsyncFdReadyMutGuard};
use tokio::signal;
use anticheat_common::PtraceEvent;

mod loader;

static OBJ: &[u8] = aya::include_bytes_aligned!(
    "../../ebpf/target/bpfel-unknown-none/release/anticheat-ebpf"
);

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("root required");
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        anyhow::bail!("usage: anticheat <target_pid>");
    }
    let target_pid: u32 = args[1].parse().context("target_pid must be integer")?;

    // ターゲット PID が存在するか確認
    fs::metadata(format!("/proc/{}", target_pid))
        .with_context(|| format!("pid {} not found", target_pid))?;

    let mut bpf = loader::load(OBJ)?;

    let mut protected: HashMap<_, u32, u8> = HashMap::try_from(
        bpf.map_mut("PROTECTED_PROCS").context("PROTECTED_PROCS not found")?,
    )?;
    protected.insert(target_pid, 1u8, 0)?;
    info!("protecting pid={}", target_pid);

    let ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS").context("EVENTS not found")?)?;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => break,
            result = async_fd.readable_mut() => {
                let mut guard: AsyncFdReadyMutGuard<'_, RingBuf<&mut MapData>> = result?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let item: &[u8] = &item;
                    if item.len() >= core::mem::size_of::<PtraceEvent>() {
                        // Safety: eBPF 側で PtraceEvent として書き込んでいる
                        let ev = unsafe { &*(item.as_ptr() as *const PtraceEvent) };
                        info!(
                            "ptrace blocked: caller_pid={} -> target_pid={}",
                            ev.caller_pid, ev.target_pid
                        );
                    }
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}
