use anyhow::{Context, Result};
use aya::maps::{HashMap, MapData, RingBuf};
use log::info;
use tokio::io::unix::{AsyncFd, AsyncFdReadyMutGuard};
use tokio::process::Command;
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
        anyhow::bail!("usage: anticheat <game_binary> [args...]");
    }
    let game_binary = &args[1];
    let game_args = &args[2..];

    let mut bpf = loader::load(OBJ)?;

    let mut protected: HashMap<MapData, u32, u8> = HashMap::try_from(
        bpf.take_map("PROTECTED_PROCS").context("PROTECTED_PROCS not found")?,
    )?;

    let daemon_pid = std::process::id();
    protected.insert(daemon_pid, 1u8, 0)?;
    info!("daemon pid={} registered", daemon_pid);

    // getenv はフック可能なので /proc/self/environ を直接読む
    let environ = std::fs::read("/proc/self/environ").context("failed to read /proc/self/environ")?;
    if environ.split(|&b| b == 0).any(|var| var.starts_with(b"LD_PRELOAD=")) {
        anyhow::bail!("LD_PRELOAD is set");
    }

    // Safety: pre_exec は fork 後 exec 前に子プロセスのみで実行される
    let mut child = unsafe {
        Command::new(game_binary)
            .args(game_args)
            .env_remove("LD_PRELOAD") // exec に渡す env を直接操作（unsetenv フック回避）
            .pre_exec(|| {
                // 親 (daemon) が死んだら子 (game) も SIGKILL で落とす
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
                Ok(())
            })
            .spawn()
            .context("failed to spawn game")?
    };

    let game_pid = child.id().context("failed to get game pid")? as u32;
    protected.insert(game_pid, 1u8, 0)?;
    info!("game pid={} registered", game_pid);

    let ring_buf: RingBuf<MapData> = RingBuf::try_from(
        bpf.take_map("EVENTS").context("EVENTS not found")?,
    )?;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                let _ = child.kill().await;
                break;
            }
            status = child.wait() => {
                info!("game exited: {:?}", status);
                let _ = protected.remove(&game_pid);
                break;
            }
            result = async_fd.readable_mut() => {
                let mut guard: AsyncFdReadyMutGuard<'_, RingBuf<MapData>> = result?;
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
