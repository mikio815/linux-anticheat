use anyhow::{Context, Result};
use aya::maps::{loaded_maps, HashMap, MapData, RingBuf};
use aya::programs::loaded_links;
use log::info;
use tokio::io::unix::{AsyncFd, AsyncFdReadyMutGuard};
use tokio::process::Command;
use tokio::signal;
use anticheat_common::PtraceEvent;

mod loader;
mod maps;
use maps::MapsScanner;

const MAPS_SCAN_INTERVAL_SECS: u64 = 5;

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

    // Game protection: eBPF auto-registers into PROTECTED_PROCS when it observes exec.
    // The daemon only writes its own tgid into WATCH_TGIDS to trigger it.
    let mut watch_tgids: HashMap<MapData, u32, u8> = HashMap::try_from(
        bpf.take_map("WATCH_TGIDS").context("WATCH_TGIDS not found")?,
    )?;
    // Coarse protection for the daemon itself (tgid only)
    let mut protected_tgids: HashMap<MapData, u32, u8> = HashMap::try_from(
        bpf.take_map("PROTECTED_TGIDS").context("PROTECTED_TGIDS not found")?,
    )?;
    // Monitor exemption: let the daemon read protected targets' maps/mem
    let mut monitor_tgids: HashMap<MapData, u32, u8> = HashMap::try_from(
        bpf.take_map("MONITOR_TGIDS").context("MONITOR_TGIDS not found")?,
    )?;

    // Collect all of the anti-cheat's program IDs
    let our_prog_ids: Vec<u32> = ["ptrace_access_check", "bpf_hook", "sched_process_exec"]
        .iter()
        .filter_map(|name| {
            bpf.program(name)
                .and_then(|p| p.info().ok())
                .map(|info| info.id())
        })
        .collect();

    // Walk all kernel links via loaded_links() and protect those bound to our programs
    let mut protected_links: HashMap<MapData, u32, u8> = HashMap::try_from(
        bpf.take_map("PROTECTED_LINKS").context("PROTECTED_LINKS not found")?,
    )?;
    for link_info in loaded_links().flatten() {
        if our_prog_ids.contains(&link_info.program_id()) {
            let link_id = link_info.id();
            protected_links.insert(link_id, 1u8, 0)?;
            info!("link id={} protected", link_id);
        }
    }

    // Register our prog IDs as FD-guard targets (deny BPF_PROG_GET_FD_BY_ID)
    let mut protected_progs: HashMap<MapData, u32, u8> = HashMap::try_from(
        bpf.take_map("PROTECTED_PROGS").context("PROTECTED_PROGS not found")?,
    )?;
    for id in &our_prog_ids {
        protected_progs.insert(*id, 1u8, 0)?;
        info!("prog id={} protected", id);
    }

    // Register our map IDs as FD-guard targets (deny BPF_MAP_GET_FD_BY_ID).
    // This stops an attacker from getting an FD for maps like PROTECTED_PROCS by ID and tampering.
    const OUR_MAPS: &[&str] = &[
        "EVENTS",
        "PROTECTED_PROCS",
        "PROTECTED_TGIDS",
        "MONITOR_TGIDS",
        "WATCH_TGIDS",
        "PROTECTED_LINKS",
        "PROTECTED_PROGS",
        "PROTECTED_MAPS",
    ];
    let mut protected_maps: HashMap<MapData, u32, u8> = HashMap::try_from(
        bpf.take_map("PROTECTED_MAPS").context("PROTECTED_MAPS not found")?,
    )?;
    for map_info in loaded_maps().flatten() {
        if map_info.name_as_str().is_some_and(|n| OUR_MAPS.contains(&n)) {
            let id = map_info.id();
            protected_maps.insert(id, 1u8, 0)?;
            info!("map id={} protected", id);
        }
    }

    // Write before spawn: the game is the daemon's child, so on exec eBPF registers it
    // if the parent tgid is in WATCH_TGIDS (eliminates the registration race window)
    let daemon_tgid = std::process::id();
    watch_tgids.insert(daemon_tgid, 1u8, 0)?;
    protected_tgids.insert(daemon_tgid, 1u8, 0)?;
    monitor_tgids.insert(daemon_tgid, 1u8, 0)?;
    info!("daemon tgid={} watched", daemon_tgid);

    // getenv can be hooked, so read /proc/self/environ directly
    let environ = std::fs::read("/proc/self/environ").context("failed to read /proc/self/environ")?;
    if environ.split(|&b| b == 0).any(|var| var.starts_with(b"LD_PRELOAD=")) {
        anyhow::bail!("LD_PRELOAD is set");
    }

    // Safety: pre_exec runs only in the child, after fork and before exec
    let mut child = unsafe {
        Command::new(game_binary)
            .args(game_args)
            .env_remove("LD_PRELOAD") // manipulate the exec env directly (avoids the unsetenv hook)
            .pre_exec(|| {
                // If the parent (daemon) dies, take the child (game) down with SIGKILL
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
                Ok(())
            })
            .spawn()
            .context("failed to spawn game")?
    };

    let game_pid = child.id().context("failed to get game pid")? as u32;
    // eBPF registers into PROTECTED_PROCS when it observes exec (with start_time)
    info!("game pid={} spawned", game_pid);

    let ring_buf: RingBuf<MapData> = RingBuf::try_from(
        bpf.take_map("EVENTS").context("EVENTS not found")?,
    )?;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    // Injection-detection scanner. The first scan() records the baseline; later ones diff against it
    let mut scanner = MapsScanner::new(game_pid, game_binary);
    scanner.scan();
    let mut scan_tick =
        tokio::time::interval(std::time::Duration::from_secs(MAPS_SCAN_INTERVAL_SECS));

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                let _ = child.kill().await;
                break;
            }
            _ = scan_tick.tick() => {
                scanner.scan();
            }
            status = child.wait() => {
                // Stale PROTECTED_PROCS entries key on (tgid+start_time), so PID reuse
                // never false-hits and no explicit removal is needed
                info!("game exited: {:?}", status);
                break;
            }
            result = async_fd.readable_mut() => {
                let mut guard: AsyncFdReadyMutGuard<'_, RingBuf<MapData>> = result?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let item: &[u8] = &item;
                    if item.len() >= core::mem::size_of::<PtraceEvent>() {
                        // Safety: the eBPF side wrote this as a PtraceEvent
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
