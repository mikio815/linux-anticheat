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

    // ゲーム保護は eBPF が exec 観測時に PROTECTED_PROCS へ自動登録する。
    // daemon は WATCH_TGIDS に自分の tgid を書いてトリガするだけ。
    let mut watch_tgids: HashMap<MapData, u32, u8> = HashMap::try_from(
        bpf.take_map("WATCH_TGIDS").context("WATCH_TGIDS not found")?,
    )?;
    // daemon 自身の coarse 保護 (tgid 単体)
    let mut protected_tgids: HashMap<MapData, u32, u8> = HashMap::try_from(
        bpf.take_map("PROTECTED_TGIDS").context("PROTECTED_TGIDS not found")?,
    )?;
    // 監視役免除: daemon は保護対象の maps/mem を読めるようにする
    let mut monitor_tgids: HashMap<MapData, u32, u8> = HashMap::try_from(
        bpf.take_map("MONITOR_TGIDS").context("MONITOR_TGIDS not found")?,
    )?;

    // アンチチートの全プログラム ID を収集
    let our_prog_ids: Vec<u32> = ["ptrace_access_check", "bpf_hook", "sched_process_exec"]
        .iter()
        .filter_map(|name| {
            bpf.program(name)
                .and_then(|p| p.info().ok())
                .map(|info| info.id())
        })
        .collect();

    // loaded_links() でカーネル上の全リンクを走査し、自分のプログラムに紐づくものを保護
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

    // 自分の prog ID を FD ガード対象に登録 (BPF_PROG_GET_FD_BY_ID 拒否)
    let mut protected_progs: HashMap<MapData, u32, u8> = HashMap::try_from(
        bpf.take_map("PROTECTED_PROGS").context("PROTECTED_PROGS not found")?,
    )?;
    for id in &our_prog_ids {
        protected_progs.insert(*id, 1u8, 0)?;
        info!("prog id={} protected", id);
    }

    // 自分の map ID を FD ガード対象に登録 (BPF_MAP_GET_FD_BY_ID 拒否)。
    // これにより攻撃者は PROTECTED_PROCS 等の map FD を ID から入手できず改ざんできない。
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

    // spawn より前に書く: ゲームは daemon の子なので exec 時に親 tgid が
    // WATCH_TGIDS にあれば eBPF が登録する (登録の取りこぼし窓を無くす)
    let daemon_tgid = std::process::id();
    watch_tgids.insert(daemon_tgid, 1u8, 0)?;
    protected_tgids.insert(daemon_tgid, 1u8, 0)?;
    monitor_tgids.insert(daemon_tgid, 1u8, 0)?;
    info!("daemon tgid={} watched", daemon_tgid);

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
    // PROTECTED_PROCS への登録は eBPF が exec 観測時に行う (start_time 付き)
    info!("game pid={} spawned", game_pid);

    let ring_buf: RingBuf<MapData> = RingBuf::try_from(
        bpf.take_map("EVENTS").context("EVENTS not found")?,
    )?;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    // 注入検出スキャナ。最初の scan() でベースラインを記録し、以降は差分を見る
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
                // PROTECTED_PROCS の stale エントリは (tgid+start_time) キーなので
                // PID 再利用されても誤ヒットせず、明示削除は不要
                info!("game exited: {:?}", status);
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
