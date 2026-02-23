use anyhow::Result;
use aya::maps::RingBuf;
use log::info;
use tokio::io::unix::AsyncFd;
use tokio::signal;
use anticheat_common::PtraceEvent;

mod loader;

// ebpf/ を先にビルドしてから cargo build すること
static OBJ: &[u8] = include_bytes!(
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

    let mut bpf = loader::load(OBJ)?;
    info!("anticheat running");

    let ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS")?)?;
    let async_fd = AsyncFd::new(ring_buf)?;

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => break,
            result = async_fd.readable_mut() => {
                let mut guard = result?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    if item.len() >= core::mem::size_of::<PtraceEvent>() {
                        // Safety: eBPF 側で PtraceEvent として書き込んでいる
                        let ev = unsafe { &*(item.as_ptr() as *const PtraceEvent) };
                        info!("ptrace blocked: caller_pid={}", ev.caller_pid);
                    }
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
}
