#![cfg_attr(not(feature = "user"), no_std)]

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PtraceEvent {
    pub caller_pid: u32,
    pub target_pid: u32, // Phase 2: task_struct から取得
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PtraceEvent {}
