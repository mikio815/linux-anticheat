#![cfg_attr(not(feature = "user"), no_std)]

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ProcessKey {
    pub pid: u32,
    pub _pad: u32,
    pub start_time: u64,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PtraceEvent {
    pub caller_pid: u32,
    pub target_pid: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PtraceEvent {}
