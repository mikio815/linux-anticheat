#![cfg_attr(not(feature = "user"), no_std)]

/// Key for the protection maps. BPF hash map keys are compared byte-wise, so
/// `_pad` must always be 0 and must never be given a meaning: entries inserted
/// with one value would stop matching lookups using another.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ProcessKey {
    pub pid: u32,
    pub _pad: u32,
    pub start_time: u64,
}

/// Value for the protection maps. Values are never compared, so the reserved
/// space is free to claim later (per-entry policy such as allow_wx) without
/// changing value_size -- which would otherwise mean recreating pinned maps and
/// updating the KM's map-integrity baseline in lockstep.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ProtFlags {
    pub flags: u32,
    pub _reserved: u32,
}

impl ProtFlags {
    pub const PRESENT: u32 = 1 << 0;

    pub const fn present() -> Self {
        Self { flags: Self::PRESENT, _reserved: 0 }
    }
}

pub const EVENT_PTRACE_BLOCKED: u16 = 1;
pub const EVENT_MAP_FULL: u16 = 2;

pub const MAP_ID_PROTECTED_PROCS: u32 = 0;
pub const MAP_ID_WATCH_TGIDS: u32 = 1;

/// Common prefix of every ring buffer event. The consumer dispatches on
/// `event_type`; without it, records of different types are indistinguishable
/// and get silently misparsed as whichever type the reader assumes.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct EventHeader {
    pub event_type: u16,
    pub version: u8,
    pub _reserved: u8,
    pub _pad: u32,
    pub timestamp_ns: u64,
}

impl EventHeader {
    pub const VERSION: u8 = 1;

    pub const fn new(event_type: u16, timestamp_ns: u64) -> Self {
        Self {
            event_type,
            version: Self::VERSION,
            _reserved: 0,
            _pad: 0,
            timestamp_ns,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PtraceEvent {
    pub header: EventHeader,
    pub caller_pid: u32,
    pub target_pid: u32,
}

/// A protection map hit its capacity: the process in `tgid` could not be
/// registered and is therefore unprotected.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct MapFullEvent {
    pub header: EventHeader,
    pub map_id: u32,
    pub tgid: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProtFlags {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PtraceEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for MapFullEvent {}
