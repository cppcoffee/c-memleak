#![no_std]

pub const ALLOCS_MAX_ENTRIES: u32 = 1000000;
pub const MAP_FAILED: u64 = u64::MAX;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct AllocInfo {
    pub size: usize,
    pub timestamp_ns: u64,
    pub stack_id: i64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for AllocInfo {}

impl AllocInfo {
    pub fn new(size: usize, timestamp_ns: u64, stack_id: i64) -> Self {
        Self {
            size,
            timestamp_ns,
            stack_id,
        }
    }
}
