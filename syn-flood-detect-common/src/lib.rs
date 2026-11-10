#![no_std]

pub mod hashing;

/// Physical capacity; UBF_SIZE controls the usable hash range.
pub const UBF_ENTRIES: u32 = 8192;
pub const DEFAULT_UBF_SIZE: u32 = 2048;

pub const MODE_ALLOW: u32 = 0;
pub const MODE_BLOCK: u32 = 1;
pub const MODE_FILTER: u32 = 2;
pub const MODE_UNKNOWN: u32 = u32::MAX;

#[cfg(feature = "user")]
use aya::Pod;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UpdatableBloomFilter {
    pub counter: u64,
    pub timestamp: u64,
}

#[cfg(feature = "user")]
unsafe impl Pod for UpdatableBloomFilter {}

/// One complete runtime configuration with explicit padding.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirewallConfig {
    /// Reset a bucket on the next SYN after this many milliseconds without SYNs.
    pub idle_timeout_ms: u64,
    pub syn_count_block_threshold: u32,
    pub packet_handling_mode: u32,
    pub ubf_size: u32,
    pub hash_algorithm: u32,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            idle_timeout_ms: 2000,
            syn_count_block_threshold: 3,
            packet_handling_mode: MODE_FILTER,
            ubf_size: DEFAULT_UBF_SIZE,
            hash_algorithm: hashing::DEFAULT_HASH_ALGORITHM,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl Pod for FirewallConfig {}

/// Fixed 48-byte wire record. Explicit reserved bytes avoid uninitialized padding.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PacketEvent {
    pub timestamp_monotonic_ns: u64,
    pub ifindex: u32,
    pub length_bytes: u32,
    pub mode: u32,
    pub action: u32,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub ethertype: u16,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u16,
    pub ip_protocol: u8,
    pub valid: u8,
    pub reserved: [u8; 6],
}

pub const VALID_ETH: u8 = 1;
pub const VALID_IP: u8 = 2;
pub const VALID_PORTS: u8 = 4;
pub const VALID_TCP: u8 = 8;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PacketStats {
    pub passed: u64,
    pub dropped: u64,
    pub aborted: u64,
    pub lost: u64,
}

#[cfg(feature = "user")]
unsafe impl Pod for PacketStats {}

const _: () = assert!(core::mem::size_of::<PacketEvent>() == 48);

const _: () = assert!(core::mem::size_of::<FirewallConfig>() == 24);
