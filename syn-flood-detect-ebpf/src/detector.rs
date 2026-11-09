use aya_ebpf::{bindings::xdp_action, helpers::bpf_ktime_get_ns, macros::map, maps::Array};
use syn_flood_detect_common::{FirewallConfig, UBF_ENTRIES, UpdatableBloomFilter};

use syn_flood_detect_common::hashing::{
    HASH_FNV1A, HASH_HALFSIPHASH, HASH_MURMUR3, fnv1a_32, halfsiphash_2_4_32, murmur3_x86_32,
    service_key,
};

use crate::packet::{Packet, PacketKind};

#[map]
static UBF_ARRAY: Array<UpdatableBloomFilter> = Array::with_max_entries(UBF_ENTRIES, 0);

#[inline(always)]
pub fn filter(packet: &Packet, config: &FirewallConfig) -> u32 {
    if config.ubf_size == 0
        || config.ubf_size > UBF_ENTRIES
        || !matches!(
            config.hash_algorithm,
            HASH_FNV1A | HASH_MURMUR3 | HASH_HALFSIPHASH
        )
    {
        return xdp_action::XDP_ABORTED;
    }
    match packet.kind {
        PacketKind::Malformed | PacketKind::Fragment => xdp_action::XDP_DROP,
        PacketKind::Tcp => process_tcp(packet, config),
        PacketKind::Other => xdp_action::XDP_PASS,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum TcpAction {
    Syn,
    Ack,
    Ignore,
}

fn classify_flags(flags: u16) -> TcpAction {
    match flags & 0x003f {
        0x02 => TcpAction::Syn,
        0x10 => TcpAction::Ack,
        _ => TcpAction::Ignore,
    }
}

#[inline(always)]
fn process_tcp(packet: &Packet, config: &FirewallConfig) -> u32 {
    let flags = classify_flags(packet.tcp_flags);
    if flags == TcpAction::Ignore {
        return xdp_action::XDP_PASS;
    }
    let key = service_key(packet.src_ip, packet.dst_ip, packet.dst_port);
    let hash = match config.hash_algorithm {
        HASH_FNV1A => fnv1a_32(&key),
        HASH_MURMUR3 => murmur3_x86_32(&key),
        HASH_HALFSIPHASH => halfsiphash_2_4_32(&key),
        _ => return xdp_action::XDP_ABORTED,
    };
    // Local guard prevents a panic path in eBPF even if this function is reused.
    let index = if config.ubf_size == 0 {
        return xdp_action::XDP_ABORTED;
    } else {
        hash % config.ubf_size
    };
    match flags {
        TcpAction::Syn => process_syn(index, config),
        TcpAction::Ack => {
            process_ack(index);
            xdp_action::XDP_PASS
        }
        TcpAction::Ignore => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn process_syn(index: u32, config: &FirewallConfig) -> u32 {
    let entry = UBF_ARRAY.get(index).copied().unwrap_or_default();
    let now = unsafe { bpf_ktime_get_ns() } / 1_000_000;
    let updated = count_syn(entry, now, config.epoch_time_ms);
    let _ = UBF_ARRAY.set(index, &updated, 0);
    syn_action(&updated, config.syn_count_block_threshold)
}

fn count_syn(mut entry: UpdatableBloomFilter, now: u64, epoch_ms: u64) -> UpdatableBloomFilter {
    entry.counter = if entry.counter == 0 || now.saturating_sub(entry.timestamp) >= epoch_ms {
        1
    } else {
        entry.counter.saturating_add(1)
    };
    entry.timestamp = now;
    entry
}

fn syn_action(entry: &UpdatableBloomFilter, threshold: u32) -> u32 {
    if entry.counter >= u64::from(threshold) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    }
}

#[inline(always)]
fn process_ack(index: u32) {
    if let Some(entry) = UBF_ARRAY.get(index) {
        if let Some(cleared) = acknowledge(*entry) {
            let _ = UBF_ARRAY.set(index, &cleared, 0);
        }
    }
}

fn acknowledge(entry: UpdatableBloomFilter) -> Option<UpdatableBloomFilter> {
    (entry.counter == 1).then_some(UpdatableBloomFilter {
        counter: 0,
        timestamp: 0,
    })
}
