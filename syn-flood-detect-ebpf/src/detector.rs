use aya_ebpf::{bindings::xdp_action, helpers::bpf_ktime_get_ns, macros::map, maps::Array};
use syn_flood_detect_common::{FirewallConfig, UBF_ENTRIES, UpdatableBloomFilter};

use crate::packet::{Packet, PacketKind};

#[map]
static UBF_ARRAY: Array<UpdatableBloomFilter> = Array::with_max_entries(UBF_ENTRIES, 0);

#[inline(always)]
pub fn filter(packet: &Packet, config: &FirewallConfig) -> u32 {
    if config.ubf_size == 0 || config.ubf_size > UBF_ENTRIES {
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
    let index = hash_flow(
        packet.src_ip,
        packet.dst_ip,
        packet.dst_port.to_be(),
        config.ubf_size,
    );
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

#[inline(always)]
pub fn hash_flow(src_ip: [u8; 4], dst_ip: [u8; 4], dst_port: u16, max_entries: u32) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811c_9dc5;
    const FNV_PRIME: u32 = 0x0100_0193;

    let mut hash = FNV_OFFSET_BASIS;

    for byte in src_ip {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    for byte in dst_ip {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash ^= (dst_port as u32) & 0xff;
    hash = hash.wrapping_mul(FNV_PRIME);
    hash ^= ((dst_port as u32) >> 8) & 0xff;
    hash = hash.wrapping_mul(FNV_PRIME);

    // Keep the zero check local: no Rust panic path may be emitted into eBPF.
    if max_entries == 0 {
        0
    } else {
        hash % max_entries
    }
}
