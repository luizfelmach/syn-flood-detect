use crate::packet::Packet;
use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::map,
    maps::{PerCpuArray, RingBuf},
    programs::XdpContext,
};
use syn_flood_detect_common::{PacketEvent, PacketStats};

#[map]
static PACKET_EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);
#[map]
static PACKET_STATS: PerCpuArray<PacketStats> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
pub fn record(ctx: &XdpContext, packet: &Packet, mode: u32, action: u32) {
    count_action(action);
    let event = build_event(ctx, packet, mode, action);
    publish(event);
}

#[inline(always)]
fn count_action(action: u32) {
    if let Some(stats) = PACKET_STATS.get_ptr_mut(0) {
        unsafe {
            match action {
                xdp_action::XDP_PASS => (*stats).passed += 1,
                xdp_action::XDP_DROP => (*stats).dropped += 1,
                _ => (*stats).aborted += 1,
            }
        }
    }
}

#[inline(always)]
fn build_event(ctx: &XdpContext, packet: &Packet, mode: u32, action: u32) -> PacketEvent {
    PacketEvent {
        timestamp_monotonic_ns: unsafe { bpf_ktime_get_ns() },
        ifindex: unsafe { (*ctx.ctx).ingress_ifindex },
        length_bytes: (ctx.data_end() - ctx.data()) as u32,
        mode,
        action,
        src_ip: packet.src_ip,
        dst_ip: packet.dst_ip,
        ethertype: packet.ethertype,
        src_port: packet.src_port,
        dst_port: packet.dst_port,
        tcp_flags: packet.tcp_flags,
        ip_protocol: packet.ip_protocol,
        valid: packet.valid,
        reserved: [0; 6],
    }
}

#[inline(always)]
fn publish(event: PacketEvent) {
    if let Some(mut slot) = PACKET_EVENTS.reserve::<PacketEvent>(0) {
        slot.write(event);
        slot.submit(0);
    } else if let Some(stats) = PACKET_STATS.get_ptr_mut(0) {
        unsafe {
            (*stats).lost += 1;
        }
    }
}
