use aya_ebpf::programs::XdpContext;
use syn_flood_detect_common::{VALID_ETH, VALID_IP, VALID_PORTS, VALID_TCP};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketKind {
    Malformed,
    Fragment,
    Tcp,
    Other,
}

pub struct Packet {
    pub kind: PacketKind,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub ethertype: u16,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u16,
    pub ip_protocol: u8,
    pub valid: u8,
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            kind: PacketKind::Malformed,
            src_ip: [0; 4],
            dst_ip: [0; 4],
            ethertype: 0,
            src_port: 0,
            dst_port: 0,
            tcp_flags: 0,
            ip_protocol: 0,
            valid: 0,
        }
    }
}

struct Frame {
    start: usize,
    end: usize,
}

impl Frame {
    #[inline(always)]
    fn bytes<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        let address = core::hint::black_box(self.start + offset);
        if address + N > self.end {
            return None;
        }
        Some(unsafe { core::ptr::read_unaligned(address as *const [u8; N]) })
    }

    #[inline(always)]
    fn contains(&self, end: usize) -> bool {
        // Keep an explicit scalar bound visible to the BPF verifier before
        // adding a variable offset to a packet pointer (IPv4 length + Ethernet).
        let end = core::hint::black_box(end);
        if end > 14 + u16::MAX as usize {
            return false;
        }
        self.start + end <= self.end
    }
}

#[inline(always)]
pub fn parse(ctx: &XdpContext) -> Packet {
    parse_frame(&Frame {
        start: ctx.data(),
        end: ctx.data_end(),
    })
}

#[inline(always)]
fn parse_frame(frame: &Frame) -> Packet {
    let mut packet = Packet::default();
    let _ = parse_ethernet(frame, &mut packet);
    packet
}

#[inline(always)]
fn parse_ethernet(frame: &Frame, packet: &mut Packet) -> Option<()> {
    let eth = frame.bytes::<14>(0)?;
    packet.ethertype = u16::from_be_bytes([eth[12], eth[13]]);
    packet.valid = VALID_ETH;
    if packet.ethertype == 0x0800 {
        parse_ipv4(frame, packet)
    } else {
        packet.kind = PacketKind::Other;
        Some(())
    }
}

// Isolate IPv4 parsing to keep register pressure bounded in the XDP entry point.
#[inline(never)]
fn parse_ipv4(frame: &Frame, packet: &mut Packet) -> Option<()> {
    let ip = frame.bytes::<20>(14)?;
    let ihl = (ip[0] & 15) as usize * 4;
    let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if ip[0] >> 4 != 4 || ihl < 20 || total < ihl || !frame.contains(14 + total) {
        return None;
    }
    packet.src_ip = [ip[12], ip[13], ip[14], ip[15]];
    packet.dst_ip = [ip[16], ip[17], ip[18], ip[19]];
    packet.ip_protocol = ip[9];
    packet.valid |= VALID_IP;
    if u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0 {
        packet.kind = PacketKind::Fragment;
        return Some(());
    }
    let offset = 14 + ihl;
    let length = total - ihl;
    match packet.ip_protocol {
        6 => parse_tcp(frame, offset, length, packet),
        17 => parse_udp(frame, offset, length, packet),
        _ => {
            packet.kind = PacketKind::Other;
            Some(())
        }
    }
}

#[inline(always)]
fn parse_tcp(frame: &Frame, offset: usize, length: usize, packet: &mut Packet) -> Option<()> {
    if length < 20 {
        return None;
    }
    let tcp = frame.bytes::<20>(offset)?;
    let header_len = (tcp[12] >> 4) as usize * 4;
    if header_len < 20 || header_len > length || !frame.contains(offset + header_len) {
        return None;
    }
    packet.src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    packet.dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    packet.tcp_flags = ((tcp[12] as u16 & 1) << 8) | tcp[13] as u16;
    packet.valid |= VALID_PORTS | VALID_TCP;
    packet.kind = PacketKind::Tcp;
    Some(())
}

#[inline(always)]
fn parse_udp(frame: &Frame, offset: usize, length: usize, packet: &mut Packet) -> Option<()> {
    if length < 8 {
        return None;
    }
    let udp = frame.bytes::<8>(offset)?;
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len > length {
        return None;
    }
    packet.src_port = u16::from_be_bytes([udp[0], udp[1]]);
    packet.dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    packet.valid |= VALID_PORTS;
    packet.kind = PacketKind::Other;
    Some(())
}
