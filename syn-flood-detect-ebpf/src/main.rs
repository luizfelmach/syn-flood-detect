#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_F_NO_PREALLOC, xdp_action},
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use syn_flood_detect_common::{FirewallConfig, MODE_ALLOW, MODE_BLOCK, MODE_FILTER, MODE_UNKNOWN};
use syn_flood_detect_ebpf::{detector, packet, telemetry};

#[map]
static FIREWALL_CONFIG: HashMap<u32, FirewallConfig> =
    HashMap::with_max_entries(1, BPF_F_NO_PREALLOC);

#[xdp]
pub fn syn_flood_detect(ctx: XdpContext) -> u32 {
    let config = load_config();
    let packet = packet::parse(&ctx);
    let action = decide_action(&packet, config.as_ref());
    let mode = config
        .map(|c| c.packet_handling_mode)
        .unwrap_or(MODE_UNKNOWN);
    telemetry::record(&ctx, &packet, mode, action);
    return action;
}

#[inline(always)]
fn load_config() -> Option<FirewallConfig> {
    unsafe { FIREWALL_CONFIG.get(&0) }.copied()
}

#[inline(always)]
fn decide_action(packet: &packet::Packet, config: Option<&FirewallConfig>) -> u32 {
    let Some(config) = config else {
        return xdp_action::XDP_ABORTED;
    };
    match config.packet_handling_mode {
        MODE_ALLOW => xdp_action::XDP_PASS,
        MODE_BLOCK => xdp_action::XDP_DROP,
        MODE_FILTER => detector::filter(packet, config),
        _ => xdp_action::XDP_ABORTED,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"MIT\0";
