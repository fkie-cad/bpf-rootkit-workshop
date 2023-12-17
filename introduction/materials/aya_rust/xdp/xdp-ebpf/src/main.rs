#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};

#[xdp(name = "xdp")]
pub fn xdp(ctx: XdpContext) -> u32 {
    match try_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

// size-checked method to get raw pointer to packet headers and payloads
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_xdp(ctx: XdpContext) -> Result<u32, ()> {
    // ethernet header starts at 0
    // https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_II
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    // we only want IPv4 packets
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // get the IPv4 header
    // https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Packet_structure
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    // check if its a TCP or UDP packet
    match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            info!(&ctx, "got a TCP packet!");
        }
        IpProto::Udp => {
            info!(&ctx, "got a TCP packet!");
        }
        _ => return Err(()),
    };

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
