#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_sock_addr, map},
    maps::HashMap,
    programs::SockAddrContext,
};

// Key structure for IPv4 addresses
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv4Key {
    pub addr: u32, // IPv4 address in network byte order
}

// Key structure for IPv6 addresses
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv6Key {
    pub addr: [u32; 4], // IPv6 address in network byte order
}

// Allow lists for IPv4 and IPv6 addresses
#[map]
static ALLOW_V4: HashMap<Ipv4Key, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static ALLOW_V6: HashMap<Ipv6Key, u8> = HashMap::with_max_entries(1024, 0);

#[cgroup_sock_addr(connect4)]
pub fn mori_connect4(ctx: SockAddrContext) -> i32 {
    match try_handle_connect(&ctx, Protocol::Ipv4) {
        Ok(ret) => ret,
        Err(_) => ALLOW,
    }
}

#[cgroup_sock_addr(connect6)]
pub fn mori_connect6(ctx: SockAddrContext) -> i32 {
    match try_handle_connect(&ctx, Protocol::Ipv6) {
        Ok(ret) => ret,
        Err(_) => ALLOW,
    }
}

const ALLOW: i32 = 1;
#[allow(dead_code)]
const DENY: i32 = 0;

enum Protocol {
    Ipv4,
    Ipv6,
}

fn try_handle_connect(_ctx: &SockAddrContext, _proto: Protocol) -> Result<i32, ()> {
    // For now, allow all connections to test basic functionality
    Ok(ALLOW)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
pub static LICENSE: [u8; 4] = *b"GPL\0";
