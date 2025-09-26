#![no_std]
#![no_main]

use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext};
use core::convert::TryInto;

#[cgroup_sock_addr(connect4)]
pub fn mori_connect4(ctx: SockAddrContext) -> i32 {
    match handle_connect(&ctx, Protocol::Ipv4) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap_or(ALLOW),
    }
}

#[cgroup_sock_addr(connect6)]
pub fn mori_connect6(ctx: SockAddrContext) -> i32 {
    match handle_connect(&ctx, Protocol::Ipv6) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap_or(ALLOW),
    }
}

const ALLOW: i32 = 1;
enum Protocol {
    Ipv4,
    Ipv6,
}

fn handle_connect(ctx: &SockAddrContext, proto: Protocol) -> Result<i32, i64> {
    // TODO: Implement policy lookups once user space populates maps.
    let _ = (ctx, proto);
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
