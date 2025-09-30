#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_sock_addr, map},
    maps::HashMap,
    programs::SockAddrContext,
};

const ALLOW: i32 = 1;
const DENY: i32 = 0;

// Allow list for IPv4 addresses; value presence (1) means allowed
#[map]
static ALLOW_V4: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[cgroup_sock_addr(connect4)]
pub fn mori_connect4(ctx: SockAddrContext) -> i32 {
    let addr = unsafe { (*ctx.sock_addr).user_ip4 };
    match unsafe { ALLOW_V4.get(&addr) } {
        Some(_) => ALLOW,
        None => DENY,
    }
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
