#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_sock_addr, map},
    maps::HashMap,
    programs::SockAddrContext,
};

const ALLOW: i32 = 1;
const DENY: i32 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv6Key {
    pub addr: [u32; 4], // IPv6 address in network byte order
}

// Allow lists for IPv4 and IPv6 addresses
// Using u8 as value since we only care about key existence (1 = allowed)
#[map]
static ALLOW_V4: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

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

enum Protocol {
    Ipv4,
    Ipv6,
}

fn try_handle_connect(ctx: &SockAddrContext, proto: Protocol) -> Result<i32, ()> {
    match proto {
        Protocol::Ipv4 => {
            let addr = unsafe { (*ctx.sock_addr).user_ip4 };
            match unsafe { ALLOW_V4.get(&addr) } {
                Some(_) => Ok(ALLOW),
                None => Ok(DENY),
            }
        }
        Protocol::Ipv6 => {
            let addr = unsafe {
                [
                    (*ctx.sock_addr).user_ip6[0],
                    (*ctx.sock_addr).user_ip6[1],
                    (*ctx.sock_addr).user_ip6[2],
                    (*ctx.sock_addr).user_ip6[3],
                ]
            };

            let key = Ipv6Key { addr };
            match unsafe { ALLOW_V6.get(&key) } {
                Some(_) => Ok(ALLOW),
                None => Ok(DENY),
            }
        }
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
