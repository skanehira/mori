#![no_std]
#![no_main]

#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod vmlinux;

use aya_ebpf::{
    helpers::{bpf_d_path, bpf_get_current_cgroup_id},
    macros::{cgroup_sock_addr, lsm, map},
    maps::HashMap,
    programs::{LsmContext, SockAddrContext},
};
use vmlinux::{file, path};

const ALLOW: i32 = 1;
const DENY: i32 = 0;

const PATH_MAX: usize = 64;

// Allow list for IPv4 addresses; value presence (1) means allowed
#[map]
static ALLOW_V4: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

// Target cgroup ID for file access control
// Note: BPF_LSM_CGROUP attach type cannot be used for file_open hook because:
// - file_open is a sleepable LSM hook
// - BPF_LSM_CGROUP only supports non-sleepable hooks
// Therefore, we use system-wide LSM attach and filter by cgroup ID in the program
#[map]
static TARGET_CGROUP: HashMap<u64, u8> = HashMap::with_max_entries(1, 0);

// Deny list for file paths; value is access mode (1=READ, 2=WRITE, 3=READ|WRITE)
#[map]
static DENY_PATHS: HashMap<[u8; PATH_MAX], u8> = HashMap::with_max_entries(1024, 0);

#[cgroup_sock_addr(connect4)]
pub fn mori_connect4(ctx: SockAddrContext) -> i32 {
    let addr = unsafe { (*ctx.sock_addr).user_ip4 };
    match unsafe { ALLOW_V4.get(&addr) } {
        Some(_) => ALLOW,
        None => DENY,
    }
}

#[lsm(hook = "file_open")]
pub fn mori_path_open(ctx: LsmContext) -> i32 {
    match try_path_open(&ctx) {
        Ok(()) => 0,
        Err(ret) => ret,
    }
}

fn try_path_open(ctx: &LsmContext) -> Result<(), i32> {
    // Check if current process is in target cgroup
    // This filters events to only processes within the monitored cgroup
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if unsafe { TARGET_CGROUP.get(&cgroup_id).is_none() } {
        return Ok(()); // Not in target cgroup, allow
    }

    // Get file pointer from LSM context (file_open hook receives struct file *)
    let file_ptr = unsafe { ctx.arg::<*const file>(0) };
    if file_ptr.is_null() {
        return Ok(());
    }

    // Get the address of f_path field from struct file
    // This works because LSM programs have trusted pointers with BTF type information
    // Cast vmlinux::path to aya_ebpf::bindings::path (same memory layout)
    let path_ptr = unsafe {
        &(*file_ptr).f_path as *const path as *const aya_ebpf::bindings::path
            as *mut aya_ebpf::bindings::path
    };

    // Allocate buffer on stack - zero-padded to PATH_MAX for HashMap lookup
    let mut path_buf: [u8; PATH_MAX] = [0; PATH_MAX];
    let ret = unsafe {
        bpf_d_path(
            path_ptr,
            path_buf.as_mut_ptr() as *mut aya_ebpf::cty::c_char,
            PATH_MAX as u32,
        )
    };

    if ret < 0 {
        return Ok(());
    }

    // Ensure bytes after the path string are zeroed
    // bpf_d_path only writes the path string + null terminator,
    // but may leave garbage after that in the buffer.
    // We need to zero everything after the actual path to ensure HashMap lookups work.
    // eBPF verifier doesn't allow variable-offset array writes,
    // so we check each index against path_len within a fixed-range loop.
    let path_len = ret as usize;
    #[allow(clippy::needless_range_loop)]
    for i in 0..PATH_MAX {
        if i >= path_len {
            path_buf[i] = 0;
        }
    }

    // Check if this path is in the deny list
    match unsafe { DENY_PATHS.get(&path_buf) } {
        Some(_mode) => {
            // Path is denied, block access
            return Err(-1);
        }
        None => {
            // Path not in deny list, allow access
            return Ok(());
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
