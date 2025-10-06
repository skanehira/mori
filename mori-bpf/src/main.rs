#![no_std]
#![no_main]

#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod vmlinux {
    include!(concat!(env!("OUT_DIR"), "/vmlinux.rs"));
}

use aya_ebpf::{
    helpers::{bpf_d_path, bpf_get_current_cgroup_id},
    macros::{cgroup_sock_addr, lsm, map},
    maps::{
        HashMap, PerCpuArray,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{LsmContext, SockAddrContext},
};
use aya_log_ebpf::info;
use vmlinux::{file, path};

const ALLOW: i32 = 1;
const DENY: i32 = 0;

const PATH_MAX: usize = 512;

// Access mode flags (matching userspace AccessMode enum)
const ACCESS_MODE_READ: u8 = 1;
const ACCESS_MODE_WRITE: u8 = 2;
const ACCESS_MODE_READWRITE: u8 = 3;

// File open flags from Linux kernel (include/uapi/asm-generic/fcntl.h)
const O_ACCMODE: u32 = 0x0003; // Mask to extract access mode from flags
const O_RDONLY: u32 = 0x0000; // Open for reading only
const O_WRONLY: u32 = 0x0001; // Open for writing only
const O_RDWR: u32 = 0x0002; // Open for reading and writing

// Allow list for IPv4 addresses using LPM Trie for efficient CIDR matching
// Key: Key<[u8; 4]> where prefix_len is the number of significant bits and data is the IPv4 address
// Value: u8 (1 = allowed)
#[map]
static ALLOW_V4_LPM: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(1024, 0);

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

// Scratch buffer for path resolution. Using a per-CPU array avoids allocating
// large buffers on the BPF stack (limited to 512 bytes).
#[map]
static PATH_SCRATCH: PerCpuArray<[u8; PATH_MAX]> = PerCpuArray::with_max_entries(1, 0);

#[cgroup_sock_addr(connect4)]
pub fn mori_connect4(ctx: SockAddrContext) -> i32 {
    let addr = unsafe { (*ctx.sock_addr).user_ip4 };
    // When a 32-bit value is loaded in BPF it lands in CPU-endian order (little-endian on x86/arm64).
    // Convert back to big-endian so it matches the network-ordered keys stored in the map.
    let addr_be = u32::from_be(addr);

    // For LPM Trie lookup, always use prefix_len=32 (full IPv4 address).
    // The LPM Trie will find the longest matching prefix automatically.
    // For example, if searching for 104.16.30.34:
    // - First tries to match 104.16.30.34/32 (exact match)
    // - If not found, tries shorter prefixes like 104.16.0.0/13
    // - Returns the longest matching prefix entry
    let ip_bytes = addr_be.to_be_bytes();
    let key = Key::new(32, ip_bytes);

    match ALLOW_V4_LPM.get(&key) {
        Some(_) => {
            info!(
                &ctx,
                "connect: {}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
            );
            ALLOW
        }
        None => {
            info!(
                &ctx,
                "deny: {}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
            );
            DENY
        }
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

    // Use per-CPU scratch buffer to avoid exceeding the 512-byte BPF stack limit
    let path_buf = match PATH_SCRATCH.get_ptr_mut(0) {
        Some(ptr) => unsafe { &mut *ptr },
        None => return Ok(()),
    };

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

    // Get file open flags from struct file
    let f_flags = unsafe { (*file_ptr).f_flags };
    let access_mode = f_flags & O_ACCMODE;

    // Determine if this is a read or write operation
    let is_read = access_mode == O_RDONLY || access_mode == O_RDWR;
    let is_write = access_mode == O_WRONLY || access_mode == O_RDWR;

    // Check if this path is in the deny list
    match unsafe { DENY_PATHS.get(&*path_buf) } {
        Some(denied_mode) => {
            // Check if the current access mode matches the denied mode
            let should_deny = match *denied_mode {
                ACCESS_MODE_READ => is_read,
                ACCESS_MODE_WRITE => is_write,
                ACCESS_MODE_READWRITE => is_read || is_write,
                _ => false,
            };

            if should_deny {
                // Access mode matches deny policy, block access
                return Err(-1);
            } else {
                // Access mode doesn't match deny policy, allow access
                return Ok(());
            }
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
