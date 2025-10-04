# Development Guide

This guide provides instructions for setting up a development environment and contributing to mori.

## Prerequisites

### System Requirements

- **OS**: Linux (kernel 5.10+)
- **Architecture**: x86_64 or aarch64
- **Kernel Features**:
  - `CONFIG_BPF_LSM=y`
  - `CONFIG_CGROUP_BPF=y`
  - cgroup v2 enabled

Verify kernel support:

```bash
# Check kernel version
uname -r

# Check if BPF LSM is enabled
$ zcat /proc/config.gz | grep CONFIG_BPF_LSM
CONFIG_BPF_LSM=y

# Check if BPF is in LSM list
cat /sys/kernel/security/lsm
```

### Required Tools

#### Nightly Toolchain for eBPF (Linux only)

eBPF programs require Rust nightly with BPF target support:

```bash
# Install nightly toolchain with rust-src component
rustup toolchain install nightly-x86_64-unknown-linux-gnu \
    --profile minimal \
    --component rust-src

# Or for aarch64
rustup toolchain install nightly-aarch64-unknown-linux-gnu \
    --profile minimal \
    --component rust-src
```

#### bpf-linker

Required for linking eBPF programs:

```bash
cargo install bpf-linker
```

#### aya-tool

Required for generating `vmlinux.rs` from kernel BTF (BPF Type Format):

```bash
cargo install bpf-linker bindgen-cli
cargo install --git https://github.com/aya-rs/aya -- aya-tool
```

`vmlinux.rs` contains Rust bindings for kernel types and is used by eBPF programs
to safely access kernel structures. This file is **automatically generated** during
the build process from the running kernel's BTF information (`/sys/kernel/btf/vmlinux`).

**Note**: The generated `vmlinux.rs` is kernel-version specific and is created in
the build output directory (`OUT_DIR`). You don't need to manually generate it -
the `mori-bpf/build.rs` script handles this automatically using `aya-tool`.

#### BPF Development Tools (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y \
    libbpf-dev \
    linux-tools-common \
    linux-tools-$(uname -r) \
    clang \
    llvm
```

## Building

The build process automatically:
1. Compiles eBPF programs in `mori-bpf/` using the nightly toolchain
2. Embeds the compiled eBPF bytecode into the main binary
3. Builds the userspace program

### Build Artifacts

- Userspace binary: `target/release/mori`
- eBPF ELF (intermediate): `target/bpfel-unknown-none/release/mori-bpf`

## Testing

Install cargo-nextest

```bash
cargo install cargo-nextest --locked
```

### Run All Tests

```bash
# test runner
make test
```

### Code Coverage

```bash
# Generate coverage report
make test-cov
```

## eBPF Development

### eBPF Program Structure

eBPF programs are in the `mori-bpf/` workspace member:

```
mori-bpf/
├── src/
│   └── main.rs       # eBPF programs (network, file control)
├── Cargo.toml
└── build.rs          # Generates vmlinux.rs automatically
```

#### vmlinux.rs - Kernel Type Bindings

`vmlinux.rs` is **automatically generated** by `mori-bpf/build.rs` during the build
process from the running kernel's BTF (BPF Type Format) information.

**Build-time generation:**
- The `build.rs` script calls `aya-tool generate file path` to create kernel type bindings
- Generated types are written to `OUT_DIR/vmlinux.rs`
- The eBPF code includes it using `include!(concat!(env!("OUT_DIR"), "/vmlinux.rs"))`
- This ensures bindings always match your current kernel

**Required types:**
Currently, the build script generates bindings for:
- `file`: For file access control LSM hooks
- `path`: For file path operations

**Adding new types:**
If you need additional kernel types, update `mori-bpf/build.rs`:
```bash
# Add new type to the generate command
.args(["generate", "file", "path", "your_new_type"])
```

**Usage in eBPF code:**
```rust
mod vmlinux {
    include!(concat!(env!("OUT_DIR"), "/vmlinux.rs"));
}

use vmlinux::{file, path};

// Access kernel structures with type safety
let file_ptr = unsafe { ctx.arg::<*const file>(0) };
let path_ptr = unsafe { &(*file_ptr).f_path as *const path };
```

### Compiling eBPF Programs

eBPF programs are automatically compiled when building the main project.
To compile them separately:

```bash
cd mori-bpf
cargo +nightly build --release --target bpfel-unknown-none
```

### Debugging eBPF Programs

#### Using bpf_printk (eBPF side)

```rust
use aya_ebpf::macros::map;
use aya_ebpf::helpers::bpf_printk;

bpf_printk!(b"Debug message: value=%d", value);
```

View output:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

#### Using aya-log (Recommended)

```rust
use aya_log_ebpf::info;

info!(ctx, "Path blocked: {}", path);
```

User-space logger:
```rust
use aya_log::BpfLogger;

BpfLogger::init(&mut bpf).unwrap();
```

### Verifier Errors

If you encounter eBPF verifier errors:

1. Check the verifier log in the error message
2. Ensure loops have compile-time known bounds
3. Avoid variable-offset array access
4. Keep stack usage under 512 bytes
5. Limit instruction count (1M instructions max)

Common fixes:
- Use fixed-size loops: `for i in 0..CONST_SIZE`
- Use conditional writes instead of variable offsets: `if i >= offset { array[i] = value }`
- Split complex programs into smaller helper functions

## Running mori

### Network Control

```bash
# Allow specific domains
sudo ./target/release/mori --allow-network example.com -- curl https://example.com

# Allow all network access
sudo ./target/release/mori --allow-network-all -- curl https://example.com
```

### File Access Control

```bash
# Deny read access to a file
sudo ./target/release/mori --deny-file-read /etc/shadow -- cat /etc/shadow

# Deny write access
sudo ./target/release/mori --deny-file-write /tmp/test.txt -- touch /tmp/test.txt

# Deny both read and write
sudo ./target/release/mori --deny-file /etc/hosts -- cat /etc/hosts
```

### Using Config File

```bash
# Create config.toml
cat > config.toml <<EOF
[network]
allow = ["example.com", "192.0.2.1"]

[file]
deny_read = ["/etc/shadow", "/home/user/.ssh"]
EOF

# Run with config
sudo ./target/release/mori --config config.toml -- bash
```

## Resources

### eBPF Learning Resources

- [eBPF Documentation](https://ebpf.io/)
- [BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
- [Aya Book](https://aya-rs.dev/book/)
- [Linux BPF LSM Documentation](https://www.kernel.org/doc/html/latest/bpf/prog_lsm.html)

### Kernel Documentation

- [cgroup v2 Documentation](https://www.kernel.org/doc/Documentation/cgroup-v2.txt)
- [Linux Security Modules](https://www.kernel.org/doc/html/latest/security/lsm.html)

## Troubleshooting

### Permission Denied Errors

On Linux, mori requires root privileges to:
- Load eBPF programs (CAP_BPF, CAP_SYS_ADMIN)
- Create and manage cgroups (CAP_SYS_ADMIN)
- Attach LSM hooks (CAP_BPF, CAP_NET_ADMIN)

Always run with `sudo`:
```bash
sudo ./target/release/mori --allow-network example.com -- curl https://example.com
```

### cgroup Not Found Errors

Ensure cgroup v2 is mounted:
```bash
# Check if cgroup v2 is mounted
mount | grep cgroup2

# If not mounted, mount it
sudo mount -t cgroup2 none /sys/fs/cgroup
```

## License

mori is dual-licensed under the MIT License and GPL-2.0 License. See [LICENSE-MIT](../LICENSE-MIT) and [LICENSE-GPL](../LICENSE-GPL) for details.
