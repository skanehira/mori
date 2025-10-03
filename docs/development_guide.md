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
grep CONFIG_BPF_LSM /boot/config-$(uname -r)

# Check if BPF is in LSM list
cat /sys/kernel/security/lsm
```

### Required Tools

#### Rust Toolchain

mori uses Rust 2024 edition with a fixed toolchain version.

```bash
# Install rustup if not already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# The project uses rust-toolchain.toml, so the correct version
# will be automatically installed when you build
```

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
cargo install aya-tool
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

#### Optional: Testing Tools

```bash
# cargo-nextest for fast test execution
cargo install cargo-nextest

# cargo-llvm-cov for code coverage
cargo install cargo-llvm-cov
```

## Building

### Standard Build

```bash
# Debug build
cargo build

# Release build
cargo build --release
```

The build process automatically:
1. Compiles eBPF programs in `mori-bpf/` using the nightly toolchain
2. Embeds the compiled eBPF bytecode into the main binary
3. Builds the userspace program

### Build Artifacts

- Userspace binary: `target/release/mori`
- eBPF ELF (intermediate): `target/bpfel-unknown-none/release/mori-bpf`

### Build Troubleshooting

#### Error: "bpf-linker not found"

```bash
cargo install bpf-linker
```

#### Error: "can't find crate for `core`"

```bash
rustup toolchain install nightly --component rust-src
```

#### Error: "failed to run custom build command"

Check that you have the required BPF development tools:
```bash
sudo apt-get install libbpf-dev linux-tools-$(uname -r)
```

## Testing

### Run All Tests

```bash
# Standard test runner
cargo test

# Faster test execution with nextest (recommended)
cargo nextest run
```

### Run Specific Tests

```bash
# Test a specific module
cargo test policy

# Test a specific function
cargo test test_policy_loader
```

### Integration Tests (Requires root)

Some tests require root privileges to load eBPF programs:

```bash
sudo -E cargo test --test integration_tests
```

### Code Coverage

```bash
# Generate coverage report
cargo llvm-cov nextest --lcov --output-path lcov.info

# View HTML report
cargo llvm-cov nextest --html
open target/llvm-cov/html/index.html
```

## Code Quality

### Formatting

```bash
# Check formatting
cargo fmt -- --check

# Apply formatting
cargo fmt
```

### Linting

```bash
# Run Clippy
cargo clippy

# Run Clippy with all features
cargo clippy --all-features
```

### Pre-commit Checks

Before committing, ensure:
```bash
cargo fmt -- --check && cargo clippy && cargo build && cargo test
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
sudo ./target/release/mori --deny-file-readwrite /etc/hosts -- cat /etc/hosts
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

## Project Structure

```
mori/
├── src/
│   ├── main.rs                 # Entry point
│   ├── cli/                    # CLI argument parsing
│   │   ├── args.rs            # clap definitions
│   │   ├── config.rs          # TOML config parsing
│   │   └── loader.rs          # Policy loading
│   ├── policy/                 # Policy models
│   │   ├── mod.rs
│   │   ├── net.rs             # Network policy
│   │   └── file.rs            # File policy
│   ├── net/                    # Network utilities
│   │   ├── resolver.rs        # DNS resolution
│   │   ├── cache.rs           # DNS cache
│   │   └── parser.rs          # Target parsing
│   ├── runtime/                # Execution runtime
│   │   ├── mod.rs
│   │   └── linux/             # Linux-specific implementation
│   │       ├── mod.rs         # Main execution logic
│   │       ├── ebpf.rs        # Network eBPF loader
│   │       ├── file.rs        # File eBPF loader
│   │       ├── cgroup.rs      # cgroup management
│   │       ├── dns.rs         # DNS refresh task
│   │       └── sync.rs        # Shutdown coordination
│   └── error.rs                # Error types
├── mori-bpf/                   # eBPF programs (separate workspace)
│   ├── src/
│   │   └── main.rs            # eBPF hooks
│   ├── Cargo.toml
│   └── build.rs               # Auto-generates vmlinux.rs
├── docs/                       # Documentation
├── tests/                      # Integration tests
└── Cargo.toml                  # Workspace manifest
```

## Contributing

### Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make changes following the coding standards
4. Run tests: `cargo nextest run`
5. Run quality checks: `cargo fmt && cargo clippy`
7. Push and create a pull request

### Coding Standards

- Follow Rust API Guidelines
- Use meaningful variable and function names
- Add documentation comments for public APIs
- Keep functions small and focused
- Prefer explicit error handling over unwrap/expect
- Use `Result` for fallible operations
- Avoid type casts (`as`) when possible

## Resources

### eBPF Learning Resources

- [eBPF Documentation](https://ebpf.io/)
- [BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
- [Aya Book](https://aya-rs.dev/book/)
- [Linux BPF LSM Documentation](https://www.kernel.org/doc/html/latest/bpf/prog_lsm.html)

### Kernel Documentation

- [cgroup v2 Documentation](https://www.kernel.org/doc/Documentation/cgroup-v2.txt)
- [Linux Security Modules](https://www.kernel.org/doc/html/latest/security/lsm.html)

### Rust Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Cargo Book](https://doc.rust-lang.org/cargo/)

## Troubleshooting

### Permission Denied Errors

mori requires root privileges to:
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

### eBPF Program Load Failures

Check kernel configuration:
```bash
# Verify BPF LSM is enabled
cat /proc/config.gz | gunzip | grep CONFIG_BPF_LSM

# Or check boot config
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
```

If `CONFIG_BPF_LSM=n`, you need to recompile the kernel with LSM support.

## License

mori is licensed under the MIT License. See [LICENSE](../LICENSE) for details.
