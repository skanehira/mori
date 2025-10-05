# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Build & Run
```bash
# Build (requires bpf-linker and nightly toolchain on Linux)
cargo build

# Release build
cargo build --release

# Run example (requires root on Linux for eBPF/cgroup)
sudo cargo run -- --allow-network example.com -- curl https://example.com
```

### Testing
```bash
# Run all tests
cargo test

# Fast test execution with cargo-nextest (recommended)
cargo nextest run

# Run a single test
cargo test test_name

# Run E2E tests (automatically detects platform)
./tests/e2e/run_tests.sh

# Run specific E2E test suite
./tests/e2e/test_network_linux.sh      # Linux network tests (requires sudo)
./tests/e2e/test_network_macos.sh      # macOS network tests (requires sudo)
./tests/e2e/test_file_access.sh        # File access tests (requires sudo)

# Generate coverage (requires cargo-llvm-cov)
cargo llvm-cov nextest --lcov --output-path lcov.info
```

### Quality Checks
```bash
# Format check
cargo fmt -- --check

# Apply formatting
cargo fmt

# Static analysis with Clippy
cargo clippy
```

### Linux-specific Requirements
```bash
# Install BPF tools (Ubuntu/Debian)
sudo apt-get install -y libbpf-dev linux-tools-common linux-tools-$(uname -r)

# Install nightly toolchain with BPF target
rustup toolchain install nightly-x86_64-unknown-linux-gnu --profile minimal --component rust-src

# Install bpf-linker
cargo install bpf-linker
```

## Architecture

### Overview
mori is a security sandbox tool that controls network and file access for processes using:
- **Linux**: eBPF + cgroup v2 for network control, LSM for file I/O
- **macOS**: sandbox-exec (Sandbox Profile Language) for network and file control

### Key Components

#### Entry Point (src/main.rs)
- Async main function using `tokio::main`
- Parses CLI args with clap, loads policy via `PolicyLoader`
- Delegates to `runtime::execute_with_network_control`

#### CLI Layer (src/cli/)
- `args.rs`: clap-based CLI argument parsing (`--allow-network`, `--config`)
- `config.rs`: TOML configuration file support
- `loader.rs`: Merges CLI flags and config file into unified `NetworkPolicy`

#### Policy Layer (src/policy/)
- `model.rs`: Core `Policy` and `NetworkPolicy` structures
- `net.rs`: Network policy with `AllowPolicy` enum (All or specific entries)
- `file.rs`, `process.rs`: File and process policies (future use)

#### Runtime Layer (src/runtime/)
- `linux/mod.rs`: Main execution logic for Linux
  - Creates cgroup in `/sys/fs/cgroup/mori-{pid}`
  - Loads and attaches eBPF programs (connect4, file_open) to cgroup
  - Resolves domain names to IPv4 addresses using Hickory DNS
  - Spawns async refresh task for TTL-based DNS updates
  - Manages child process lifecycle and shutdown
- `linux/ebpf.rs`: eBPF program loading and map management
  - Network control: ALLOW_V4 HashMap (stores allowed IPs)
  - CIDR support: Expands CIDR ranges to individual IPs in ALLOW_V4
- `linux/file.rs`: File access control using LSM
  - TARGET_CGROUP map: Filters events by cgroup ID
  - DENY_PATHS map: Stores denied paths with access modes (read/write)
  - file_open LSM hook: Intercepts file open operations
- `linux/cgroup.rs`: Cgroup creation and process attachment
- `linux/dns.rs`: DNS resolution and periodic refresh logic
- `linux/sync.rs`: Shutdown signaling with tokio::sync::Notify
- `macos.rs`: macOS implementation using sandbox-exec
  - Generates Sandbox Profile Language (SBPL) dynamically
  - Supports network deny-all and file access control
  - Note: No domain-based filtering (only allow-all or deny-all)

#### Network Layer (src/net/)
- `resolver.rs`: DNS resolver trait and system implementation using hickory-resolver
- `cache.rs`: DNS cache with TTL tracking and change detection
- `parser.rs`: Parsing network targets (FQDN, IPv4, CIDR)

#### eBPF Programs (mori-bpf/)
- Separate workspace member for eBPF code
- `src/main.rs`: eBPF programs written with aya-bpf
- **Network control hooks**:
  - `connect4` (cgroup_sock_addr): Intercepts IPv4 TCP connections
  - `ALLOW_V4` HashMap: Stores allowed IPv4 addresses (key: u32 IP, value: u8 marker)
  - CIDR ranges are expanded to individual IPs and stored in ALLOW_V4
- **File control hooks**:
  - `file_open` (LSM): Intercepts file open operations (sleepable hook)
  - `TARGET_CGROUP` HashMap: Stores target cgroup ID for filtering
  - `DENY_PATHS` HashMap: Stores denied file paths with access modes
  - `PATH_SCRATCH` PerCpuArray: Scratch buffer for path resolution (avoids stack limits)
- Compiled to BPF ELF via `build.rs` and embedded into main binary using `include_bytes_aligned!`

### Data Flow

#### Network Control (Linux)
1. CLI args + config file → `PolicyLoader` → `NetworkPolicy`
2. `NetworkPolicy` contains allowed IPv4 addresses, CIDR ranges, and domain names
3. Domain names resolved to IPv4 via hickory-resolver (async)
4. DNS cache tracks TTL and schedules re-resolution
5. Direct IPs and CIDR-expanded IPs inserted into eBPF ALLOW_V4 map
6. Child process spawned and added to cgroup
7. eBPF connect4 hook checks destination IP against ALLOW_V4 map
8. Async refresh task monitors DNS TTL and updates map on IP changes
9. On child exit, shutdown signal stops refresh task

#### File Control (Linux)
1. Denied paths with access modes inserted into eBPF DENY_PATHS map
2. Target cgroup ID inserted into TARGET_CGROUP map
3. eBPF file_open LSM hook intercepts all file open operations
4. Hook filters by cgroup ID using TARGET_CGROUP map
5. Hook checks file path against DENY_PATHS map and access mode (read/write)
6. Access denied if path matches and access mode is restricted

#### macOS (sandbox-exec)
1. Policy converted to Sandbox Profile Language (SBPL)
2. Network: Only deny-all supported (no domain-based filtering)
3. File: Deny rules for specific paths with read/write modes
4. Child process launched with `sandbox-exec -p <profile> <command>`

### Build System
- `build.rs`: Uses `aya_build::build_ebpf` to compile mori-bpf on Linux
- Handles RUSTFLAGS clearing to avoid coverage flags breaking eBPF compilation
- Embeds BPF ELF at compile time (single binary distribution)
- Skips eBPF compilation on non-Linux targets

### Async Runtime
- Uses tokio for async DNS resolution and periodic refresh
- `hickory-resolver` provides async DNS client
- `tokio::spawn` for background DNS refresh task
- `tokio::select!` for shutdown coordination

### Current Limitations

#### Linux
- **IPv4 only**: IPv6 support (connect6) not yet implemented
- **TCP only**: UDP/ICMP not supported
- **No port filtering**: All ports allowed if IP matches
- **CIDR restrictions**: Only /24 or higher prefix (max 256 addresses) for security
- **Root required**: Needs CAP_BPF + CAP_NET_ADMIN for eBPF and CAP_SYS_ADMIN for cgroup
- **cgroup v2 required**: Unified hierarchy at `/sys/fs/cgroup`
- **LSM required**: Kernel must support BPF LSM (CONFIG_BPF_LSM=y)

#### macOS
- **Network**: Only allow-all or deny-all (no domain/IP-based filtering)
- **File**: Deny-list only (no allow-list mode)
- **sandbox-exec required**: Must be available on the system

### Design Documents
Detailed architecture and design in Japanese:
- `docs/design.md`: Overall design and implementation details
- `docs/cli_architecture.md`: CLI layer and policy loading flow
- `docs/ebpf_cgroup_architecture.md`: eBPF and cgroup integration
- `docs/roadmap.md`: Feature roadmap and future plans

### CI/CD
- **ci.yaml**: Multi-OS CI (Ubuntu, macOS)
  - Format check, Clippy, build, unit tests, E2E tests
  - Linux: Installs BPF tools, generates coverage with cargo-llvm-cov
  - macOS: Runs unit and E2E tests (no eBPF build)
  - Uses reviewdog for PR feedback
- **audit.yaml**: Dependency security audits
- **release.yaml**: Automated releases on tag push

### Key Settings
- **Rust version**: Fixed to 1.90 in `rust-toolchain.toml`
- **Edition**: Rust 2024
- **Test tools**: cargo-nextest and cargo-llvm-cov recommended