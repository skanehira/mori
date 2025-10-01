# Project Overview

## Purpose
mori (杜) is a cross-platform sandbox tool that provides network and file I/O control for Linux and macOS. The name "mori" (杜) means "shrine forest" in Japanese, symbolizing a protected domain isolated from the outside world.

## Goals (MVP)
- **Linux**: cgroup + eBPF for FQDN-based network control and Landlock for file I/O control
- **macOS**: sandbox-exec wrapper for network and file I/O control
- **Common CLI**: Unified allow-based flags and configuration file format for both OSes

## Tech Stack
- **Language**: Rust (Edition 2024, Toolchain 1.87)
- **CLI**: clap v4 with derive macros
- **Async Runtime**: tokio with multi-thread runtime
- **DNS Resolution**: hickory-resolver (for FQDN → IP resolution)
- **Linux-specific**: 
  - aya (eBPF library)
  - aya-log (eBPF logging)
  - Landlock (for file I/O control - planned)
- **Testing**: rstest, mockall, tempfile
- **Configuration**: YAML via serde + toml

## Architecture
- **Modular structure**:
  - `cli/`: Command-line argument parsing and config loading
  - `policy/`: Policy model definitions (network, file, process)
  - `net/`: Network-related utilities (DNS resolver, cache, parser)
  - `runtime/`: OS-specific runtime implementations
    - `runtime/linux/`: Linux implementation (cgroup, eBPF, DNS)
    - `runtime/macos.rs`: macOS implementation (sandbox-exec - not yet implemented)
  - `mori-bpf/`: eBPF programs for Linux

## Current Status
- Linux network control with eBPF is implemented
- macOS implementation returns Unsupported error (placeholder)
- File I/O control is placeholder only (FilePolicy struct exists but empty)
