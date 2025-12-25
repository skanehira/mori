# Docker Build Guide

This guide explains how to build mori using Docker containers, which helps avoid kernel version compatibility issues.

## Prerequisites

- Docker (with BuildKit support)
- Docker Buildx (for multi-platform builds)

## Quick Start

### Build the Builder Image

```bash
# Build for current platform (amd64 or arm64)
docker build -f Dockerfile.builder -t mori-builder:latest .

# Build for specific platform
docker build -f Dockerfile.builder --platform linux/amd64 -t mori-builder:amd64 .
docker build -f Dockerfile.builder --platform linux/arm64 -t mori-builder:arm64 .

# Build multi-platform image and push to registry
docker buildx build -f Dockerfile.builder \
  --platform linux/amd64,linux/arm64 \
  -t your-registry/mori-builder:latest \
  --push .
```

### Build mori Inside Container

```bash
# Start container with current directory mounted
docker run --rm -it \
  -v $(pwd):/workspace \
  mori-builder:latest

# Inside the container, build mori
cargo build --release

# Or run tests
cargo nextest run
```

### One-liner Build

```bash
# Build release binary
docker run --rm \
  -v $(pwd):/workspace \
  mori-builder:latest \
  cargo build --release

# The binary will be available at: target/release/mori
```

## Builder Image Details

### Base Image
- `rust:slim` - Debian-based slim Rust image (~700MB base)

### Installed Components

**System Packages:**
- `libbpf-dev` - eBPF library headers
- `linux-tools-common` - Linux kernel tools
- `linux-tools-generic` - Generic kernel tools
- `clang` - C compiler (required for eBPF)
- `llvm` - LLVM toolchain
- `pkg-config` - Package configuration tool
- `libssl-dev` - OpenSSL development files

**Rust Toolchains:**
- Stable toolchain (from base image)
- Nightly toolchain with `rust-src` component (architecture-specific)

**Cargo Tools:**
- `bpf-linker` - eBPF linker
- `bindgen-cli` - C bindings generator
- `aya-tool` - eBPF type generation tool
- `cargo-nextest` - Modern test runner

### Supported Platforms
- `linux/amd64` (x86_64)
- `linux/arm64` (aarch64)

The builder image automatically detects the target architecture and installs the appropriate nightly toolchain.

## Advanced Usage

### Custom Build Script

Create a `build.sh` script:

```bash
#!/bin/bash
set -e

docker run --rm \
  -v $(pwd):/workspace \
  mori-builder:latest \
  bash -c "cargo build --release && cargo nextest run"
```

### GitHub Actions Integration

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - name: Build builder image
        run: docker build -f Dockerfile.builder -t mori-builder:latest .

      - name: Build mori
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            mori-builder:latest \
            cargo build --release

      - name: Run tests
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            mori-builder:latest \
            cargo nextest run
```

### Running E2E Tests

E2E tests require privileged mode to load eBPF programs:

```bash
docker run --rm -it \
  --privileged \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -v $(pwd):/workspace \
  mori-builder:latest \
  bash -c "./tests/e2e/run_tests.sh"
```

## Troubleshooting

### Permission Issues

If you encounter permission issues with build artifacts:

```bash
# Run with your user ID
docker run --rm \
  -v $(pwd):/workspace \
  -u $(id -u):$(id -g) \
  mori-builder:latest \
  cargo build --release
```

### Cache Not Working

If incremental builds are slow, ensure the cargo cache is preserved:

```bash
docker run --rm \
  -v $(pwd):/workspace \
  -v cargo-cache:/usr/local/cargo/registry \
  mori-builder:latest \
  cargo build --release
```

### Platform-specific Issues

For cross-platform builds, use QEMU:

```bash
# Install QEMU
docker run --privileged --rm tonistiigi/binfmt --install all

# Build for different architecture
docker build -f Dockerfile.builder --platform linux/arm64 -t mori-builder:arm64 .
```

## Benefits of Container Builds

1. **Kernel Compatibility**: Build artifacts are compatible with the target kernel
2. **Reproducible**: Same build environment across different machines
3. **Isolated**: No need to install eBPF tools on host system
4. **Multi-platform**: Easy cross-compilation for amd64/arm64
5. **CI/CD Ready**: Integrates easily with GitHub Actions, GitLab CI, etc.

## Image Size Optimization

Current builder image size: ~2GB (includes all development tools)

For production deployments, consider:
1. Multi-stage builds to separate build and runtime environments
2. Using distroless or alpine base images for the final runtime image
3. Stripping debug symbols from binaries

See `Dockerfile` (if exists) for production runtime image configuration.
