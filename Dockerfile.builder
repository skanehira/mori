# Multi-platform eBPF build container for mori
# Supports: linux/amd64, linux/arm64

FROM rust:slim

# Install system dependencies for eBPF development
RUN apt-get update && apt-get install -y \
    # eBPF development tools
    libbpf-dev \
    linux-tools-common \
    linux-tools-generic \
    clang \
    llvm \
    # Build essentials
    pkg-config \
    libssl-dev \
    # Utilities
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Determine architecture and install appropriate nightly toolchain
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        RUST_TARGET="x86_64-unknown-linux-gnu"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        RUST_TARGET="aarch64-unknown-linux-gnu"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    rustup toolchain install nightly-${RUST_TARGET} --profile minimal --component rust-src

# Install Rust tools for eBPF development
RUN cargo install bpf-linker bindgen-cli && \
    cargo install --git https://github.com/aya-rs/aya -- aya-tool

# Install cargo-nextest for testing
RUN cargo install cargo-nextest --locked

# Set working directory
WORKDIR /workspace

# Default command
CMD ["/bin/bash"]
