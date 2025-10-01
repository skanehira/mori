# Suggested Commands

## Build Commands
```bash
# Development build
cargo build

# Release build
cargo build --release
# or
make build
```

## Testing Commands
```bash
# Run all tests with nextest (recommended)
cargo nextest run

# Run doc tests
cargo test --doc

# Run both
make test
```

## Quality Checks
```bash
# Format code
cargo fmt

# Check formatting
cargo fmt -- --check

# Run linter
cargo clippy
```

## Running the Application
```bash
# Allow network access to specific domain (requires sudo on Linux)
sudo ./target/release/mori --allow-network www.google.com -- ping -c 1 www.google.com
# or
make run-allow

# Deny all network access (requires sudo on Linux)
sudo ./target/release/mori -- ping -c 1 www.google.com
# or
make run-deny
```

## Coverage
```bash
# Generate coverage report (requires cargo-llvm-cov)
cargo llvm-cov nextest --lcov --output-path lcov.info
```

## System Commands (macOS)
Standard Unix commands are available:
- `ls` - list directory contents
- `cd` - change directory
- `grep` - search text patterns
- `find` - search for files
- `git` - version control
