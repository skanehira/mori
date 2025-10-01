# Task Completion Checklist

When completing a task, ensure the following steps are executed:

## 1. Code Quality
- [ ] Run `cargo fmt` to format code
- [ ] Run `cargo clippy` to check for linting issues
- [ ] Resolve all compiler warnings

## 2. Testing
- [ ] Run `cargo nextest run` to execute unit tests
- [ ] Run `cargo test --doc` to execute documentation tests
- [ ] Ensure all tests pass
- [ ] Add new tests for new functionality (if applicable)

## 3. Documentation
- [ ] Update inline documentation for modified functions/structs
- [ ] Update README.md if user-facing changes were made
- [ ] Update roadmap.md to mark completed TODOs (if applicable)

## 4. Build Verification
- [ ] Run `cargo build` to verify development build succeeds
- [ ] Run `cargo build --release` for production build verification

## 5. Manual Testing (if applicable)
- [ ] Test with `make run-allow` for allowed network scenario
- [ ] Test with `make run-deny` for denied network scenario
- [ ] Verify behavior on target OS (Linux or macOS)

## Complete Command Sequence
```bash
# Format and lint
cargo fmt
cargo clippy

# Test
cargo nextest run
cargo test --doc

# Build
cargo build --release
```

## Notes
- On Linux, many tests require sudo privileges due to cgroup/eBPF operations
- macOS implementation is currently a stub (returns Unsupported error)
- File I/O control is not yet implemented (placeholder only)
