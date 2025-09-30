# Repository Guidelines

## Project Structure & Module Organization
- `src/`: Rust CLI entrypoints and platform runtimes. Key files include `main.rs` for argument parsing and `runtime/linux.rs` for cgroup/eBPF orchestration.
- `mori-bpf/`: no_std sub-crate containing the `cgroup_sock_addr` eBPF programs (`src/main.rs`). Built automatically via `build.rs`.
- `docs/`: architectural notes, roadmap, and interface specifications. Consult `design.md` and `ebpf_cgroup_architecture.md` before making behavioral changes.
- `target/`: Cargo build artifacts. Generated files should never be committed.

## Build, Test, and Development Commands
- `cargo check`: Fast validation of host-side Rust code; run after every edit cycle.
- `cargo fmt && cargo clippy --all-targets --all-features`: Enforce formatting and linting before committing.
- `cargo test`: Execute the host-side unit test suite.
- `cargo build --release`: Produce distributable binaries and rebuild the embedded eBPF object via `build.rs`.
- `sudo target/release/mori --allow-network=example.com -- curl https://example.com`: Quick manual smoke test; requires CAP_BPF/CAP_SYS_ADMIN and a kernel with cgroup v2 + eBPF enabled.

## Coding Style & Naming Conventions
- Rust code follows standard `rustfmt` defaults (4-space indent, snake_case for items, UpperCamelCase for types).
- Keep module paths aligned with existing layout (`runtime::linux`, `policy::*`).
- eBPF programs stay in `mori-bpf` with explicit `#[map]` identifiers in SCREAMING_SNAKE_CASE.
- Prefer concise comments that explain intent, not implementation mechanics.

## Testing Guidelines
- Use `cargo test` for host logic. Place new tests alongside implementation modules using the `mod tests` pattern.
- Manual eBPF validation relies on attaching programs to a disposable cgroup; document reproduction steps in PR descriptions when adding kernel interactions.
- Aim for coverage of parsing, policy translation, and error paths. Add regression tests when fixing bugs.

## Commit & Pull Request Guidelines
- Write commits in the imperative mood (“Add Hickory resolver cache”) and keep scopes narrow.
- Reference related docs or issues in commit messages when behavior changes (e.g., “Refer doc/design.md for TTL policy”).
- PRs should include: summary of changes, testing evidence (`cargo check`, `cargo test`, manual sandbox runs if applicable), and any security or permission considerations.
- Request review when CI equivalents succeed and ensure no generated artifacts or `target/` files are staged.

## System & Security Notes
- Development requires Linux 5.13+ with cgroup v2 and CAP_BPF. macOS support is orchestrated separately; do not modify sandbox-exec logic in Linux-focused PRs.
- Treat `/sys/fs/cgroup/mori-*` directories as ephemeral; never rely on them for persistent state.
