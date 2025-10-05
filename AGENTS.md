# Repository Guidelines

## Project Structure & Module Organization
- `src/` houses the CLI entrypoint `main.rs` plus modules: `cli/` (argument parsing), `policy/` (access rules), `net/` (resolver/cache), and `runtime/` for OS backends. Linux orchestration sits under `runtime/linux/` (cgroups, DNS, eBPF), while `runtime/macos.rs` wraps sandbox-exec.
- `mori-bpf/` is the no_std workspace member with programs in `src/main.rs`; `build.rs` rebuilds and embeds the ELF automatically on Linux.
- `tests/e2e/` contains shell smoke/regression scripts; inline `mod tests` blocks live next to Rust modules for unit coverage.
- `docs/development_guide.md` documents environment requirements; review it before altering runtime behavior.
- `target/` is the build output cache and must stay untracked.

## Build, Test, and Development Commands
- `cargo check` – fast validation after edits.
- `cargo fmt && cargo clippy --all-targets --all-features` – enforce formatting and lints prior to review.
- `cargo nextest run` (or `make test`) – run the suite; `make test` also runs doc tests.
- `cargo test` – quick fallback when iterating locally.
- `cargo build --release` or `make build` – produce optimized binaries and refresh the embedded eBPF object.
- `sudo target/release/mori --allow-network www.google.com -- curl https://www.google.com` – Linux smoke test requiring CAP_BPF and cgroup v2.

## Coding Style & Naming Conventions
- Use `rustfmt` defaults (4-space indent, snake_case functions, UpperCamelCase types) and keep module namespaces aligned (`runtime::linux`, `policy::*`, `net::*`).
- eBPF maps/programs in `mori-bpf` define explicit SCREAMING_SNAKE_CASE identifiers with `#[map]` attributes.
- Keep comments focused on intent or kernel constraints, not line-by-line narration.

## Testing Guidelines
- Add unit tests beside implementations via `mod tests`, reusing `rstest` and `mockall` patterns.
- Run `cargo nextest run` and `cargo test --doc` before pushing; document manual steps when using `tests/e2e/run_tests.sh` or custom cgroup experiments.
- Target regression coverage for policy parsing, resolver caching, and runtime error paths whenever bugs are fixed.

## Commit & Pull Request Guidelines
- Write imperative commit subjects (e.g., `Add ICMP deny policy`) and reference docs such as `docs/development_guide.md` when behavior changes.
- PR summaries should capture intent, list executed commands (`cargo check`, `cargo nextest run`, smoke tests), link issues, and flag security or permission impacts.
- Ensure `git status` is clean aside from intentional edits; never stage `target/` or generated artifacts.

## Security & Environment Notes
- Linux development targets kernel 5.10+ with cgroup v2, `CONFIG_BPF_LSM=y`, and capabilities CAP_BPF, CAP_SYS_ADMIN, CAP_NET_ADMIN; macOS logic is maintained separately.
- Treat `/sys/fs/cgroup/mori-*` directories as ephemeral and use `/tmp` for logs.
