# Code Style and Conventions

## General Style
- **Rust Edition**: 2024
- **Formatting**: Use `cargo fmt` (rustfmt)
- **Linting**: Use `cargo clippy` for static analysis
- **Error Handling**: Use `thiserror` for custom error types
- **Async**: Use `tokio` async runtime with `async-trait` for trait implementations

## Naming Conventions
- **Modules**: snake_case (e.g., `net`, `runtime`, `cli`)
- **Structs/Enums**: PascalCase (e.g., `NetworkPolicy`, `FilePolicy`)
- **Functions**: snake_case (e.g., `execute_with_network_control`)
- **Constants**: SCREAMING_SNAKE_CASE

## Code Organization
- **Modular separation**: Each policy type has its own module (network, file, process)
- **OS-specific code**: Conditional compilation with `#[cfg(target_os = "...")]`
- **Platform-specific modules**: Separate files for Linux and macOS implementations
- **Common models**: Shared definitions in `policy/model.rs`

## Testing
- **Test framework**: Use `rstest` for parameterized tests
- **Mocking**: Use `mockall` for mock objects
- **Test placement**: Tests can be in separate test files or inline with `#[cfg(test)]`
- **Documentation tests**: Include examples in doc comments

## Error Handling
- Use `Result<T, E>` for fallible operations
- Define custom error types in `error.rs` using `thiserror`
- Propagate errors with `?` operator

## Comments and Documentation
- **Public APIs**: Document all public functions, structs, and modules with `///` comments
- **Inline comments**: Use `//` for explanatory comments within code
- **TODO comments**: Mark unimplemented features with comments referencing roadmap

## Dependencies
- Pin dependencies to specific versions in `Cargo.toml`
- Use features flags to enable optional functionality (e.g., tokio features)
- Separate dev-dependencies from regular dependencies
