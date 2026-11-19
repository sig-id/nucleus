# Contributing to Nucleus

Thank you for your interest in contributing to Nucleus!

## Development Setup

### Prerequisites

- Rust 1.100 or later (the repository pins 1.100.0)
- Linux kernel 5.x+ (required for cgroups v2, namespaces)
- (Optional) Apalache for running TLA+ model checking tests
- (Optional) Nix for reproducible development environment

### Getting Started

```bash
# Clone the repository
git clone https://github.com/wiggum-cc/nucleus
cd nucleus

# Option 1: Use Nix (recommended)
nix develop

# Option 2: Use cargo directly
cargo build

# Run tests
cargo test

# Run examples (requires root)
sudo cargo run --example simple_container
```

## Spec-Driven Development

Nucleus follows a spec-first approach:

1. **Write Intent specs** in `intent/` directory
2. **Compile to TLA+** using Intent compiler
3. **Verify with Apalache** model checker
4. **Implement in Rust** matching verified state machines
5. **Test with tla-connect** to ensure implementation matches spec

### Example Workflow

```bash
# 1. Write Intent specification
edit intent/my_feature.intent

# 2. Compile to TLA+
intent compile intent/my_feature.intent

# 3. Verify with Apalache
apalache-mc check formal/tla/MyFeature.tla

# 4. Implement in Rust
edit src/my_feature.rs

# 5. Add tla-connect tests
edit tests/tla_my_feature.rs

# 6. Run tests
cargo test
```

## Code Style

- Follow Rust standard formatting: `cargo fmt`
- Pass Clippy lints: `cargo clippy`
- Add documentation for public APIs
- Include tests for new functionality

## Testing Requirements

All new features must include:

1. **Unit tests**: Test individual functions and methods
2. **Property tests**: Verify state machine properties from TLA+ specs
3. **tla-connect tests**: Implement Driver for trace replay
4. **Documentation**: Update relevant docs

### Running Tests

```bash
# Unit and property tests
cargo test

# With Apalache installed
cargo test -- --include-ignored

# Specific module
cargo test --test tla_security

# Integration tests (requires root)
sudo cargo test --test integration_lifecycle
```

## State Machine Guidelines

When adding new state machines:

1. **Define states clearly**: Each state should have a clear meaning
2. **Document transitions**: Explain when and why transitions occur
3. **Verify properties**: Define temporal properties in TLA+
4. **Test exhaustively**: Test all valid and invalid transitions

Example state machine structure:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MyState {
    Initial,
    Processing,
    Complete,
}

impl MyState {
    pub fn can_transition_to(&self, next: MyState) -> bool {
        use MyState::*;
        matches!(
            (self, next),
            (Initial, Processing)
                | (Processing, Complete)
                | /* stuttering steps */
        )
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, MyState::Complete)
    }
}
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes following the guidelines above
4. Add tests and documentation
5. Ensure all tests pass: `cargo test`
6. Format code: `cargo fmt`
7. Run Clippy: `cargo clippy`
8. Commit changes with descriptive messages
9. Push to your fork: `git push origin feature/my-feature`
10. Open a Pull Request

### Commit Message Format

```
<type>: <description>

<optional body>

Co-Authored-By: Your Name <email@example.com>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `style`, `chore`

Example:
```
feat: add user namespace support for rootless containers

Implements user namespace UID/GID mapping to enable running
containers without root privileges.

Closes #42
```

## Security

If you discover a security vulnerability:

1. **Do not** open a public issue
2. Email security details to the maintainers
3. Allow reasonable time for a fix before disclosure

## Releasing

1. Merge a release PR that bumps `Cargo.toml`/`Cargo.lock` and finalizes `CHANGELOG.md`.
2. Publish a GitHub release tagged `vX.Y.Z` on the merge commit. The release
   workflow reruns CI, checks the tag matches the crate version, and attaches
   the x86_64 and aarch64 binaries.
3. After the workflow passes, publish the crate manually from a clean checkout
   of the tag: `cargo publish --locked`.

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project (MIT OR Apache-2.0).

## Questions?

- Open an issue for bugs or feature requests
- Check existing issues before creating duplicates
- Be respectful and constructive in discussions

Thank you for contributing to Nucleus!
