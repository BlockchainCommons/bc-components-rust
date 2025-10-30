⚠️ NOTE: Reading this *entire* file is REQUIRED. Do a `wc -l <path>` to get the number of lines, then fetch the entire file.

# bc-components Guidelines

## Development Environment

### Build/Test Commands

```bash
# Build the crate
cargo build

# Run all tests
cargo test

# Run tests without doc tests
cargo test --all-targets

# Run specific tests with specific features
cargo test --lib --all-features -- module::tests::test_name --exact --show-output

# Run doctests
cargo test --doc
cargo test --doc --all-features -- module::sub_module::Item::test_name --show-output

# Check code quality
cargo clippy -- -D warnings

# Build documentation
cargo doc --no-deps --target-dir cargo-docs
```

### Development Guidelines

- **Production quality** - Write real-world production-quality code
- **Clean code** - Fix all compiler errors and Clippy lints
- **Security focus** - Cryptographic operations must adhere to best practices and be thoroughly tested

### Testing

- Don't mark tasks as complete until all tests pass
- Security-critical components require comprehensive test coverage

## Development Environment

### Build/Test Commands

```bash
# Build the crate
cargo build

# Run all tests
cargo test

# Run tests without doc tests
cargo test --all-targets

# Run specific tests with specific features
cargo test --lib --all-features -- module::tests::test_name --exact --show-output

# Run doctests
cargo test --doc
cargo test --doc --all-features -- module::sub_module::Item::test_name --show-output

# Check code quality
cargo clippy -- -D warnings

# Build documentation
cargo doc --no-deps --target-dir cargo-docs
```

### Development Guidelines

- **Production quality** - Write real-world production-quality code
- **Clean code** - Fix all compiler errors and Clippy lints
- **Security focus** - Cryptographic operations must adhere to best practices and be thoroughly tested

### Testing

- Don't mark tasks as complete until all tests pass
- Security-critical components require comprehensive test coverage

## Important Dependencies

### `dcbor` Repository

This repository relies on the `dcbor` crate for deterministic CBOR serialization, which is essential for the consistent representation of Gordian Envelopes.

#### Documentation Quality Criteria

- **Comprehensive**: All public API elements have documentation
- **Contextual**: Documentation explains both "what" and "why"
- **Practical**: Examples demonstrate real-world usage
- **Consistent**: Uniform style and detail level across the codebase
- **Accessible**: Explanations suitable for developers not familiar with Rust, and Rust engineers not familiar with Gordian Envelope
- **Searchable**: Proper cross-references and keyword usage
- **Validated**: Examples compile and work correctly

#### Documentation Testing Guidelines

- **Doc Example Best Practices:**
  - Use appropriate imports in examples, typically `use bc_envelope::prelude::*`
  - Handle errors properly in examples that return `Result`
  - Use `no_run` for examples that can't be directly compiled/run in doc tests. Do *NOT* use `no_run` as a crutch for tests that should be valid but aren't.
  - Use `ignore` for examples that are not meant to be run, but should still compile. This is useful for examples that are fragmentary or too complex to run in a doc test.
  - Check constructors for type initialization in examples - some types may lack `Default` implementation
  - For internal/implementation types that users shouldn't directly interact with, clearly mark them as such in the documentation
  - Before writing examples, refer to unit tests and the `tests/` module to understand how the types are used in practice.
  - In your examples, use `use bc_envelope::prelude::*;` to import all necessary types.
  - Show typical usage patterns for each type, not all possible ways to use it
  - For complex operations like encryption, signatures, and elision, include complete examples that demonstrate the full workflow
  - 🚨 **CRITICAL**: ALL trait implementations (`impl Trait for Type`) MUST have a single-line doc comment explaining the implementation's purpose

#### Required Quality Checks

🚨 **CRITICAL**: Always perform these quality checks with EVERY documentation task BEFORE considering it complete:

1. **Fix all doc tests**:
   ```bash
   # Run from the bc-envelope directory, not the workspace root
   cd /path/to/bc-envelope && cargo test --doc
   ```
   Ensure all doc tests pass, and fix any failures immediately.

2. **Fix all Clippy lints**:
   ```bash
   # Run from the bc-envelope directory, not the workspace root
   cd /path/to/bc-envelope && cargo clippy -- -D warnings
   ```
   Address any Clippy warnings introduced by documentation changes.

🔴 **MANDATORY**: YOU MUST RUN THESE CHECKS YOURSELF after making changes, without waiting to be prompted. Documentation is not complete until all tests pass. NEVER mark a task as complete without running and passing these checks.
