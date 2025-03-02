# TURTL - Build, Test and Style Guide

## Build & Test Commands
```
# Run all tests
cargo test

# Run a specific test
cargo test test_name

# Run specific test file
cargo test --test error_handling_test

# Run all benchmarks
cargo bench

# Run a specific benchmark
cargo bench bench_name

# Run specific module tests
cargo test --package turtl --lib common::ntt::tests

# Run with release optimizations
cargo test --release
```

## Code Style Guidelines
- **Naming**: snake_case for functions/variables, PascalCase for types
- **Indentation**: 4 spaces (no tabs)
- **Documentation**: Use doc comments (///) for public items, module docs (//!)
- **Error handling**: Use Result<T> with ? operator, proper error propagation
- **Imports**: Group by std, external crates, then local modules
- **No unsafe code**: Maintain 100% safe Rust
- **Constant-time**: Use security::constant_time module for timing-attack resistance
- **Fault protection**: Use security::fault_detection for validating operations
- **Testing**: Unit tests in #[cfg(test)] modules, integration tests in /tests
- **Memory safety**: Use zeroize for sensitive data
- **Input validation**: Validate all public-facing inputs thoroughly

## Security Features
- Implement constant-time operations for all secret-dependent code
- Verify integrity of sensitive values with fault detection mechanisms
- Use secure random number generation for all cryptographic operations
- Maintain side-channel resistance in cryptographic implementations
- Include thorough boundary and error checking

## Features
- Use `default-features = false` for no_std compatibility
- Enable `nightly` feature for performance optimizations