# TURTL - Build, Test and Style Guide

## Commands
```
cargo test --release                                  # full suite (KATs, interop, adversarial)
cargo test --release --test fips_interop              # one test file
cargo clippy --all-targets -- -D warnings             # must be clean (CI enforces)
cargo fmt --check
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

# Adversarial (see ADVERSARIAL.md)
TURTL_ADV_ITERS=5000 cargo test --release --test adversarial
cargo test --release --test timing_leakage -- --ignored --test-threads=1 --nocapture
cd fuzz && cargo +nightly fuzz run kem_decaps          # needs a C++ compiler
```
The toolchain is pinned in `rust-toolchain.toml` so local clippy matches CI.

## Code rules
- 100% safe Rust (`#![forbid(unsafe_code)]`).
- No `%`, `/`, `rem_euclid` or branches on secret data: use `common::reduce::ct_mod` /
  `ct_normalize_small` and mask arithmetic. Public data (ciphertext parsing, `t1`, signatures
  being verified) may branch.
- Secret-holding types zeroize in `Drop` (a bare `impl ZeroizeOnDrop` does nothing); wrap
  temporary secret buffers in `zeroize::Zeroizing`; secret types must not derive `Debug`.
- Validate public inputs; `verify` returns `Ok(false)`, never `Err`, for a bad signature.
- After touching algorithm code, run `fips_interop`, `keygen_kat`, `det_kat` and `adversarial`.
- Doc comments on public items; snake_case / PascalCase; 4-space indentation.

## Status
See SECURITY.md for verified properties and remaining limitations.
