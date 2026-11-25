o/\.

# TURTL: Trusted Uniform Rust Toolkit for Lattice-cryptography

A pure-Rust implementation of NIST's post-quantum standards: **ML-KEM** (FIPS 203) and
**ML-DSA** (FIPS 204).

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![CI](https://github.com/larchey/turtl/actions/workflows/ci.yml/badge.svg)](https://github.com/larchey/turtl/actions/workflows/ci.yml)
[![Adversarial](https://github.com/larchey/turtl/actions/workflows/adversarial.yml/badge.svg)](https://github.com/larchey/turtl/actions/workflows/adversarial.yml)

## Features

- ML-KEM-512 / 768 / 1024 and ML-DSA-44 / 65 / 87
- Byte-for-byte agreement with the `fips203`/`fips204` reference crates (keygen, deterministic
  encapsulation and signing), plus two-way interoperability tests
- Pure and pre-hash (HashML-DSA) signing, hedged or deterministic, with context strings
- FIPS 203 key input checks; ML-DSA private keys are range-checked
- Branch-free, division-free arithmetic on secret data, checked by timing-leakage tests
- Secrets (keys, shared secrets, seeds, intermediates) are zeroized on drop; secret types
  redact their `Debug` output
- Continuous adversarial testing: differential fuzzing against the reference implementations
  ([ADVERSARIAL.md](ADVERSARIAL.md))
- `#![forbid(unsafe_code)]`

## Security

See [SECURITY.md](SECURITY.md) for the assurance evidence, the limitations (turtl has not yet had
an independent audit, and it has no power/EM countermeasures), and how to report a vulnerability.

## Installation

turtl is not on crates.io yet; depend on it from git:

```toml
[dependencies]
turtl = { git = "https://github.com/larchey/turtl" }
```

## Quick Examples

### Key Encapsulation (ML-KEM)

```rust
use turtl::kem::{decapsulate, encapsulate, shell::Shell, KeyPair, ParameterSet};

fn main() -> turtl::Result<()> {
    // Receiver generates a keypair and publishes the public key.
    let keypair = KeyPair::generate(ParameterSet::MlKem768)?;

    // Sender encapsulates a fresh shared secret.
    let (ciphertext, sender_secret) = encapsulate(&keypair.public_key())?;

    // Receiver decapsulates it.
    let receiver_secret = decapsulate(&keypair.private_key(), &ciphertext)?;
    assert_eq!(sender_secret, receiver_secret);

    // Derive purpose-specific keys from the shared secret.
    let shell = Shell::new(receiver_secret);
    let _encryption_key = shell.derive_encryption_key();
    let _authentication_key = shell.derive_authentication_key();
    Ok(())
}
```

### Digital Signatures (ML-DSA)

```rust
use turtl::dsa::{sign, stamp::Stamp, verify, KeyPair, ParameterSet, SigningMode};

fn main() -> turtl::Result<()> {
    let keypair = KeyPair::generate(ParameterSet::MlDsa65)?;

    let message = b"This is a test message";
    let context = b""; // optional domain-separation string, at most 255 bytes
    let signature = sign(&keypair.private_key(), message, context, SigningMode::Hedged)?;
    assert!(verify(&keypair.public_key(), message, &signature, context)?);

    // Or use the Stamp convenience wrapper.
    let stamp = Stamp::new(keypair.private_key());
    let signature = stamp.stamp_document(message)?;
    assert!(verify(&keypair.public_key(), message, &signature, b"")?);
    Ok(())
}
```

More complete programs live in [`examples/`](examples/README.md).

## Parameter Sets

### ML-KEM

| Parameter Set | Security Category | Public Key | Private Key | Ciphertext | Shared Secret |
|---------------|-------------------|------------|-------------|------------|---------------|
| ML-KEM-512    | 1                 | 800 B      | 1632 B      | 768 B      | 32 B          |
| ML-KEM-768    | 3                 | 1184 B     | 2400 B      | 1088 B     | 32 B          |
| ML-KEM-1024   | 5                 | 1568 B     | 3168 B      | 1568 B     | 32 B          |

### ML-DSA

| Parameter Set | Security Category | Public Key | Private Key | Signature |
|---------------|-------------------|------------|-------------|-----------|
| ML-DSA-44     | 2                 | 1312 B     | 2560 B      | 2420 B    |
| ML-DSA-65     | 3                 | 1952 B     | 4032 B      | 3309 B    |
| ML-DSA-87     | 5                 | 2592 B     | 4896 B      | 4627 B    |

## Project Layout

```text
src/
├── lib.rs
├── error.rs
├── kem/            ML-KEM (FIPS 203): keys, encaps/decaps, Shell KDF helper
│   └── internal/   K-PKE and the *_internal algorithms
├── dsa/            ML-DSA (FIPS 204): keys, sign/verify, Stamp helper
│   └── internal/   KeyGen/Sign/Verify internals, encodings, sampling
├── common/         NTT, polynomial arithmetic, constant-time reduction, SHA-3/SHAKE
└── security/       constant-time helpers
tests/              KAT, interop, negative, adversarial and timing tests
fuzz/               libFuzzer targets (differential, vs. the reference crates)
benches/            criterion benchmarks
examples/           runnable usage examples
docs/               implementation notes and the FIPS 203/204 PDFs
```

## Development

```sh
cargo test --release      # full suite, including reference interop and KATs
cargo clippy --all-targets -- -D warnings
cargo bench
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
