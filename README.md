o/\.

# TURTL: Trusted Uniform Rust Toolkit for Lattice-cryptography

A secure, efficient implementation of NIST's post-quantum cryptographic standards in Rust.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

## Overview

TURTL is a pure Rust implementation of NIST's post-quantum cryptographic standards, focusing on ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism, FIPS 203) and ML-DSA (Module-Lattice-Based Digital Signature Algorithm, FIPS 204). 

This library provides post-quantum cryptographic primitives that are resistant to attacks from quantum computers, while maintaining high performance and ease of use.

## Features

- **Complete ML-KEM Implementation** - All parameter sets (512, 768, 1024)
- **Complete ML-DSA Implementation** - All parameter sets (44, 65, 87)
- **No Unsafe Code** - 100% safe Rust with zero unsafe blocks
- **Constant-Time Operations** - Resistant to timing side-channel attacks
- **Optional no_std Support** - For embedded platforms and WebAssembly
- **Simple API** - Easy to use for both beginners and experts
- **Zeroizing Memory** - Sensitive data is automatically cleared from memory
- **NIST Standards Compliant** - Fully compliant with FIPS 203 and FIPS 204

## Installation

Add TURTL to your Rust project by adding this to your `Cargo.toml`:

```toml
[dependencies]
turtl = "0.1.0"
```

## Quick Examples

### Key Encapsulation (ML-KEM)

```rust
use turtl::kem::{KeyPair, ParameterSet};
use turtl::error::Result;

fn main() -> Result<()> {
    // Generate a keypair
    let keypair = KeyPair::generate(ParameterSet::ML_KEM_768)?;
    
    // Encapsulate (create a shared secret)
    let (ciphertext, shared_secret) = turtl::kem::encapsulate(&keypair.public_key())?;
    
    // Decapsulate (recover the shared secret)
    let decapsulated_secret = turtl::kem::decapsulate(&keypair.private_key(), &ciphertext)?;
    
    // Both parties now have the same shared secret
    assert_eq!(shared_secret, decapsulated_secret);
    
    // You can derive keys for other cryptographic algorithms
    let shell = turtl::kem::shell::Shell::new(shared_secret);
    let encryption_key = shell.derive_encryption_key();
    let authentication_key = shell.derive_authentication_key();
    
    Ok(())
}
```

### Digital Signatures (ML-DSA)

```rust
use turtl::dsa::{KeyPair, ParameterSet, SigningMode};
use turtl::error::Result;

fn main() -> Result<()> {
    // Generate a keypair
    let keypair = KeyPair::generate(ParameterSet::ML_DSA_65)?;
    
    // Sign a message
    let message = b"This is a test message";
    let context = b"";  // Optional context
    let signature = turtl::dsa::sign(
        &keypair.private_key(), 
        message, 
        context, 
        SigningMode::Hedged
    )?;
    
    // Verify a signature
    let is_valid = turtl::dsa::verify(
        &keypair.public_key(), 
        message, 
        &signature, 
        context
    )?;
    
    assert!(is_valid);
    
    // Or use the high-level Stamp API for convenience
    let stamp = turtl::dsa::stamp::Stamp::new(keypair.private_key());
    let signature = stamp.stamp_document(message)?;
    
    Ok(())
}
```

## Parameter Sets

### ML-KEM

| Parameter Set | Security Category | Public Key Size | Private Key Size | Ciphertext Size | Shared Secret Size |
|---------------|-------------------|-----------------|------------------|-----------------|-------------------|
| ML-KEM-512    | Category 1        | 800 bytes       | 1632 bytes       | 768 bytes       | 32 bytes          |
| ML-KEM-768    | Category 3        | 1184 bytes      | 2400 bytes       | 1088 bytes      | 32 bytes          |
| ML-KEM-1024   | Category 5        | 1568 bytes      | 3168 bytes       | 1568 bytes      | 32 bytes          |

### ML-DSA

| Parameter Set | Security Category | Public Key Size | Private Key Size | Signature Size |
|---------------|-------------------|-----------------|------------------|---------------|
| ML-DSA-44     | Category 2        | 1312 bytes      | 2560 bytes       | 2420 bytes    |
| ML-DSA-65     | Category 3        | 1952 bytes      | 4032 bytes       | 3309 bytes    |
| ML-DSA-87     | Category 5        | 2592 bytes      | 4896 bytes       | 4627 bytes    |

## Security Features

TURTL is designed with security as a primary goal:

- **Constant-Time Operations**: All cryptographic operations are implemented to run in constant time to prevent timing attacks.
- **Memory Safety**: All sensitive data (private keys, shared secrets) is automatically zeroized when dropped.
- **Input Validation**: All inputs are strictly validated to prevent invalid data from being processed.
- **Test Vectors**: Comprehensive test vectors from the NIST standards ensure correctness.
- **No Unsafe Code**: The entire codebase uses 100% safe Rust.

## Feature Flags

- `std` (default): Enables standard library features
- `nightly`: Enables performance optimizations available only on nightly Rust
- Use `default-features = false` for no_std compatibility

## Documentation

For more detailed documentation, run:

```
cargo doc --open
```

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Disclaimer

This implementation has not been audited for production use. While we strive to follow the NIST standards precisely, this library should be thoroughly reviewed before use in security-critical applications.
```


turtl/
├── src/
│   ├── lib.rs                # Library entry point and exports
│   ├── kem/                  # ML-KEM implementation (FIPS 203)
│   │   ├── mod.rs            # Module definition and public API
│   │   ├── params.rs         # Parameter sets (512, 768, 1024)
│   │   ├── keypair.rs        # Key generation and management
│   │   ├── encapsulate.rs    # Encapsulation algorithm
│   │   ├── decapsulate.rs    # Decapsulation algorithm
│   │   ├── shell.rs          # Key derivation utilities
│   │   └── internal/         # Internal implementation details
│   │       ├── mod.rs
│   │       ├── k_pke.rs      # PKE component
│   │       └── aux.rs        # Auxiliary functions
│   ├── dsa/                  # ML-DSA implementation (FIPS 204)
│   │   ├── mod.rs            # Module definition and public API
│   │   ├── params.rs         # Parameter sets (44, 65, 87)
│   │   ├── keypair.rs        # Key generation and management
│   │   ├── sign.rs           # Signing algorithms
│   │   ├── verify.rs         # Verification algorithms
│   │   ├── stamp.rs          # High-level signing utilities
│   │   └── internal/         # Internal implementation details
│   │       ├── mod.rs
│   │       └── aux.rs        # Auxiliary functions
│   ├── common/               # Shared functionality
│   │   ├── mod.rs            # Module definition
│   │   ├── ntt.rs            # Number-Theoretic Transform
│   │   ├── poly.rs           # Polynomial operations
│   │   ├── ring.rs           # Ring arithmetic
│   │   ├── sample.rs         # Random sampling functions
│   │   ├── coding.rs         # Encoding/decoding functions
│   │   └── hash.rs           # Hash function wrappers
│   └── error.rs              # Error handling
├── examples/                 # Usage examples
│   ├── kem_example.rs        # Key encapsulation example
│   └── dsa_example.rs        # Digital signature example
├── benches/                  # Performance benchmarks
├── tests/                    # Integration tests
│   ├── kem_test_vectors.rs   # ML-KEM test vectors
│   └── dsa_test_vectors.rs   # ML-DSA test vectors
└── Cargo.toml                # Package manifest