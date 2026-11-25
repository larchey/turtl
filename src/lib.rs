//! # TURTL: Trusted Uniform Rust Toolkit for Lattice-cryptography
//!
//! A Rust implementation of NIST's post-quantum cryptographic standards,
//! focusing on ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism, FIPS 203) and ML-DSA
//! (Module-Lattice-Based Digital Signature Algorithm, FIPS 204).
//!
//! ## Features
//!
//! * ML-KEM with all parameter sets (512, 768, 1024)
//! * ML-DSA with all parameter sets (44, 65, 87)
//! * FIPS 203/204 conformance is cross-checked against reference implementations:
//!   interoperability and byte-for-byte keygen KATs pass for every parameter set
//! * Private keys and shared secrets zeroize their buffers on drop
//! * Simple, developer-friendly API
//! * No `unsafe` code
//!
//! ## Security
//!
//! Secret-dependent arithmetic is branch-free and division-free, secrets are zeroized on drop,
//! and conformance is checked against reference implementations, including adversarial
//! differential fuzzing. See `SECURITY.md` for the evidence and the remaining limitations
//! (notably: no independent audit yet).
//!
//! ## Examples
//!
//! ### Key Encapsulation (ML-KEM)
//!
//! ```
//! use turtl::kem::{decapsulate, encapsulate, KeyPair, ParameterSet};
//!
//! # fn main() -> turtl::Result<()> {
//! let keypair = KeyPair::generate(ParameterSet::MlKem768)?;
//! let (ciphertext, sender_secret) = encapsulate(&keypair.public_key())?;
//! let receiver_secret = decapsulate(&keypair.private_key(), &ciphertext)?;
//! assert_eq!(sender_secret, receiver_secret);
//! # Ok(())
//! # }
//! ```
//!
//! ### Digital Signatures (ML-DSA)
//!
//! ```
//! use turtl::dsa::{sign, verify, KeyPair, ParameterSet, SigningMode};
//!
//! # fn main() -> turtl::Result<()> {
//! let keypair = KeyPair::generate(ParameterSet::MlDsa65)?;
//! let signature = sign(&keypair.private_key(), b"hello", b"", SigningMode::Hedged)?;
//! assert!(verify(&keypair.public_key(), b"hello", &signature, b"")?);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// Allow certain clippy lints that require extensive refactoring
#![allow(clippy::needless_range_loop)]
#![allow(clippy::type_complexity)]

// Public modules
pub mod dsa;
pub mod error;
pub mod kem;
pub mod security;

// Internal arithmetic, public only so the benchmarks can reach it. Not a
// supported API.
#[doc(hidden)]
pub mod common;

// Re-exports for convenience
pub use error::Error;
pub use error::Result;

// Compile and run the README examples as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
