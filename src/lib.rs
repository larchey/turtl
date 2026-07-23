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
//! ## Status
//!
//! This crate is **not** yet hardened against timing/power side-channels and has not had an
//! independent audit. See `SECURITY_REVIEW_2026-07.md`. Not yet suitable for production use.
//!
//! ## Examples
//!
//! ### Key Encapsulation (ML-KEM)
//!
//! ```
//! # fn main() {
//! use turtl::kem::{ParameterSet};
//!
//! // Display available parameter sets for ML-KEM
//! println!("ML-KEM parameter sets for each security level:");
//! println!("Security level 1: {:?}", ParameterSet::MlKem512);
//! println!("Security level 3: {:?}", ParameterSet::MlKem768);
//! println!("Security level 5: {:?}", ParameterSet::MlKem1024);
//! # }
//! ```
//!
//! ### Digital Signatures (ML-DSA)
//!
//! ```
//! # fn main() {
//! use turtl::dsa::{ParameterSet};
//!
//! // Display available parameter sets for ML-DSA
//! println!("ML-DSA parameter sets for each security level:");
//! println!("Security level 2: {:?}", ParameterSet::MlDsa44);
//! println!("Security level 3: {:?}", ParameterSet::MlDsa65);
//! println!("Security level 5: {:?}", ParameterSet::MlDsa87);
//! # }
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
// Allow certain clippy lints that require extensive refactoring
#![allow(clippy::needless_range_loop)]
#![allow(clippy::type_complexity)]

// Public modules
pub mod dsa;
pub mod error;
pub mod kem;
pub mod security;

// Export the common module so it's accessible to benchmarks
pub mod common;

// Re-exports for convenience
pub use error::Error;
pub use error::Result;
