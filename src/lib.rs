//! # TURTL: Trusted Uniform Rust Toolkit for Lattice-cryptography
//! 
//! A Rust implementation of NIST's post-quantum cryptographic standards,
//! focusing on ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism, FIPS 203) and ML-DSA 
//! (Module-Lattice-Based Digital Signature Algorithm, FIPS 204).
//! 
//! ## Features
//! 
//! * Complete implementation of ML-KEM with all parameter sets (512, 768, 1024)
//! * Complete implementation of ML-DSA with all parameter sets (44, 65, 87)
//! * High-performance NTT implementation
//! * Enhanced side-channel resistance with constant-time operations
//! * Fault attack countermeasures for hardened security
//! * Safe memory handling with automatic zeroization for sensitive data
//! * Simple, developer-friendly API
//! * Comprehensive security validation and testing
//! * No unsafe code - 100% safe Rust
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
#![cfg_attr(feature = "nightly", feature(portable_simd))]

// Public modules
pub mod kem;
pub mod dsa;
pub mod error;
pub mod security;

// Export the common module so it's accessible to benchmarks
pub mod common;

// Re-exports for convenience
pub use error::Error;
pub use error::Result;