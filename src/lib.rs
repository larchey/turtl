//! # TURTL: Trusted Uniform Rust Toolkit for Lattice-cryptography
//! 
//! A Rust implementation of NIST's post-quantum cryptographic standards,
//! focusing on ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) and ML-DSA 
//! (Module-Lattice-Based Digital Signature Algorithm).
//! 
//! ## Features
//! 
//! * Complete implementation of ML-KEM with all parameter sets (512, 768, 1024)
//! * Complete implementation of ML-DSA with all parameter sets (44, 65, 87)
//! * High-performance NTT implementation
//! * Constant-time operations for side-channel resistance
//! * Safe memory handling for sensitive data
//! * Simple API for easy integration
//! 
//! ## Examples
//! 
//! ### Key Encapsulation (ML-KEM)
//! 
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use turtl::kem::{KeyPair, ParameterSet};
//! 
//! // Generate a keypair
//! let keypair = KeyPair::generate(ParameterSet::ML_KEM_768)?;
//! 
//! // Encapsulate (create a shared secret)
//! let (ciphertext, shared_secret) = turtl::kem::encapsulate(&keypair.public_key())?;
//! 
//! // Decapsulate (recover the shared secret)
//! let decapsulated_secret = turtl::kem::decapsulate(&keypair.private_key(), &ciphertext)?;
//! 
//! // Both parties now have the same shared secret
//! assert_eq!(shared_secret, decapsulated_secret);
//! # Ok(())
//! # }
//! ```
//! 
//! ### Digital Signatures (ML-DSA)
//! 
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use turtl::dsa::{KeyPair, ParameterSet, SigningMode};
//! 
//! // Generate a keypair
//! let keypair = KeyPair::generate(ParameterSet::ML_DSA_65)?;
//! 
//! // Sign a message
//! let message = b"This is a test message";
//! let context = b"";  // Optional context
//! let signature = turtl::dsa::sign(&keypair.private_key(), message, context, SigningMode::Hedged)?;
//! 
//! // Verify a signature
//! let is_valid = turtl::dsa::verify(&keypair.public_key(), message, &signature, context)?;
//! assert!(is_valid);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "nightly", feature(portable_simd))]

// Public modules
pub mod kem;
pub mod dsa;
pub mod error;

// Internal modules
mod common;

// Re-exports for convenience
pub use error::Error;