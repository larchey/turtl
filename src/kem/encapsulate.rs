//! ML-KEM encapsulation implementation.
//!
//! This module implements the encapsulation algorithm for ML-KEM as specified in NIST FIPS 203.
//!
//! Encapsulation is the process by which a party (typically called Alice) generates a random
//! shared secret and encrypts it using the recipient's (Bob's) public key. The result is a
//! ciphertext that can be sent to Bob, who can recover the same shared secret using his
//! private key through decapsulation.
//!
//! # Security Properties
//!
//! - **IND-CCA2 Security**: The encapsulation provides indistinguishability under adaptive
//!   chosen-ciphertext attack.
//! - **Random Shared Secret**: Each encapsulation generates a fresh random 32-byte shared secret.
//! - **Implicit Rejection**: Invalid ciphertexts during decapsulation produce a pseudorandom
//!   shared secret rather than returning an error (protecting against certain side-channel attacks).
//!
//! # Example
//!
//! ```no_run
//! use turtl::kem::{self, ParameterSet};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Bob generates a keypair
//! let (public_key, _private_key) = kem::key_gen(ParameterSet::MlKem768)?;
//!
//! // Alice encapsulates a shared secret using Bob's public key
//! let (ciphertext, shared_secret) = kem::encapsulate(&public_key)?;
//!
//! // Alice can now use the shared_secret for encryption
//! // Alice sends the ciphertext to Bob
//! println!("Encapsulation successful, shared secret: {} bytes", shared_secret.as_bytes().len());
//! # Ok(())
//! # }
//! ```

use super::internal::encapsulate_internal;
use super::{Ciphertext, PublicKey, SharedSecret};
use crate::error::Result;

/// Encapsulates a random shared secret using the recipient's ML-KEM public key.
///
/// This function implements the ML-KEM encapsulation algorithm (FIPS 203). It generates
/// a random 32-byte shared secret and encrypts it using the provided public key,
/// producing a ciphertext that can be sent to the holder of the corresponding private key.
///
/// # Arguments
///
/// * `public_key` - The recipient's ML-KEM public key (encapsulation key). The public key
///   determines which parameter set (ML-KEM-512, ML-KEM-768, or ML-KEM-1024) is used.
///
/// # Returns
///
/// Returns a tuple containing:
/// - `Ciphertext`: The encapsulated shared secret that should be transmitted to the recipient
/// - `SharedSecret`: The 32-byte shared secret that both parties will possess (32 bytes for all parameter sets)
///
/// # Errors
///
/// Returns an error if:
/// - The public key is malformed or invalid
/// - Internal cryptographic operations fail
/// - Random number generation fails
///
/// # Security Considerations
///
/// - The shared secret is generated using a cryptographically secure random number generator
/// - Each call generates a fresh, independent shared secret
/// - The ciphertext reveals no information about the shared secret to attackers
/// - Constant-time operations protect against timing side-channel attacks
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{self, ParameterSet};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Generate a keypair
/// let (public_key, private_key) = kem::key_gen(ParameterSet::MlKem768)?;
///
/// // Encapsulate a shared secret
/// let (ciphertext, alice_secret) = kem::encapsulate(&public_key)?;
///
/// // The ciphertext can be transmitted over an insecure channel
/// // The shared secret should be kept confidential
/// assert_eq!(alice_secret.as_bytes().len(), 32);
/// # Ok(())
/// # }
/// ```
pub fn encapsulate(public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
    encapsulate_internal(public_key)
}
