//! ML-KEM decapsulation implementation.
//!
//! This module implements the decapsulation algorithm for ML-KEM as specified in NIST FIPS 203.
//!
//! Decapsulation is the process by which the recipient (typically called Bob) uses his private
//! key to recover the shared secret from a ciphertext produced during encapsulation. After
//! successful decapsulation, both parties possess the same shared secret without having
//! transmitted it directly.
//!
//! # Security Properties
//!
//! - **IND-CCA2 Security**: The decapsulation is secure against adaptive chosen-ciphertext attacks.
//! - **Implicit Rejection**: Invalid or malformed ciphertexts do not cause errors but instead
//!   produce a pseudorandom shared secret. This prevents certain side-channel attacks.
//! - **Constant-Time Operations**: Decapsulation runs in constant time regardless of input
//!   validity, protecting against timing attacks.
//! - **Re-Encryption Check**: The implementation re-encrypts the decrypted message to verify
//!   ciphertext integrity, protecting against fault injection attacks.
//!
//! # Example
//!
//! ```no_run
//! use turtl::kem::{self, ParameterSet};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Bob generates a keypair
//! let (public_key, private_key) = kem::key_gen(ParameterSet::MlKem768)?;
//!
//! // Alice encapsulates a shared secret using Bob's public key
//! let (ciphertext, alice_secret) = kem::encapsulate(&public_key)?;
//!
//! // Bob decapsulates to recover the shared secret
//! let bob_secret = kem::decapsulate(&private_key, &ciphertext)?;
//!
//! // Both parties now have the same shared secret
//! assert_eq!(alice_secret, bob_secret);
//! # Ok(())
//! # }
//! ```

use super::internal::decapsulate_internal;
use super::{Ciphertext, PrivateKey, SharedSecret};
use crate::error::{Error, Result};

/// Decapsulates a shared secret from a ciphertext using the recipient's ML-KEM private key.
///
/// This function implements the ML-KEM decapsulation algorithm (FIPS 203). It recovers
/// the shared secret that was encapsulated by the sender, allowing both parties to
/// derive the same cryptographic keys without transmitting the secret directly.
///
/// # Arguments
///
/// * `private_key` - The recipient's ML-KEM private key (decapsulation key). Must correspond
///   to the public key used during encapsulation.
/// * `ciphertext` - The ciphertext produced by the encapsulation operation. Must use the
///   same parameter set as the private key.
///
/// # Returns
///
/// Returns the 32-byte shared secret that was encapsulated in the ciphertext. This will
/// match the shared secret generated during encapsulation if the ciphertext is valid.
///
/// # Errors
///
/// Returns an error if:
/// - The private key and ciphertext use different parameter sets (ML-KEM-512 vs ML-KEM-768, etc.)
/// - The ciphertext length is incorrect for the parameter set
/// - Internal cryptographic operations fail
///
/// Note: Invalid or malformed ciphertexts do not cause errors in the cryptographic sense
/// (implicit rejection), but may still fail validation checks.
///
/// # Security Considerations
///
/// - **Implicit Rejection**: This implementation uses implicit rejection, meaning invalid
///   ciphertexts produce a pseudorandom shared secret rather than an error. This prevents
///   attackers from learning information through decapsulation oracle attacks.
/// - **Constant-Time**: All operations run in constant time to prevent timing side-channel attacks.
/// - **Fault Detection**: Re-encryption is performed internally to detect fault injection attacks.
/// - **Automatic Zeroization**: The shared secret is automatically zeroized when dropped.
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{self, ParameterSet};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Complete key exchange example
/// let param_set = ParameterSet::MlKem1024; // Highest security level
///
/// // Bob generates keypair and shares public key
/// let (public_key, private_key) = kem::key_gen(param_set)?;
///
/// // Alice encapsulates using Bob's public key
/// let (ciphertext, alice_shared_secret) = kem::encapsulate(&public_key)?;
///
/// // Bob decapsulates using his private key
/// let bob_shared_secret = kem::decapsulate(&private_key, &ciphertext)?;
///
/// // Verify both parties have the same secret
/// assert_eq!(alice_shared_secret, bob_shared_secret);
/// println!("Key exchange successful!");
/// # Ok(())
/// # }
/// ```
pub fn decapsulate(private_key: &PrivateKey, ciphertext: &Ciphertext) -> Result<SharedSecret> {
    // Check that the parameter sets match
    if private_key.parameter_set() != ciphertext.parameter_set() {
        return Err(Error::InvalidParameterSet);
    }

    decapsulate_internal(private_key, ciphertext)
}
