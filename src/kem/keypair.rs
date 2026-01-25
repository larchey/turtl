//! ML-KEM key generation implementation.
//!
//! This module implements the key generation algorithm for ML-KEM as specified in NIST FIPS 203.
//!
//! Key generation creates a public/private keypair for ML-KEM operations:
//! - **Public Key (Encapsulation Key)**: Can be freely shared and is used by others to
//!   encapsulate shared secrets for the key owner.
//! - **Private Key (Decapsulation Key)**: Must be kept secret and is used to decapsulate
//!   ciphertexts to recover shared secrets.
//!
//! # Security Considerations
//!
//! - Keys are generated using cryptographically secure randomness from the OS
//! - Private keys are automatically zeroized when dropped to prevent memory leakage
//! - The implementation includes fault detection mechanisms
//! - Constant-time operations prevent timing side-channel attacks
//!
//! # Example
//!
//! ```no_run
//! use turtl::kem::{ParameterSet, KeyPair};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a new keypair for ML-KEM-768 (recommended parameter set)
//! let keypair = KeyPair::generate(ParameterSet::MlKem768)?;
//!
//! // Access the public and private keys
//! let public_key = keypair.public_key();
//! let private_key = keypair.private_key();
//!
//! println!("Generated ML-KEM-768 keypair");
//! println!("Public key size: {} bytes", public_key.as_bytes().len());
//! println!("Private key size: {} bytes", private_key.as_bytes().len());
//! # Ok(())
//! # }
//! ```

use super::internal::seed_to_keypair;
use super::{ParameterSet, PrivateKey, PublicKey};
use crate::error::{Error, Result};
use rand::{rngs::OsRng, CryptoRng, RngCore};

/// An ML-KEM public/private keypair.
///
/// A `KeyPair` consists of:
/// - A public key (encapsulation key) that can be shared with others
/// - A private key (decapsulation key) that must be kept secret
///
/// Both keys are bound to a specific parameter set (ML-KEM-512, ML-KEM-768, or ML-KEM-1024)
/// chosen during key generation.
///
/// # Security
///
/// - The private key is automatically zeroized when the `KeyPair` is dropped
/// - Keys should be generated using [`KeyPair::generate`] which uses secure randomness
/// - For deterministic key generation from a seed, use [`KeyPair::from_seed`]
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{ParameterSet, KeyPair};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Generate a keypair
/// let keypair = KeyPair::generate(ParameterSet::MlKem768)?;
///
/// // Extract the keys
/// let public_key = keypair.public_key();
/// let private_key = keypair.private_key();
///
/// // The public key can be serialized and transmitted
/// let pk_bytes = public_key.as_bytes();
///
/// // The private key must be kept secret
/// // It will be automatically zeroized when keypair goes out of scope
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct KeyPair {
    /// Public key (encapsulation key)
    public_key: PublicKey,
    /// Private key (decapsulation key)
    private_key: PrivateKey,
}

impl KeyPair {
    /// Generates a new ML-KEM keypair using secure randomness.
    ///
    /// This method generates a fresh keypair for the specified parameter set using the
    /// operating system's cryptographically secure random number generator.
    ///
    /// # Arguments
    ///
    /// * `parameter_set` - The ML-KEM parameter set to use:
    ///   - `MlKem512`: Security category 1 (AES-128 equivalent)
    ///   - `MlKem768`: Security category 3 (AES-192 equivalent, recommended)
    ///   - `MlKem1024`: Security category 5 (AES-256 equivalent)
    ///
    /// # Returns
    ///
    /// Returns a new `KeyPair` containing a public key and private key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The random number generator fails
    /// - Internal key generation operations fail
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{ParameterSet, KeyPair};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Generate a keypair with recommended security level
    /// let keypair = KeyPair::generate(ParameterSet::MlKem768)?;
    /// println!("Keypair generated successfully");
    /// # Ok(())
    /// # }
    /// ```
    pub fn generate(parameter_set: ParameterSet) -> Result<Self> {
        generate(parameter_set)
    }

    /// Creates a keypair from existing public and private keys.
    ///
    /// This method combines a public key and private key into a keypair, validating that
    /// both keys use the same parameter set.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The ML-KEM public key
    /// * `private_key` - The ML-KEM private key
    ///
    /// # Returns
    ///
    /// Returns a `KeyPair` containing both keys.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidParameterSet` if the public and private keys use different
    /// parameter sets (e.g., public key is ML-KEM-512 but private key is ML-KEM-768).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{ParameterSet, PublicKey, PrivateKey, KeyPair};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let public_key = PublicKey::new(vec![0u8; 800], ParameterSet::MlKem512)?;
    /// # let private_key = PrivateKey::new(vec![0u8; 1632], ParameterSet::MlKem512)?;
    /// // Combine separate keys into a keypair
    /// let keypair = KeyPair::from_keys(public_key, private_key)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_keys(public_key: PublicKey, private_key: PrivateKey) -> Result<Self> {
        // Ensure both keys use the same parameter set
        if public_key.parameter_set() != private_key.parameter_set() {
            return Err(Error::InvalidParameterSet);
        }

        Ok(Self {
            public_key,
            private_key,
        })
    }

    /// Generates a keypair deterministically from a 32-byte seed.
    ///
    /// This method performs deterministic key generation, producing the same keypair
    /// every time it's called with the same seed and parameter set. This is useful
    /// for key derivation schemes or when reproducible key generation is required.
    ///
    /// # Arguments
    ///
    /// * `seed` - A 32-byte seed for deterministic key generation. Must be generated
    ///   using a cryptographically secure random number generator.
    /// * `parameter_set` - The ML-KEM parameter set to use.
    ///
    /// # Returns
    ///
    /// Returns a `KeyPair` deterministically derived from the seed.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The seed length is not exactly 32 bytes
    /// - Internal key generation operations fail
    ///
    /// # Security Warning
    ///
    /// The seed must be generated using secure randomness and kept secret. If the seed
    /// is compromised, the entire keypair is compromised.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{ParameterSet, KeyPair};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Generate a secure random 32-byte seed
    /// let mut seed = [0u8; 32];
    /// // In production, use a CSPRNG to fill the seed
    /// // e.g., getrandom::getrandom(&mut seed)?;
    ///
    /// // Generate keypair from seed
    /// let keypair = KeyPair::from_seed(&seed, ParameterSet::MlKem768)?;
    ///
    /// // Same seed produces same keypair
    /// let keypair2 = KeyPair::from_seed(&seed, ParameterSet::MlKem768)?;
    /// assert_eq!(
    ///     keypair.public_key().as_bytes(),
    ///     keypair2.public_key().as_bytes()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_seed(seed: &[u8], parameter_set: ParameterSet) -> Result<Self> {
        if seed.len() != 32 {
            return Err(Error::InvalidParameterSet);
        }

        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(seed);

        seed_to_keypair(&seed_array, parameter_set)
    }

    /// Returns a copy of the public key from this keypair.
    ///
    /// The public key can be freely shared and is used by others to encapsulate
    /// shared secrets for this keypair's owner.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{ParameterSet, KeyPair};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let keypair = KeyPair::generate(ParameterSet::MlKem768)?;
    ///
    /// // Get the public key to share with others
    /// let public_key = keypair.public_key();
    /// let pk_bytes = public_key.as_bytes();
    /// // pk_bytes can be transmitted over an insecure channel
    /// # Ok(())
    /// # }
    /// ```
    pub fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    /// Returns a copy of the private key from this keypair.
    ///
    /// The private key must be kept secret and is used to decapsulate ciphertexts
    /// to recover shared secrets.
    ///
    /// # Security Warning
    ///
    /// The private key must never be transmitted or exposed. It is automatically
    /// zeroized when dropped.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{ParameterSet, KeyPair};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let keypair = KeyPair::generate(ParameterSet::MlKem768)?;
    ///
    /// // Get the private key for decapsulation
    /// let private_key = keypair.private_key();
    /// // Keep private_key secret!
    /// # Ok(())
    /// # }
    /// ```
    pub fn private_key(&self) -> PrivateKey {
        self.private_key.clone()
    }

    /// Returns the parameter set used by this keypair.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{ParameterSet, KeyPair};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let keypair = KeyPair::generate(ParameterSet::MlKem1024)?;
    /// assert_eq!(keypair.parameter_set(), ParameterSet::MlKem1024);
    /// # Ok(())
    /// # }
    /// ```
    pub fn parameter_set(&self) -> ParameterSet {
        self.public_key.parameter_set()
    }
}

/// Generates a new ML-KEM keypair using the OS random number generator.
///
/// This is the recommended way to generate ML-KEM keypairs for most applications.
/// It uses the operating system's cryptographically secure random number generator
/// to ensure proper randomness.
///
/// # Arguments
///
/// * `parameter_set` - The ML-KEM parameter set (512, 768, or 1024)
///
/// # Returns
///
/// Returns a new `KeyPair` with a randomly generated public/private key pair.
///
/// # Errors
///
/// Returns an error if key generation fails or the RNG is unavailable.
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{ParameterSet, keypair};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let keypair = keypair::generate(ParameterSet::MlKem768)?;
/// println!("Generated ML-KEM-768 keypair");
/// # Ok(())
/// # }
/// ```
pub fn generate(parameter_set: ParameterSet) -> Result<KeyPair> {
    // Generate a random 32-byte seed
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);

    // Generate key pair from seed
    seed_to_keypair(&seed, parameter_set)
}

/// Generates a keypair using a custom random number generator.
///
/// This function allows using a custom RNG instead of the OS RNG, which can be useful
/// for testing or when a specific RNG is required. The RNG must implement both
/// `RngCore` and `CryptoRng` traits to ensure cryptographic quality.
///
/// # Arguments
///
/// * `parameter_set` - The ML-KEM parameter set (512, 768, or 1024)
/// * `rng` - A cryptographically secure random number generator
///
/// # Returns
///
/// Returns a new `KeyPair` with a randomly generated public/private key pair.
///
/// # Errors
///
/// Returns an error if key generation fails.
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{ParameterSet, keypair};
/// use rand::rngs::OsRng;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut rng = OsRng;
/// let keypair = keypair::generate_with_rng(ParameterSet::MlKem768, &mut rng)?;
/// println!("Generated ML-KEM-768 keypair with custom RNG");
/// # Ok(())
/// # }
/// ```
pub fn generate_with_rng<R>(parameter_set: ParameterSet, rng: &mut R) -> Result<KeyPair>
where
    R: RngCore + CryptoRng,
{
    // Generate a random 32-byte seed
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    // Generate key pair from seed
    seed_to_keypair(&seed, parameter_set)
}
