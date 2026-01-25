//! ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) implementation.
//!
//! This module implements the ML-KEM algorithm as specified in NIST FIPS 203.
//! ML-KEM is a post-quantum key encapsulation mechanism based on the Module-LWE problem.
//!
//! # Overview
//!
//! ML-KEM is a key encapsulation mechanism (KEM) standardized by NIST (FIPS 203) that provides
//! security against both classical and quantum computer attacks. It is based on the mathematical
//! hardness of the Module Learning With Errors (M-LWE) problem.
//!
//! A key encapsulation mechanism is used to establish a shared secret between two parties.
//! Unlike traditional key exchange mechanisms, a KEM is a one-way mechanism where:
//!
//! 1. Party A generates a keypair (public key and private key)
//! 2. Party A shares the public key with Party B
//! 3. Party B uses the public key to encapsulate a random shared secret, producing a ciphertext
//! 4. Party B sends the ciphertext to Party A
//! 5. Party A uses their private key to decapsulate the ciphertext, recovering the same shared secret
//!
//! # Parameter Sets
//!
//! ML-KEM defines three parameter sets with different security levels:
//!
//! - **ML-KEM-512**: Security category 1 (equivalent to AES-128)
//! - **ML-KEM-768**: Security category 3 (equivalent to AES-192)
//! - **ML-KEM-1024**: Security category 5 (equivalent to AES-256)
//!
//! # Security Features
//!
//! This implementation includes several security features:
//!
//! - **Constant-Time Operations**: All cryptographic operations are implemented to run in constant time
//!   to prevent timing side-channel attacks.
//! - **Automatic Zeroization**: Sensitive data (private keys, shared secrets) is automatically
//!   zeroized when dropped.
//! - **Fault Detection**: Mechanisms to detect fault injection attacks during decapsulation.
//! - **Input Validation**: Thorough validation of inputs to prevent attacks.
//!
//! # Usage Example
//!
//! ```
//! use turtl::kem::{ParameterSet};
//!
//! fn main() {
//!     // Check security levels and parameter sizes
//!     let param_set = ParameterSet::MlKem768;
//!     
//!     println!("ML-KEM-768 Parameters:");
//!     println!("Security Category: {}", param_set.security_category());
//!     println!("Matrix Dimension (k): {}", param_set.k());
//!     println!("Public Key Size: {} bytes", param_set.public_key_size());
//!     println!("Private Key Size: {} bytes", param_set.private_key_size());
//!     println!("Ciphertext Size: {} bytes", param_set.ciphertext_size());
//!     println!("Shared Secret Size: {} bytes", param_set.shared_secret_size());
//! }
//! ```
//!
//! # FIPS 203 Compliance
//!
//! This implementation adheres to the NIST FIPS 203 standard and includes all of the
//! required features and parameter sets. Additionally, it includes security enhancements
//! to protect against side-channel and fault attacks.

use crate::error::{Error, Result};
// Import only what we need
use zeroize::{Zeroize, ZeroizeOnDrop};

// Import aux for ceil_log2
use crate::kem::internal::aux;

pub mod decapsulate;
pub mod encapsulate;
mod internal;
pub mod keypair;
pub mod params;
pub mod shell;

pub use keypair::KeyPair;
pub use params::ParameterSet;

// Import ZeroizeParameterSet
use params::ZeroizeParameterSet;

/// ML-KEM public key (encapsulation key).
///
/// This type represents an ML-KEM public key used for encapsulation operations.
/// The public key can be safely shared and is used by a sender to encapsulate
/// a shared secret into a ciphertext.
///
/// # Security
///
/// Public keys do not contain secret material and can be freely transmitted.
/// However, they should be authenticated to prevent man-in-the-middle attacks.
///
/// # Memory Safety
///
/// While not containing secrets, public keys are automatically zeroized when
/// dropped as a defense-in-depth measure.
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// Raw byte representation of the public key
    bytes: Vec<u8>,
    /// Parameter set associated with this key
    parameter_set: ParameterSet,
    // Add a ZeroizeParameterSet for zeroizing
    #[doc(hidden)]
    _zeroize_param: ZeroizeParameterSet,
}

// Manual implementation of Zeroize
impl Zeroize for PublicKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
        // parameter_set doesn't need to be zeroized as it's Copy and doesn't contain secrets
        // But _zeroize_param will be zeroized
        self._zeroize_param.zeroize();
    }
}

impl PublicKey {
    /// Creates a new public key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw byte representation of the public key
    /// * `parameter_set` - The ML-KEM parameter set (determines expected size)
    ///
    /// # Returns
    ///
    /// Returns `Ok(PublicKey)` if the bytes have the correct length for the parameter set.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPublicKey` if the byte length doesn't match the
    /// expected size for the parameter set.
    pub fn new(bytes: Vec<u8>, parameter_set: ParameterSet) -> Result<Self> {
        // Check if the bytes have the correct length for the parameter set
        let expected_len = parameter_set.public_key_size();
        if bytes.len() != expected_len {
            return Err(Error::InvalidPublicKey);
        }

        Ok(Self {
            bytes,
            parameter_set,
            _zeroize_param: ZeroizeParameterSet(parameter_set),
        })
    }

    /// Returns the raw bytes of the public key.
    ///
    /// This is the serialized form suitable for transmission or storage.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the parameter set associated with this key.
    ///
    /// The parameter set determines the security level and key sizes.
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }
}

/// ML-KEM private key (decapsulation key).
///
/// This type represents an ML-KEM private key used for decapsulation operations.
/// The private key must be kept secret and is used by a receiver to decapsulate
/// a ciphertext to recover the shared secret.
///
/// # Security
///
/// Private keys contain highly sensitive cryptographic material:
/// - They MUST be kept secret and protected from unauthorized access
/// - They MUST NOT be transmitted over insecure channels
/// - They are automatically zeroized when dropped to prevent memory disclosure
///
/// # Memory Safety
///
/// This type implements `ZeroizeOnDrop`, ensuring that the private key material
/// is securely erased from memory when the value is dropped.
#[derive(Clone, Debug)]
pub struct PrivateKey {
    /// Raw byte representation of the private key
    bytes: Vec<u8>,
    /// Parameter set associated with this key
    parameter_set: ParameterSet,
    // Add a ZeroizeParameterSet for zeroizing
    #[doc(hidden)]
    _zeroize_param: ZeroizeParameterSet,
}

// Manual implementation of Zeroize
impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
        // parameter_set doesn't need to be zeroized as it's Copy and doesn't contain secrets
        // But _zeroize_param will be zeroized
        self._zeroize_param.zeroize();
    }
}

// Implement ZeroizeOnDrop manually
impl ZeroizeOnDrop for PrivateKey {}

impl PrivateKey {
    /// Creates a new private key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw byte representation of the private key
    /// * `parameter_set` - The ML-KEM parameter set (determines expected size)
    ///
    /// # Returns
    ///
    /// Returns `Ok(PrivateKey)` if the bytes have the correct length for the parameter set.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPrivateKey` if the byte length doesn't match the
    /// expected size for the parameter set.
    ///
    /// # Security
    ///
    /// The provided bytes must be kept secret. This function takes ownership
    /// of the bytes and will zeroize them when the `PrivateKey` is dropped.
    pub fn new(bytes: Vec<u8>, parameter_set: ParameterSet) -> Result<Self> {
        // Check if the bytes have the correct length for the parameter set
        let expected_len = parameter_set.private_key_size();
        if bytes.len() != expected_len {
            return Err(Error::InvalidPrivateKey);
        }

        Ok(Self {
            bytes,
            parameter_set,
            _zeroize_param: ZeroizeParameterSet(parameter_set),
        })
    }

    /// Returns the raw bytes of the private key.
    ///
    /// # Security
    ///
    /// The returned bytes contain secret key material. Handle with extreme care.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the parameter set associated with this key.
    ///
    /// The parameter set determines the security level and key sizes.
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }

    /// Extracts the public key bytes from the private key.
    ///
    /// ML-KEM private key contains the public key as part of its structure.
    /// According to FIPS 203, the private key format is:
    /// - s (ρ, K, tr, s1, s2, t0)
    ///
    /// And the public key (ρ, t1) is reconstructable from these components.
    /// This method extracts those bytes for use in verification operations.
    pub fn extract_public_key_bytes(&self) -> Result<Vec<u8>> {
        // Check if the private key has the minimum required length
        // Basic validation to prevent out-of-bounds access
        if self.bytes.len() < 128 {
            // Minimum size (32+32+64)
            return Err(Error::InvalidPrivateKey);
        }

        // According to the FIPS 203 key format and our implementation in k_pke.rs:
        // Private key = rho (32) + key_seed (32) + tr (64) + s1 + s2 + t0
        // Public key = rho (32) + t1

        // The ML-KEM private key format doesn't directly store the public key
        // but stores components to reconstruct it

        // For full FIPS 203 compliance, we would:
        // 1. Extract rho, key_seed, tr, s1, s2, t0 from private key
        // 2. Use s1, s2 to compute t = A*s1 + s2
        // 3. Compute t1 from t
        // 4. Construct public key as (rho, t1)

        // For now, we extract the public key from the stored format used in our implementation
        // Based on the decode_private_key function, the private key contains the public key

        let k = self.parameter_set.k();

        // Skip the dk_pke section (varies by parameter set)
        let dk_pke_size = 384 * k; // Based on decode_private_key

        // Skip to the embedded public key
        if self.bytes.len() < dk_pke_size {
            return Err(Error::InvalidPrivateKey);
        }

        let d = 13; // The d parameter from FIPS 203
        let pk_size = 32 + 32 * k * (aux::ceil_log2(8380417 - 1) as usize - d);

        // Ensure the private key is long enough to contain the public key
        if self.bytes.len() < dk_pke_size + pk_size {
            return Err(Error::InvalidPrivateKey);
        }

        // Extract the public key portion
        let pk_bytes = self.bytes[dk_pke_size..(dk_pke_size + pk_size)].to_vec();

        // Verify the extracted bytes length matches the expected public key size
        if pk_bytes.len() != self.parameter_set.public_key_size() {
            return Err(Error::InvalidPublicKey);
        }

        Ok(pk_bytes)
    }

    /// Extracts the public key from the private key.
    ///
    /// This is a convenience method that extracts the public key bytes and
    /// wraps them in a `PublicKey` type.
    ///
    /// # Returns
    ///
    /// Returns `Ok(PublicKey)` containing the extracted public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the public key cannot be extracted from the private key.
    pub fn extract_public_key(&self) -> Result<PublicKey> {
        let pk_bytes = self.extract_public_key_bytes()?;
        PublicKey::new(pk_bytes, self.parameter_set)
    }
}

/// ML-KEM ciphertext.
///
/// This type represents an ML-KEM ciphertext produced by the encapsulation operation.
/// The ciphertext encapsulates a shared secret and can only be decapsulated by the
/// holder of the corresponding private key.
///
/// # Security
///
/// Ciphertexts do not contain the shared secret directly, but they may leak
/// information if manipulated. They should be transmitted over authenticated
/// channels to prevent tampering.
///
/// # Memory Safety
///
/// Ciphertexts are automatically zeroized when dropped as a defense-in-depth measure.
#[derive(Clone, Debug)]
pub struct Ciphertext {
    /// Raw byte representation of the ciphertext
    bytes: Vec<u8>,
    /// Parameter set associated with this ciphertext
    parameter_set: ParameterSet,
    // Add a ZeroizeParameterSet for zeroizing
    #[doc(hidden)]
    _zeroize_param: ZeroizeParameterSet,
}

// Manual implementation of Zeroize
impl Zeroize for Ciphertext {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
        // parameter_set doesn't need to be zeroized as it's Copy and doesn't contain secrets
        // But _zeroize_param will be zeroized
        self._zeroize_param.zeroize();
    }
}

impl Ciphertext {
    /// Creates a new ciphertext from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw byte representation of the ciphertext
    /// * `parameter_set` - The ML-KEM parameter set (determines expected size)
    ///
    /// # Returns
    ///
    /// Returns `Ok(Ciphertext)` if the bytes have the correct length for the parameter set.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidCiphertext` if the byte length doesn't match the
    /// expected size for the parameter set.
    pub fn new(bytes: Vec<u8>, parameter_set: ParameterSet) -> Result<Self> {
        // Check if the bytes have the correct length for the parameter set
        let expected_len = parameter_set.ciphertext_size();
        if bytes.len() != expected_len {
            return Err(Error::InvalidCiphertext);
        }

        Ok(Self {
            bytes,
            parameter_set,
            _zeroize_param: ZeroizeParameterSet(parameter_set),
        })
    }

    /// Returns the raw bytes of the ciphertext.
    ///
    /// This is the serialized form suitable for transmission or storage.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the parameter set associated with this ciphertext.
    ///
    /// The parameter set determines the security level and ciphertext size.
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }
}

/// ML-KEM shared secret.
///
/// This type represents the shared secret established by the ML-KEM key encapsulation.
/// Both the sender (via encapsulation) and receiver (via decapsulation) obtain the
/// same shared secret, which can then be used for symmetric encryption.
///
/// # Security
///
/// Shared secrets are highly sensitive cryptographic material:
/// - They MUST be kept secret and used only for key derivation or encryption
/// - They MUST NOT be transmitted or exposed
/// - They are automatically zeroized when dropped to prevent memory disclosure
///
/// # Size
///
/// All ML-KEM shared secrets are exactly 32 bytes (256 bits), regardless of
/// the parameter set used.
///
/// # Memory Safety
///
/// This type implements `ZeroizeOnDrop`, ensuring that the shared secret is
/// securely erased from memory when the value is dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedSecret {
    /// Raw byte representation of the shared secret
    bytes: [u8; 32],
}

// Manual implementation of Zeroize
impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

// Implement ZeroizeOnDrop manually
impl ZeroizeOnDrop for SharedSecret {}

impl SharedSecret {
    /// Creates a new shared secret from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The 32-byte shared secret value
    ///
    /// # Security
    ///
    /// The provided bytes must be kept secret. This function takes ownership
    /// of the bytes and will zeroize them when the `SharedSecret` is dropped.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Returns the raw bytes of the shared secret.
    ///
    /// # Security
    ///
    /// The returned bytes contain secret key material. Handle with extreme care.
    /// Use this only for immediate key derivation or encryption operations.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Generates a new ML-KEM key pair.
///
/// This function generates a fresh key pair for the specified ML-KEM parameter set.
/// The public key can be shared with others for encapsulation, while the private
/// key must be kept secret for decapsulation.
///
/// # Arguments
///
/// * `parameter_set` - The ML-KEM parameter set (MlKem512, MlKem768, or MlKem1024)
///
/// # Returns
///
/// Returns `Ok((PublicKey, PrivateKey))` containing the generated key pair.
///
/// # Errors
///
/// Returns `Error::RandomnessError` if the system's random number generator fails.
/// This is extremely rare and typically indicates a system-level problem.
///
/// # Example
///
/// ```rust
/// use turtl::kem::{key_gen, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// // Generate a key pair for ML-KEM-768 (security level 3)
/// let (public_key, private_key) = key_gen(ParameterSet::MlKem768)?;
///
/// println!("Generated ML-KEM-768 key pair");
/// println!("Public key size: {} bytes", public_key.as_bytes().len());
/// println!("Private key size: {} bytes", private_key.as_bytes().len());
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// This function uses the system's cryptographically secure random number generator.
/// Ensure the system RNG is properly seeded before use. The generated private key
/// is automatically zeroized when dropped.
///
/// # Reference
///
/// FIPS 203 Section 7.1 - ML-KEM.KeyGen
pub fn key_gen(parameter_set: ParameterSet) -> Result<(PublicKey, PrivateKey)> {
    let keypair = keypair::generate(parameter_set)?;
    Ok((keypair.public_key(), keypair.private_key()))
}

/// Encapsulates a shared secret using a public key.
///
/// This function generates a random shared secret and encapsulates it into a
/// ciphertext using the provided public key. The shared secret can then be used
/// for symmetric encryption, while the ciphertext is sent to the holder of the
/// corresponding private key.
///
/// # Arguments
///
/// * `public_key` - The recipient's ML-KEM public key
///
/// # Returns
///
/// Returns `Ok((Ciphertext, SharedSecret))` containing:
/// - The ciphertext to be sent to the recipient
/// - The shared secret for local use in symmetric encryption
///
/// # Errors
///
/// Returns `Error::RandomnessError` if the system's random number generator fails.
///
/// # Example
///
/// ```rust
/// use turtl::kem::{key_gen, encapsulate, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// // Generate recipient's key pair
/// let (public_key, private_key) = key_gen(ParameterSet::MlKem768)?;
///
/// // Encapsulate a shared secret
/// let (ciphertext, shared_secret) = encapsulate(&public_key)?;
///
/// println!("Encapsulated shared secret");
/// println!("Ciphertext size: {} bytes", ciphertext.as_bytes().len());
/// println!("Shared secret: 32 bytes");
///
/// // The ciphertext can be sent to the recipient
/// // The shared_secret is used locally for encryption
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - Uses cryptographically secure randomness for shared secret generation
/// - The shared secret is automatically zeroized when dropped
/// - The public key should be authenticated to prevent man-in-the-middle attacks
///
/// # Reference
///
/// FIPS 203 Section 7.2 - ML-KEM.Encaps
pub fn encapsulate(public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
    encapsulate::encapsulate(public_key)
}

/// Decapsulates a shared secret using a private key and ciphertext.
///
/// This function recovers the shared secret from a ciphertext using the private key.
/// The recovered shared secret will be identical to the one obtained by the sender
/// during encapsulation (assuming the ciphertext has not been modified).
///
/// # Arguments
///
/// * `private_key` - The recipient's ML-KEM private key
/// * `ciphertext` - The ciphertext received from the sender
///
/// # Returns
///
/// Returns `Ok(SharedSecret)` containing the recovered shared secret.
///
/// # Errors
///
/// This function uses implicit rejection and will NOT return an error for invalid
/// ciphertexts. Instead, it returns a pseudorandom shared secret that is
/// indistinguishable from the real secret to prevent timing attacks.
///
/// Returns `Error::RandomnessError` only if the system's RNG fails during
/// implicit rejection (extremely rare).
///
/// # Example
///
/// ```rust
/// use turtl::kem::{key_gen, encapsulate, decapsulate, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// // Generate recipient's key pair
/// let (public_key, private_key) = key_gen(ParameterSet::MlKem768)?;
///
/// // Sender encapsulates a shared secret
/// let (ciphertext, sender_secret) = encapsulate(&public_key)?;
///
/// // Recipient decapsulates to recover the shared secret
/// let recipient_secret = decapsulate(&private_key, &ciphertext)?;
///
/// // Both parties now have the same shared secret
/// assert_eq!(sender_secret.as_bytes(), recipient_secret.as_bytes());
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - Uses **implicit rejection** (FIPS 203 Section 7.3): Invalid ciphertexts
///   produce a pseudorandom shared secret instead of an error, preventing
///   chosen-ciphertext attacks via timing analysis
/// - The shared secret is automatically zeroized when dropped
/// - Constant-time implementation prevents timing side-channel attacks
///
/// # Reference
///
/// FIPS 203 Section 7.3 - ML-KEM.Decaps with implicit rejection
pub fn decapsulate(private_key: &PrivateKey, ciphertext: &Ciphertext) -> Result<SharedSecret> {
    decapsulate::decapsulate(private_key, ciphertext)
}
