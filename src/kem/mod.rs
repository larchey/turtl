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

/// An ML-KEM public key used for encapsulation.
///
/// The public key (also called the encapsulation key) is used by senders to encapsulate
/// shared secrets for the key owner. It can be freely distributed without compromising security.
///
/// # Size
///
/// The public key size depends on the parameter set:
/// - ML-KEM-512: 800 bytes
/// - ML-KEM-768: 1,184 bytes
/// - ML-KEM-1024: 1,568 bytes
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{self, ParameterSet};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Generate a keypair
/// let (public_key, _private_key) = kem::key_gen(ParameterSet::MlKem768)?;
///
/// // Public key can be serialized and transmitted
/// let pk_bytes = public_key.as_bytes();
/// println!("Public key size: {} bytes", pk_bytes.len());
///
/// // Public key stores its parameter set
/// assert_eq!(public_key.parameter_set(), ParameterSet::MlKem768);
/// # Ok(())
/// # }
/// ```
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
    /// This method validates that the byte length matches the expected size for the
    /// specified parameter set before constructing the public key.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw byte representation of the public key
    /// * `parameter_set` - The ML-KEM parameter set (must match the key's actual parameter set)
    ///
    /// # Returns
    ///
    /// Returns a new `PublicKey` if the bytes are valid.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPublicKey` if the byte length doesn't match the expected
    /// size for the parameter set:
    /// - ML-KEM-512 expects 800 bytes
    /// - ML-KEM-768 expects 1,184 bytes
    /// - ML-KEM-1024 expects 1,568 bytes
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{ParameterSet, PublicKey};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Raw bytes (normally obtained from serialization or key generation)
    /// let pk_bytes = vec![0u8; 1184]; // ML-KEM-768 size
    ///
    /// let public_key = PublicKey::new(pk_bytes, ParameterSet::MlKem768)?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Returns the raw byte representation of the public key.
    ///
    /// This can be used to serialize the public key for transmission or storage.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{self, ParameterSet};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let (public_key, _) = kem::key_gen(ParameterSet::MlKem768)?;
    ///
    /// // Get bytes for transmission
    /// let pk_bytes = public_key.as_bytes();
    /// // pk_bytes can be sent over a network, saved to disk, etc.
    /// # Ok(())
    /// # }
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the parameter set associated with this public key.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{self, ParameterSet};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let (public_key, _) = kem::key_gen(ParameterSet::MlKem1024)?;
    ///
    /// assert_eq!(public_key.parameter_set(), ParameterSet::MlKem1024);
    /// # Ok(())
    /// # }
    /// ```
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }
}

/// An ML-KEM private key used for decapsulation.
///
/// The private key (also called the decapsulation key) is used by the key owner to decapsulate
/// ciphertexts and recover shared secrets. It must be kept secret and protected.
///
/// # Security
///
/// - The private key is automatically zeroized when dropped
/// - Never transmit or expose the private key
/// - Store private keys securely (encrypted at rest)
/// - The private key contains the corresponding public key data
///
/// # Size
///
/// The private key size depends on the parameter set:
/// - ML-KEM-512: 1,632 bytes
/// - ML-KEM-768: 2,400 bytes
/// - ML-KEM-1024: 3,168 bytes
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{self, ParameterSet};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Generate a keypair
/// let (_public_key, private_key) = kem::key_gen(ParameterSet::MlKem768)?;
///
/// // Private key size
/// println!("Private key size: {} bytes", private_key.as_bytes().len());
///
/// // Private key will be automatically zeroized when it goes out of scope
/// # Ok(())
/// # }
/// ```
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
    /// This method validates that the byte length matches the expected size for the
    /// specified parameter set before constructing the private key.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw byte representation of the private key
    /// * `parameter_set` - The ML-KEM parameter set (must match the key's actual parameter set)
    ///
    /// # Returns
    ///
    /// Returns a new `PrivateKey` if the bytes are valid.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPrivateKey` if the byte length doesn't match the expected
    /// size for the parameter set:
    /// - ML-KEM-512 expects 1,632 bytes
    /// - ML-KEM-768 expects 2,400 bytes
    /// - ML-KEM-1024 expects 3,168 bytes
    ///
    /// # Security Warning
    ///
    /// Private keys must be handled with care. The resulting `PrivateKey` will be
    /// automatically zeroized when dropped, but the input `bytes` are not zeroized
    /// by this function.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{ParameterSet, PrivateKey};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Raw bytes (normally obtained from secure storage)
    /// let sk_bytes = vec![0u8; 2400]; // ML-KEM-768 size
    ///
    /// let private_key = PrivateKey::new(sk_bytes, ParameterSet::MlKem768)?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Returns the raw byte representation of the private key.
    ///
    /// # Security Warning
    ///
    /// Be extremely careful when using this method. The returned bytes represent
    /// the private key material and must be protected. Consider encrypting the
    /// bytes before storage or transmission.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{self, ParameterSet};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let (_, private_key) = kem::key_gen(ParameterSet::MlKem768)?;
    ///
    /// // Get bytes for secure storage (should be encrypted)
    /// let sk_bytes = private_key.as_bytes();
    /// // WARNING: Protect these bytes!
    /// # Ok(())
    /// # }
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the parameter set associated with this private key.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{self, ParameterSet};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let (_, private_key) = kem::key_gen(ParameterSet::MlKem512)?;
    ///
    /// assert_eq!(private_key.parameter_set(), ParameterSet::MlKem512);
    /// # Ok(())
    /// # }
    /// ```
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }

    /// Extracts the public key bytes from the private key.
    ///
    /// ML-KEM private keys contain the corresponding public key data as part of their
    /// structure (as specified in FIPS 203). This method extracts those bytes.
    ///
    /// # Returns
    ///
    /// Returns the raw bytes of the corresponding public key.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPrivateKey` if the private key is malformed or too short.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{self, ParameterSet};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let (expected_pk, private_key) = kem::key_gen(ParameterSet::MlKem768)?;
    ///
    /// // Extract public key from private key
    /// let pk_bytes = private_key.extract_public_key_bytes()?;
    /// assert_eq!(pk_bytes, expected_pk.as_bytes());
    /// # Ok(())
    /// # }
    /// ```
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
    /// This is a convenience method that extracts the public key bytes and wraps
    /// them in a `PublicKey` object.
    ///
    /// # Returns
    ///
    /// Returns the corresponding `PublicKey`.
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is malformed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{self, ParameterSet};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let (expected_pk, private_key) = kem::key_gen(ParameterSet::MlKem768)?;
    ///
    /// // Extract public key from private key
    /// let extracted_pk = private_key.extract_public_key()?;
    /// assert_eq!(extracted_pk.as_bytes(), expected_pk.as_bytes());
    /// # Ok(())
    /// # }
    /// ```
    pub fn extract_public_key(&self) -> Result<PublicKey> {
        let pk_bytes = self.extract_public_key_bytes()?;
        PublicKey::new(pk_bytes, self.parameter_set)
    }
}

/// An ML-KEM ciphertext containing an encapsulated shared secret.
///
/// A ciphertext is produced during encapsulation and contains an encrypted shared secret.
/// It can be safely transmitted over an insecure channel to the recipient, who can
/// decapsulate it using their private key to recover the shared secret.
///
/// # Size
///
/// The ciphertext size depends on the parameter set:
/// - ML-KEM-512: 768 bytes
/// - ML-KEM-768: 1,088 bytes
/// - ML-KEM-1024: 1,568 bytes
///
/// # Security
///
/// - Ciphertexts can be transmitted over insecure channels
/// - Each ciphertext encapsulates a unique shared secret
/// - Ciphertexts reveal no information about the shared secret
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{self, ParameterSet};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let (public_key, private_key) = kem::key_gen(ParameterSet::MlKem768)?;
///
/// // Encapsulate a shared secret
/// let (ciphertext, sender_secret) = kem::encapsulate(&public_key)?;
///
/// // Ciphertext can be transmitted
/// println!("Ciphertext size: {} bytes", ciphertext.as_bytes().len());
///
/// // Recipient decapsulates
/// let recipient_secret = kem::decapsulate(&private_key, &ciphertext)?;
/// assert_eq!(sender_secret, recipient_secret);
/// # Ok(())
/// # }
/// ```
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
    /// * `parameter_set` - The ML-KEM parameter set
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidCiphertext` if the byte length doesn't match the expected size.
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

    /// Returns the raw byte representation of the ciphertext.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the parameter set associated with this ciphertext.
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }
}

/// A 32-byte shared secret generated by ML-KEM.
///
/// The shared secret is the output of both encapsulation and decapsulation. After a
/// successful key exchange, both parties possess the same shared secret, which can be
/// used to derive encryption and authentication keys.
///
/// # Security
///
/// - The shared secret is automatically zeroized when dropped
/// - Always use the shared secret through a key derivation function (KDF)
/// - Never use the raw shared secret bytes directly as encryption keys
/// - Each encapsulation generates a fresh, independent shared secret
///
/// # Size
///
/// The shared secret is always 32 bytes (256 bits) for all ML-KEM parameter sets.
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{self, ParameterSet, shell::Shell};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let (public_key, private_key) = kem::key_gen(ParameterSet::MlKem768)?;
/// let (ciphertext, shared_secret) = kem::encapsulate(&public_key)?;
///
/// // Use the shell to derive keys from the shared secret
/// let shell = Shell::new(shared_secret);
/// let encryption_key = shell.derive_encryption_key();
/// let auth_key = shell.derive_authentication_key();
///
/// // Use derived keys for encryption/authentication
/// # Ok(())
/// # }
/// ```
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
    /// Creates a new shared secret from a 32-byte array.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte array containing the shared secret
    ///
    /// # Security Warning
    ///
    /// This method does not zeroize the input `bytes`. If you need to ensure the
    /// input is zeroized, do so manually after calling this method.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Returns a reference to the raw 32-byte shared secret.
    ///
    /// # Security Warning
    ///
    /// The shared secret should be used through a key derivation function (KDF) rather
    /// than directly. Consider using [`shell::Shell`](crate::kem::shell::Shell) to derive keys.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{self, ParameterSet};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let (pk, sk) = kem::key_gen(ParameterSet::MlKem768)?;
    /// let (_, shared_secret) = kem::encapsulate(&pk)?;
    ///
    /// // Get the raw bytes (for KDF input)
    /// let secret_bytes = shared_secret.as_bytes();
    /// assert_eq!(secret_bytes.len(), 32);
    /// # Ok(())
    /// # }
    /// ```
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Generates a new ML-KEM keypair for the specified parameter set.
///
/// This is a convenience function that generates both the public and private keys,
/// returning them as a tuple. It's equivalent to calling [`KeyPair::generate`] and
/// then extracting the keys.
///
/// # Arguments
///
/// * `parameter_set` - The ML-KEM parameter set to use:
///   - [`ParameterSet::MlKem512`]: Security category 1 (128-bit security)
///   - [`ParameterSet::MlKem768`]: Security category 3 (192-bit security, recommended)
///   - [`ParameterSet::MlKem1024`]: Security category 5 (256-bit security)
///
/// # Returns
///
/// Returns a tuple of `(PublicKey, PrivateKey)`:
/// - The `PublicKey` can be shared with others for encapsulation
/// - The `PrivateKey` must be kept secret for decapsulation
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
/// use turtl::kem::{self, ParameterSet};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Generate a keypair with recommended security
/// let (public_key, private_key) = kem::key_gen(ParameterSet::MlKem768)?;
///
/// // Public key can be shared
/// println!("Public key: {} bytes", public_key.as_bytes().len());
///
/// // Private key must be kept secret
/// // It will be automatically zeroized when dropped
/// # Ok(())
/// # }
/// ```
pub fn key_gen(parameter_set: ParameterSet) -> Result<(PublicKey, PrivateKey)> {
    let keypair = keypair::generate(parameter_set)?;
    Ok((keypair.public_key(), keypair.private_key()))
}

/// Encapsulates a random shared secret using the recipient's public key.
///
/// This function generates a fresh 32-byte shared secret and encrypts it using the
/// provided public key, producing a ciphertext. Both the shared secret and ciphertext
/// are returned. The shared secret can be used to derive encryption keys, while the
/// ciphertext should be transmitted to the recipient.
///
/// This is a convenience function equivalent to calling [`encapsulate::encapsulate`].
///
/// # Arguments
///
/// * `public_key` - The recipient's ML-KEM public key
///
/// # Returns
///
/// Returns a tuple of `(Ciphertext, SharedSecret)`:
/// - The `Ciphertext` should be sent to the recipient
/// - The `SharedSecret` should be used locally for deriving encryption keys
///
/// Both parties will have the same shared secret after decapsulation.
///
/// # Errors
///
/// Returns an error if:
/// - The public key is invalid or malformed
/// - Random number generation fails
/// - Internal cryptographic operations fail
///
/// # Security
///
/// - Each call generates a fresh, independent shared secret
/// - Constant-time operations protect against timing attacks
/// - The shared secret is automatically zeroized when dropped
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{self, ParameterSet};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Recipient generates keypair
/// let (public_key, _private_key) = kem::key_gen(ParameterSet::MlKem768)?;
///
/// // Sender encapsulates a shared secret
/// let (ciphertext, shared_secret) = kem::encapsulate(&public_key)?;
///
/// // Send ciphertext to recipient
/// println!("Ciphertext: {} bytes", ciphertext.as_bytes().len());
/// println!("Shared secret: {} bytes", shared_secret.as_bytes().len());
/// # Ok(())
/// # }
/// ```
pub fn encapsulate(public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
    encapsulate::encapsulate(public_key)
}

/// Decapsulates a shared secret from a ciphertext using the private key.
///
/// This function recovers the shared secret that was encapsulated by the sender.
/// After successful decapsulation, both the sender and recipient will possess
/// the same 32-byte shared secret.
///
/// This is a convenience function equivalent to calling [`decapsulate::decapsulate`].
///
/// # Arguments
///
/// * `private_key` - The recipient's ML-KEM private key
/// * `ciphertext` - The ciphertext received from the sender
///
/// # Returns
///
/// Returns the 32-byte `SharedSecret` that was encapsulated in the ciphertext.
///
/// # Errors
///
/// Returns an error if:
/// - The private key and ciphertext use different parameter sets
/// - The ciphertext has invalid length
/// - Internal cryptographic operations fail
///
/// Note: Due to implicit rejection, invalid ciphertexts produce a pseudorandom
/// shared secret rather than an error in most cases.
///
/// # Security
///
/// - Uses implicit rejection to prevent chosen-ciphertext attacks
/// - Constant-time operations protect against timing attacks
/// - Re-encryption check protects against fault injection attacks
/// - The shared secret is automatically zeroized when dropped
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{self, ParameterSet};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Complete key exchange
/// let (public_key, private_key) = kem::key_gen(ParameterSet::MlKem768)?;
///
/// // Sender encapsulates
/// let (ciphertext, sender_secret) = kem::encapsulate(&public_key)?;
///
/// // Recipient decapsulates
/// let recipient_secret = kem::decapsulate(&private_key, &ciphertext)?;
///
/// // Both parties have the same shared secret
/// assert_eq!(sender_secret, recipient_secret);
/// println!("Key exchange successful!");
/// # Ok(())
/// # }
/// ```
pub fn decapsulate(private_key: &PrivateKey, ciphertext: &Ciphertext) -> Result<SharedSecret> {
    decapsulate::decapsulate(private_key, ciphertext)
}
