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
//! # Security notes
//!
//! - **Input validation**: `PublicKey::new` applies the FIPS 203 modulus check and
//!   `PrivateKey::new` the hash check; lengths are checked everywhere.
//! - **Implicit rejection**: an invalid ciphertext yields a pseudorandom shared secret, selected
//!   without branching, never an error.
//! - **Side channels**: arithmetic on secret data is branch-free and division-free.
//! - **Zeroization**: private keys, shared secrets and intermediate secrets are wiped on drop.
//!
//! See `SECURITY.md` for the assurance evidence and limitations.
//!
//! # Usage Example
//!
//! ```
//! use turtl::kem::{decapsulate, encapsulate, KeyPair, ParameterSet};
//!
//! # fn main() -> turtl::Result<()> {
//! // Receiver generates a keypair and publishes the public key.
//! let keypair = KeyPair::generate(ParameterSet::MlKem768)?;
//!
//! // Sender encapsulates a fresh shared secret to that public key.
//! let (ciphertext, sender_secret) = encapsulate(&keypair.public_key())?;
//!
//! // Receiver recovers the same secret from the ciphertext.
//! let receiver_secret = decapsulate(&keypair.private_key(), &ciphertext)?;
//! assert_eq!(sender_secret, receiver_secret);
//! # Ok(())
//! # }
//! ```

use crate::error::{Error, Result};
// Import only what we need
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod decapsulate;
pub mod encapsulate;
mod internal;
pub mod keypair;
pub mod params;
pub mod shell;

pub use keypair::KeyPair;
pub use params::ParameterSet;

/// ML-KEM public key (encapsulation key).
///
/// This type represents a public key for the ML-KEM key encapsulation mechanism.
/// The public key is used by a sender to encapsulate a shared secret, producing
/// a ciphertext that only the holder of the corresponding private key can decapsulate.
///
/// # Security Features
///
/// - Immutable after creation to prevent accidental modification
/// - Size validated during construction
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{key_gen, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, _private_key) = key_gen(ParameterSet::MlKem768)?;
///
/// println!("Public key size: {} bytes", public_key.as_bytes().len());
/// println!("Parameter set: {:?}", public_key.parameter_set());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// Raw byte representation of the public key
    bytes: Vec<u8>,
    /// Parameter set associated with this key
    parameter_set: ParameterSet,
}

impl Zeroize for PublicKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl PublicKey {
    /// Create a new public key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw byte representation of the public key
    /// * `parameter_set` - The ML-KEM parameter set this key belongs to
    ///
    /// # Returns
    ///
    /// A new `PublicKey` instance if the bytes are valid.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPublicKey` if the byte length doesn't match the
    /// expected size for the given parameter set, or if the key fails the FIPS 203
    /// encapsulation-key modulus check (an encoded coefficient is not below q).
    ///
    /// # Example
    ///
    /// ```
    /// use turtl::kem::{PublicKey, ParameterSet};
    ///
    /// # fn main() -> Result<(), turtl::error::Error> {
    /// let bytes = vec![0u8; ParameterSet::MlKem768.public_key_size()];
    /// let public_key = PublicKey::new(bytes, ParameterSet::MlKem768)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(bytes: Vec<u8>, parameter_set: ParameterSet) -> Result<Self> {
        // Check if the bytes have the correct length for the parameter set
        let expected_len = parameter_set.public_key_size();
        if bytes.len() != expected_len {
            return Err(Error::InvalidPublicKey);
        }

        // FIPS 203 Section 7.2 input check: ByteEncode_12(ByteDecode_12(ek)) == ek.
        if !internal::k_pke::encoded_coeffs_below_q(&bytes[..384 * parameter_set.k()]) {
            return Err(Error::InvalidPublicKey);
        }

        Ok(Self {
            bytes,
            parameter_set,
        })
    }

    /// Get the raw bytes of the public key.
    ///
    /// Returns a reference to the byte representation of this public key.
    /// This can be used for serialization or transmission.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{key_gen, ParameterSet};
    ///
    /// # fn main() -> Result<(), turtl::error::Error> {
    /// let (public_key, _) = key_gen(ParameterSet::MlKem768)?;
    /// let bytes = public_key.as_bytes();
    /// assert_eq!(bytes.len(), ParameterSet::MlKem768.public_key_size());
    /// # Ok(())
    /// # }
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the parameter set associated with this key.
    ///
    /// Returns the ML-KEM parameter set (ML-KEM-512, ML-KEM-768, or ML-KEM-1024)
    /// that was used to generate this key.
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }
}

/// ML-KEM private key (decapsulation key).
///
/// This type represents a private key for the ML-KEM key encapsulation mechanism.
/// The private key is used to decapsulate a ciphertext and recover the shared secret
/// that was encapsulated by the sender using the corresponding public key.
///
/// # Security Features
///
/// - Zeroized on drop; `Debug` output is redacted
/// - Immutable after creation to prevent accidental modification
/// - Size validated during construction
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{key_gen, encapsulate, decapsulate, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, private_key) = key_gen(ParameterSet::MlKem768)?;
/// let (ciphertext, shared_secret1) = encapsulate(&public_key)?;
/// let shared_secret2 = decapsulate(&private_key, &ciphertext)?;
///
/// assert_eq!(shared_secret1, shared_secret2);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct PrivateKey {
    /// Raw byte representation of the private key
    bytes: Vec<u8>,
    /// Parameter set associated with this key
    parameter_set: ParameterSet,
}

impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for PrivateKey {}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("parameter_set", &self.parameter_set)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl PrivateKey {
    /// Create a new private key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw byte representation of the private key
    /// * `parameter_set` - The ML-KEM parameter set this key belongs to
    ///
    /// # Returns
    ///
    /// A new `PrivateKey` instance if the bytes are valid.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPrivateKey` if the byte length doesn't match the
    /// expected size for the given parameter set, or if the key fails the FIPS 203
    /// decapsulation-key hash check (the embedded `H(ek)` does not match `ek`).
    ///
    /// # Security
    ///
    /// The private key will be automatically zeroized when dropped.
    pub fn new(bytes: Vec<u8>, parameter_set: ParameterSet) -> Result<Self> {
        // Check if the bytes have the correct length for the parameter set
        let expected_len = parameter_set.private_key_size();
        if bytes.len() != expected_len {
            return Err(Error::InvalidPrivateKey);
        }

        // FIPS 203 Section 7.3 input check: H(dk[384k : 768k+32]) == dk[768k+32 : 768k+64].
        let k = parameter_set.k();
        let ek = &bytes[384 * k..768 * k + 32];
        let h = &bytes[768 * k + 32..768 * k + 64];
        if !crate::security::constant_time::ct_eq(&crate::common::hash::sha3_256(ek), h) {
            return Err(Error::InvalidPrivateKey);
        }

        Ok(Self {
            bytes,
            parameter_set,
        })
    }

    /// Get the raw bytes of the private key.
    ///
    /// Returns a reference to the byte representation of this private key.
    ///
    /// # Security
    ///
    /// Handle these bytes with care as they contain sensitive cryptographic material.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the parameter set associated with this key.
    ///
    /// Returns the ML-KEM parameter set (ML-KEM-512, ML-KEM-768, or ML-KEM-1024)
    /// that was used to generate this key.
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }

    /// Extract the public key bytes from the private key.
    ///
    /// ML-KEM private key contains the public key as part of its structure.
    /// According to FIPS 203, the ML-KEM private key format is:
    /// dk_pke || ek_pke || H(ek_pke) || z
    ///
    /// This method extracts the embedded public key (ek_pke) from the private key.
    pub fn extract_public_key_bytes(&self) -> Result<Vec<u8>> {
        // ML-KEM private key format (FIPS 203):
        // - dk_pke: ByteEncode_12(s) for each polynomial in s (k * 384 bytes)
        // - ek_pke: public key (parameter_set.public_key_size() bytes)
        // - H(ek_pke): hash of public key (32 bytes)
        // - z: random value (32 bytes)

        let k = self.parameter_set.k();
        let dk_pke_size = k * 384;
        let pk_size = self.parameter_set.public_key_size();

        // Ensure the private key is long enough
        if self.bytes.len() < dk_pke_size + pk_size + 64 {
            return Err(Error::InvalidPrivateKey);
        }

        // Extract the public key portion (ek_pke)
        let pk_bytes = self.bytes[dk_pke_size..(dk_pke_size + pk_size)].to_vec();

        // Verify the extracted bytes length matches the expected public key size
        if pk_bytes.len() != pk_size {
            return Err(Error::InvalidPublicKey);
        }

        Ok(pk_bytes)
    }

    /// Extract the public key from the private key.
    ///
    /// ML-KEM private keys contain the public key as part of their structure,
    /// allowing the public key to be reconstructed from the private key.
    ///
    /// # Returns
    ///
    /// The corresponding `PublicKey` for this private key.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPrivateKey` if the private key structure is malformed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::kem::{key_gen, ParameterSet};
    ///
    /// # fn main() -> Result<(), turtl::error::Error> {
    /// let (original_pk, private_key) = key_gen(ParameterSet::MlKem768)?;
    /// let extracted_pk = private_key.extract_public_key()?;
    ///
    /// assert_eq!(original_pk.as_bytes(), extracted_pk.as_bytes());
    /// # Ok(())
    /// # }
    /// ```
    pub fn extract_public_key(&self) -> Result<PublicKey> {
        let pk_bytes = self.extract_public_key_bytes()?;
        PublicKey::new(pk_bytes, self.parameter_set)
    }
}

/// ML-KEM ciphertext.
///
/// This type represents a ciphertext produced by the ML-KEM encapsulation operation.
/// The ciphertext encapsulates a shared secret and can only be decapsulated by the
/// holder of the corresponding private key.
///
/// # Security Features
///
/// - Immutable after creation
/// - Size validated during construction
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{key_gen, encapsulate, decapsulate, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, private_key) = key_gen(ParameterSet::MlKem768)?;
/// let (ciphertext, shared_secret1) = encapsulate(&public_key)?;
///
/// // Send ciphertext to the private key holder
/// let shared_secret2 = decapsulate(&private_key, &ciphertext)?;
///
/// assert_eq!(shared_secret1, shared_secret2);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Ciphertext {
    /// Raw byte representation of the ciphertext
    bytes: Vec<u8>,
    /// Parameter set associated with this ciphertext
    parameter_set: ParameterSet,
}

impl Zeroize for Ciphertext {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Ciphertext {
    /// Create a new ciphertext from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw byte representation of the ciphertext
    /// * `parameter_set` - The ML-KEM parameter set this ciphertext belongs to
    ///
    /// # Returns
    ///
    /// A new `Ciphertext` instance if the bytes are valid.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidCiphertext` if the byte length doesn't match the
    /// expected size for the given parameter set.
    pub fn new(bytes: Vec<u8>, parameter_set: ParameterSet) -> Result<Self> {
        // Check if the bytes have the correct length for the parameter set
        let expected_len = parameter_set.ciphertext_size();
        if bytes.len() != expected_len {
            return Err(Error::InvalidCiphertext);
        }

        Ok(Self {
            bytes,
            parameter_set,
        })
    }

    /// Get the raw bytes of the ciphertext.
    ///
    /// Returns a reference to the byte representation of this ciphertext.
    /// This can be used for serialization or transmission.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the parameter set associated with this ciphertext.
    ///
    /// Returns the ML-KEM parameter set that was used to create this ciphertext.
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }
}

/// ML-KEM shared secret.
///
/// This type represents the shared secret established between two parties using ML-KEM.
/// The shared secret is a 32-byte value that can be used as a symmetric key for
/// subsequent encryption or as input to a key derivation function.
///
/// # Security Features
///
/// - Zeroized on drop; `Debug` output is redacted
/// - Fixed size of 32 bytes for all ML-KEM parameter sets
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{key_gen, encapsulate, decapsulate, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, private_key) = key_gen(ParameterSet::MlKem768)?;
/// let (ciphertext, sender_secret) = encapsulate(&public_key)?;
/// let receiver_secret = decapsulate(&private_key, &ciphertext)?;
///
/// // Both parties now have the same 32-byte shared secret
/// assert_eq!(sender_secret, receiver_secret);
/// assert_eq!(sender_secret.as_bytes().len(), 32);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
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

impl ZeroizeOnDrop for SharedSecret {}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedSecret")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Constant-time equality: comparing shared secrets must not leak, through timing,
/// how many leading bytes match.
impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        crate::security::constant_time::ct_eq(&self.bytes, &other.bytes)
    }
}

impl Eq for SharedSecret {}

impl SharedSecret {
    /// Create a new shared secret from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte array containing the shared secret
    ///
    /// # Security
    ///
    /// The shared secret will be automatically zeroized when dropped.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Get the raw bytes of the shared secret.
    ///
    /// Returns a reference to the 32-byte shared secret.
    ///
    /// # Security
    ///
    /// Handle these bytes with care as they contain sensitive cryptographic material.
    /// Consider using a key derivation function (KDF) to derive session keys from
    /// this shared secret.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Generate a new ML-KEM key pair.
///
/// This function generates a fresh public/private key pair using the specified
/// ML-KEM parameter set. The key generation uses a cryptographically secure
/// random number generator.
///
/// # Arguments
///
/// * `parameter_set` - The ML-KEM parameter set to use (ML-KEM-512, ML-KEM-768, or ML-KEM-1024)
///
/// # Returns
///
/// A tuple containing `(public_key, private_key)` on success.
///
/// # Errors
///
/// Returns `Error::RandomnessError` if the random number generator fails
/// (extremely rare with a properly functioning system RNG).
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{key_gen, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// // Generate keys for ML-KEM-768 (security category 3)
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
/// - This function uses the system's cryptographically secure RNG
/// - Ensure the system RNG is properly seeded before calling this function
/// - The private key is automatically zeroized when dropped
///
/// # Reference
///
/// FIPS 203 Section 7.1 - ML-KEM.KeyGen
pub fn key_gen(parameter_set: ParameterSet) -> Result<(PublicKey, PrivateKey)> {
    let keypair = keypair::generate(parameter_set)?;
    Ok((keypair.public_key(), keypair.private_key()))
}

/// Encapsulate a shared secret using a public key.
///
/// This function generates a random shared secret and encapsulates it using the
/// provided public key, producing a ciphertext. The same shared secret can only
/// be recovered by decapsulating the ciphertext with the corresponding private key.
///
/// # Arguments
///
/// * `public_key` - The ML-KEM public key to use for encapsulation
///
/// # Returns
///
/// A tuple containing `(ciphertext, shared_secret)` on success.
/// - `ciphertext` - The encapsulated ciphertext to send to the private key holder
/// - `shared_secret` - The 32-byte shared secret established
///
/// # Errors
///
/// Returns `Error::RandomnessError` if the random number generator fails
/// (extremely rare with a properly functioning system RNG).
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{key_gen, encapsulate, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, _private_key) = key_gen(ParameterSet::MlKem768)?;
///
/// // Encapsulate a shared secret
/// let (ciphertext, shared_secret) = encapsulate(&public_key)?;
///
/// // The ciphertext can now be sent to the private key holder
/// println!("Ciphertext size: {} bytes", ciphertext.as_bytes().len());
/// println!("Shared secret: {} bytes", shared_secret.as_bytes().len());
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - Uses cryptographically secure randomness for shared secret generation
/// - The shared secret is automatically zeroized when dropped
/// - Each call generates a fresh, independent shared secret
///
/// # Reference
///
/// FIPS 203 Section 7.2 - ML-KEM.Encaps
pub fn encapsulate(public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
    encapsulate::encapsulate(public_key)
}

/// Encapsulate using a caller-supplied 32-byte message `m` instead of fresh
/// randomness. This is the deterministic, KAT-reproducible entry point
/// (FIPS 203 ML-KEM.Encaps_internal); for normal use call [`encapsulate()`](fn@encapsulate).
pub fn encapsulate_deterministic(
    public_key: &PublicKey,
    message: &[u8; 32],
) -> Result<(Ciphertext, SharedSecret)> {
    internal::encapsulate_deterministic_internal(public_key, message)
}

/// Decapsulate a shared secret using a private key and ciphertext.
///
/// This function recovers the shared secret that was encapsulated in the ciphertext
/// using the corresponding public key. The recovered shared secret will match the
/// one produced during encapsulation.
///
/// # Arguments
///
/// * `private_key` - The ML-KEM private key to use for decapsulation
/// * `ciphertext` - The ciphertext received from the encapsulating party
///
/// # Returns
///
/// The 32-byte shared secret on success.
///
/// # Errors
///
/// Returns an error if decapsulation fails. Note that ML-KEM uses implicit rejection,
/// so invalid ciphertexts will not produce an explicit error but will return a
/// pseudorandom shared secret that differs from the one used during encapsulation.
///
/// # Example
///
/// ```no_run
/// use turtl::kem::{key_gen, encapsulate, decapsulate, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, private_key) = key_gen(ParameterSet::MlKem768)?;
///
/// // Sender encapsulates
/// let (ciphertext, sender_secret) = encapsulate(&public_key)?;
///
/// // Receiver decapsulates
/// let receiver_secret = decapsulate(&private_key, &ciphertext)?;
///
/// // Both parties now have the same shared secret
/// assert_eq!(sender_secret, receiver_secret);
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - Implements implicit rejection (FIPS 203 Section 7.3)
/// - Invalid ciphertexts produce pseudorandom shared secrets instead of errors
/// - The shared secret is automatically zeroized when dropped
///
/// # Reference
///
/// FIPS 203 Section 7.3 - ML-KEM.Decaps
pub fn decapsulate(private_key: &PrivateKey, ciphertext: &Ciphertext) -> Result<SharedSecret> {
    decapsulate::decapsulate(private_key, ciphertext)
}
