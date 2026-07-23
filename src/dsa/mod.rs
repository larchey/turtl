//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm) implementation.
//!
//! This module implements the ML-DSA algorithm as specified in NIST FIPS 204.
//! ML-DSA is a post-quantum digital signature scheme based on the Module-LWE problem.
//!
//! # Overview
//!
//! ML-DSA is a digital signature algorithm standardized by NIST (FIPS 204) that provides
//! security against both classical and quantum computer attacks. It is based on the
//! mathematical hardness of the Module Learning With Errors (M-LWE) and Module Short Integer
//! Solution (M-SIS) problems over polynomial rings.
//!
//! # Parameter Sets
//!
//! ML-DSA defines three parameter sets with different security levels:
//!
//! - **ML-DSA-44**: Security category 2 (comparable to SHA-256/SHA3-256)
//! - **ML-DSA-65**: Security category 3 (comparable to SHA-384/SHA3-384)
//! - **ML-DSA-87**: Security category 5 (comparable to SHA-512/SHA3-512)
//!
//! # Signing Modes
//!
//! This implementation supports two signing modes:
//!
//! - **Hedged Mode** (recommended): Combines deterministic signing with fresh randomness
//!   to provide defense-in-depth against side-channel attacks and RNG failures.
//! - **Deterministic Mode**: Uses only the message and private key (no randomness),
//!   producing the same signature for the same message/key combination.
//!
//! # Context Strings
//!
//! ML-DSA supports optional context strings (up to 255 bytes) that can be used to
//! provide domain separation or additional authenticated data. The context is bound
//! to the signature and must match during verification.
//!
//! # Security notes
//!
//! - **Zeroization**: private keys zeroize their byte buffers on drop. Some intermediate
//!   secrets are not yet zeroized.
//! - **Input validation**: key, signature, context, and parameter-set lengths are checked.
//!
//! This implementation is **not** hardened against timing/power side-channels and has not had
//! an independent audit — see `SECURITY_REVIEW_2026-07.md`. It is not yet suitable for
//! protecting production data.
//!
//! # Usage Example
//!
//! ```no_run
//! use turtl::dsa::{key_gen, sign, verify, ParameterSet, SigningMode};
//!
//! # fn main() -> Result<(), turtl::error::Error> {
//! // Generate a key pair
//! let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
//!
//! // Sign a message in hedged mode (recommended)
//! let message = b"Hello, post-quantum world!";
//! let context = b"example-app-v1";
//! let signature = sign(&private_key, message, context, SigningMode::Hedged)?;
//!
//! // Verify the signature
//! let is_valid = verify(&public_key, message, &signature, context)?;
//! assert!(is_valid);
//! # Ok(())
//! # }
//! ```
//!
//! # FIPS 204 Compliance
//!
//! This implementation adheres to the NIST FIPS 204 standard and includes all
//! required features and parameter sets. Additionally, it includes security
//! enhancements to protect against side-channel and fault attacks.

use crate::error::{Error, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

mod internal;
pub mod keypair;
pub mod params;
pub mod sign;
pub mod stamp;
pub mod verify;

pub use keypair::KeyPair;
pub use params::ParameterSet;

// Import ZeroizeParameterSet
use params::ZeroizeParameterSet;

/// ML-DSA signing mode.
///
/// This enum specifies how randomness is used during the signing operation.
/// ML-DSA supports two signing modes as specified in FIPS 204.
///
/// # Modes
///
/// - **Hedged** (recommended): Combines deterministic signing with fresh randomness
///   to provide defense-in-depth against side-channel attacks and RNG failures.
///   This is the recommended mode for most applications.
/// - **Deterministic**: Uses only the message and private key (no randomness),
///   producing the same signature for the same message/key combination. This mode
///   can be useful for testing or specific applications requiring reproducibility.
///
/// # Security Considerations
///
/// - **Hedged mode** is more resistant to side-channel attacks and provides protection
///   against RNG failures or manipulation.
/// - **Deterministic mode** may be vulnerable to attacks if the same message is signed
///   multiple times and side-channel information is leaked.
/// - For production use, hedged mode is strongly recommended unless there is a specific
///   requirement for deterministic signatures.
///
/// # Example
///
/// ```no_run
/// use turtl::dsa::{key_gen, sign, SigningMode, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
/// let message = b"Important message";
/// let context = b"";
///
/// // Use hedged mode (recommended)
/// let signature1 = sign(&private_key, message, context, SigningMode::Hedged)?;
///
/// // Use deterministic mode
/// let signature2 = sign(&private_key, message, context, SigningMode::Deterministic)?;
/// # Ok(())
/// # }
/// ```
///
/// # Reference
///
/// FIPS 204 Section 5.4 - Signature Generation Modes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningMode {
    /// Default mode that uses fresh randomness for protection against side-channel attacks
    Hedged,
    /// Deterministic mode that does not use fresh randomness
    Deterministic,
}

/// ML-DSA public key (verification key).
///
/// This type represents a public key for the ML-DSA digital signature algorithm.
/// The public key is used to verify signatures created with the corresponding private key.
///
/// # Security Features
///
/// - Automatically zeroized on drop to prevent memory leakage
/// - Immutable after creation to prevent accidental modification
/// - Size validated during construction
///
/// # Example
///
/// ```no_run
/// use turtl::dsa::{key_gen, sign, verify, SigningMode, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
///
/// let message = b"Message to sign";
/// let context = b"";
/// let signature = sign(&private_key, message, context, SigningMode::Hedged)?;
///
/// // Use public key to verify the signature
/// let is_valid = verify(&public_key, message, &signature, context)?;
/// assert!(is_valid);
///
/// println!("Public key size: {} bytes", public_key.as_bytes().len());
/// println!("Parameter set: {:?}", public_key.parameter_set());
/// # Ok(())
/// # }
/// ```
///
/// # Reference
///
/// FIPS 204 Section 5.1 - Key Generation
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
    /// Create a new public key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw byte representation of the public key
    /// * `parameter_set` - The ML-DSA parameter set this key belongs to
    ///
    /// # Returns
    ///
    /// A new `PublicKey` instance if the bytes are valid.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPublicKey` if the byte length doesn't match the
    /// expected size for the given parameter set.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::dsa::{PublicKey, ParameterSet};
    ///
    /// # fn main() -> Result<(), turtl::error::Error> {
    /// let bytes = vec![0u8; ParameterSet::MlDsa65.public_key_size()];
    /// let public_key = PublicKey::new(bytes, ParameterSet::MlDsa65)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(bytes: Vec<u8>, parameter_set: ParameterSet) -> Result<Self> {
        // Check if the bytes have the correct length
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

    /// Get the raw bytes of the public key.
    ///
    /// Returns a reference to the byte representation of this public key.
    /// This can be used for serialization or transmission.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::dsa::{key_gen, ParameterSet};
    ///
    /// # fn main() -> Result<(), turtl::error::Error> {
    /// let (public_key, _) = key_gen(ParameterSet::MlDsa65)?;
    /// let bytes = public_key.as_bytes();
    /// assert_eq!(bytes.len(), ParameterSet::MlDsa65.public_key_size());
    /// # Ok(())
    /// # }
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the parameter set associated with this key.
    ///
    /// Returns the ML-DSA parameter set (ML-DSA-44, ML-DSA-65, or ML-DSA-87)
    /// that was used to generate this key.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::dsa::{key_gen, ParameterSet};
    ///
    /// # fn main() -> Result<(), turtl::error::Error> {
    /// let (public_key, _) = key_gen(ParameterSet::MlDsa65)?;
    /// assert_eq!(public_key.parameter_set(), ParameterSet::MlDsa65);
    /// # Ok(())
    /// # }
    /// ```
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }
}

/// ML-DSA private key (signing key).
///
/// This type represents a private key for the ML-DSA digital signature algorithm.
/// The private key is used to create signatures that can be verified using the
/// corresponding public key.
///
/// # Security Features
///
/// - Automatically zeroized on drop to prevent memory leakage
/// - Implements `ZeroizeOnDrop` to ensure sensitive data is cleared
/// - Immutable after creation to prevent accidental modification
/// - Size validated during construction
///
/// # Example
///
/// ```no_run
/// use turtl::dsa::{key_gen, sign, verify, SigningMode, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
///
/// let message = b"Message to sign";
/// let context = b"";
/// let signature = sign(&private_key, message, context, SigningMode::Hedged)?;
///
/// let is_valid = verify(&public_key, message, &signature, context)?;
/// assert!(is_valid);
/// # Ok(())
/// # }
/// ```
///
/// # Reference
///
/// FIPS 204 Section 5.1 - Key Generation
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
    /// Create a new private key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw byte representation of the private key
    /// * `parameter_set` - The ML-DSA parameter set this key belongs to
    ///
    /// # Returns
    ///
    /// A new `PrivateKey` instance if the bytes are valid.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPrivateKey` if the byte length doesn't match the
    /// expected size for the given parameter set.
    ///
    /// # Security
    ///
    /// The private key will be automatically zeroized when dropped.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::dsa::{PrivateKey, ParameterSet};
    ///
    /// # fn main() -> Result<(), turtl::error::Error> {
    /// let bytes = vec![0u8; ParameterSet::MlDsa65.private_key_size()];
    /// let private_key = PrivateKey::new(bytes, ParameterSet::MlDsa65)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(bytes: Vec<u8>, parameter_set: ParameterSet) -> Result<Self> {
        // Check if the bytes have the correct length
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

    /// Get the raw bytes of the private key.
    ///
    /// Returns a reference to the byte representation of this private key.
    ///
    /// # Security
    ///
    /// Handle these bytes with care as they contain sensitive cryptographic material.
    /// The private key should be stored securely and never transmitted in plaintext.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::dsa::{key_gen, ParameterSet};
    ///
    /// # fn main() -> Result<(), turtl::error::Error> {
    /// let (_, private_key) = key_gen(ParameterSet::MlDsa65)?;
    /// let bytes = private_key.as_bytes();
    /// assert_eq!(bytes.len(), ParameterSet::MlDsa65.private_key_size());
    /// # Ok(())
    /// # }
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the parameter set associated with this key.
    ///
    /// Returns the ML-DSA parameter set (ML-DSA-44, ML-DSA-65, or ML-DSA-87)
    /// that was used to generate this key.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::dsa::{key_gen, ParameterSet};
    ///
    /// # fn main() -> Result<(), turtl::error::Error> {
    /// let (_, private_key) = key_gen(ParameterSet::MlDsa65)?;
    /// assert_eq!(private_key.parameter_set(), ParameterSet::MlDsa65);
    /// # Ok(())
    /// # }
    /// ```
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }
}

/// ML-DSA signature.
///
/// This type represents a digital signature produced by the ML-DSA signing operation.
/// The signature can be verified using the corresponding public key to authenticate
/// the message and prove it was signed by the holder of the private key.
///
/// # Security Features
///
/// - Automatically zeroized on drop to prevent memory leakage
/// - Immutable after creation
/// - Size validated during construction
///
/// # Example
///
/// ```no_run
/// use turtl::dsa::{key_gen, sign, verify, SigningMode, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
/// let message = b"Important message";
/// let context = b"";
///
/// // Create a signature
/// let signature = sign(&private_key, message, context, SigningMode::Hedged)?;
///
/// // Verify the signature
/// let is_valid = verify(&public_key, message, &signature, context)?;
/// assert!(is_valid);
///
/// println!("Signature size: {} bytes", signature.as_bytes().len());
/// # Ok(())
/// # }
/// ```
///
/// # Reference
///
/// FIPS 204 Section 5.2 - Signature Generation
#[derive(Clone, Debug)]
pub struct Signature {
    /// Raw byte representation of the signature
    bytes: Vec<u8>,
    /// Parameter set associated with this signature
    parameter_set: ParameterSet,
    // Add a ZeroizeParameterSet for zeroizing
    #[doc(hidden)]
    _zeroize_param: ZeroizeParameterSet,
}

// Manual implementation of Zeroize
impl Zeroize for Signature {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
        // parameter_set doesn't need to be zeroized as it's Copy and doesn't contain secrets
        // But _zeroize_param will be zeroized
        self._zeroize_param.zeroize();
    }
}

impl Signature {
    /// Create a new signature from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw byte representation of the signature
    /// * `parameter_set` - The ML-DSA parameter set this signature belongs to
    ///
    /// # Returns
    ///
    /// A new `Signature` instance if the bytes are valid.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidSignature` if the byte length doesn't match the
    /// expected size for the given parameter set.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::dsa::{Signature, ParameterSet};
    ///
    /// # fn main() -> Result<(), turtl::error::Error> {
    /// let bytes = vec![0u8; ParameterSet::MlDsa65.signature_size()];
    /// let signature = Signature::new(bytes, ParameterSet::MlDsa65)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(bytes: Vec<u8>, parameter_set: ParameterSet) -> Result<Self> {
        // Check if the bytes have the correct length
        let expected_len = parameter_set.signature_size();
        if bytes.len() != expected_len {
            return Err(Error::InvalidSignature);
        }

        Ok(Self {
            bytes,
            parameter_set,
            _zeroize_param: ZeroizeParameterSet(parameter_set),
        })
    }

    /// Get the raw bytes of the signature.
    ///
    /// Returns a reference to the byte representation of this signature.
    /// This can be used for serialization or transmission.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::dsa::{key_gen, sign, SigningMode, ParameterSet};
    ///
    /// # fn main() -> Result<(), turtl::error::Error> {
    /// let (_, private_key) = key_gen(ParameterSet::MlDsa65)?;
    /// let signature = sign(&private_key, b"message", b"", SigningMode::Hedged)?;
    /// let bytes = signature.as_bytes();
    /// assert_eq!(bytes.len(), ParameterSet::MlDsa65.signature_size());
    /// # Ok(())
    /// # }
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the parameter set associated with this signature.
    ///
    /// Returns the ML-DSA parameter set that was used to create this signature.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use turtl::dsa::{key_gen, sign, SigningMode, ParameterSet};
    ///
    /// # fn main() -> Result<(), turtl::error::Error> {
    /// let (_, private_key) = key_gen(ParameterSet::MlDsa65)?;
    /// let signature = sign(&private_key, b"message", b"", SigningMode::Hedged)?;
    /// assert_eq!(signature.parameter_set(), ParameterSet::MlDsa65);
    /// # Ok(())
    /// # }
    /// ```
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }
}

/// Supported hash functions for pre-hash mode.
///
/// This enum specifies the hash function to use when signing or verifying
/// messages in pre-hash mode. Pre-hash mode is useful for signing large
/// messages, as the message is hashed before signing rather than processing
/// the entire message directly.
///
/// # Hash Functions
///
/// - **SHA3-256**: 256-bit output from SHA3-256
/// - **SHA3-512**: 512-bit output from SHA3-512
/// - **SHAKE128**: 256-bit output from SHAKE128 XOF
/// - **SHAKE256**: 512-bit output from SHAKE256 XOF
///
/// # Example
///
/// ```no_run
/// use turtl::dsa::{key_gen, hash_sign, hash_verify, SigningMode, HashFunction, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
/// let large_message = vec![0u8; 1024 * 1024]; // 1 MB message
/// let context = b"";
///
/// // Use pre-hash mode with SHA3-256
/// let signature = hash_sign(
///     &private_key,
///     &large_message,
///     context,
///     HashFunction::SHA3_256,
///     SigningMode::Hedged
/// )?;
///
/// let is_valid = hash_verify(
///     &public_key,
///     &large_message,
///     &signature,
///     context,
///     HashFunction::SHA3_256
/// )?;
/// assert!(is_valid);
/// # Ok(())
/// # }
/// ```
///
/// # Reference
///
/// FIPS 204 Section 5.3 - HashML-DSA
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashFunction {
    /// SHA3-256 hash function with 256-bit output
    SHA3_256,
    /// SHA3-512 hash function with 512-bit output
    SHA3_512,
    /// SHAKE128 extendable-output function with 256-bit output
    SHAKE128,
    /// SHAKE256 extendable-output function with 512-bit output
    SHAKE256,
}

/// Generate a new ML-DSA key pair.
///
/// This function generates a fresh public/private key pair for the specified
/// ML-DSA parameter set. The key generation uses a cryptographically secure
/// random number generator.
///
/// # Arguments
///
/// * `parameter_set` - The ML-DSA parameter set to use (ML-DSA-44, ML-DSA-65, or ML-DSA-87)
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
/// use turtl::dsa::{key_gen, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// // Generate keys for ML-DSA-65 (security category 3)
/// let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
///
/// println!("Generated ML-DSA-65 key pair");
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
/// - Store the private key securely and never transmit it in plaintext
///
/// # Reference
///
/// FIPS 204 Section 5.1 - ML-DSA.KeyGen
pub fn key_gen(parameter_set: ParameterSet) -> Result<(PublicKey, PrivateKey)> {
    let keypair = keypair::generate(parameter_set)?;
    Ok((keypair.public_key(), keypair.private_key()))
}

/// Sign a message.
///
/// This function creates a digital signature for the provided message using the
/// private key. The signature can later be verified using the corresponding public key.
///
/// # Arguments
///
/// * `private_key` - The ML-DSA private key to use for signing
/// * `message` - The message to sign (arbitrary length)
/// * `context` - Optional context string (up to 255 bytes) for domain separation
/// * `mode` - Signing mode (Hedged or Deterministic)
///
/// # Returns
///
/// A `Signature` that can be verified with the corresponding public key.
///
/// # Errors
///
/// - `Error::ContextTooLong` if the context exceeds 255 bytes
/// - `Error::RandomnessError` if RNG fails (only in Hedged mode)
/// - `Error::SigningError` if signature generation fails
///
/// # Example
///
/// ```no_run
/// use turtl::dsa::{key_gen, sign, verify, SigningMode, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
///
/// // Sign a message in hedged mode (recommended)
/// let message = b"Important message";
/// let context = b"app-v1.0";
/// let signature = sign(&private_key, message, context, SigningMode::Hedged)?;
///
/// // Verify the signature
/// let is_valid = verify(&public_key, message, &signature, context)?;
/// assert!(is_valid);
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - Hedged mode (recommended) provides defense-in-depth against side-channel attacks
/// - Context strings provide domain separation and prevent signature reuse across applications
/// - The signature proves knowledge of the private key without revealing it
/// - Each signature in hedged mode uses fresh randomness
///
/// # Reference
///
/// FIPS 204 Section 5.2 - ML-DSA.Sign
pub fn sign(
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
    mode: SigningMode,
) -> Result<Signature> {
    sign::sign(private_key, message, context, mode)
}

/// Verify a signature.
///
/// This function verifies that a signature is valid for a given message and public key.
/// It checks that the signature was created by the holder of the corresponding private key.
///
/// # Arguments
///
/// * `public_key` - The ML-DSA public key to use for verification
/// * `message` - The message that was signed (must match exactly)
/// * `signature` - The signature to verify
/// * `context` - Context string used during signing (must match exactly)
///
/// # Returns
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
///
/// # Errors
///
/// - `Error::ContextTooLong` if the context exceeds 255 bytes
/// - `Error::VerificationError` if verification process fails
/// - `Error::InvalidSignature` if signature format is invalid
///
/// # Example
///
/// ```no_run
/// use turtl::dsa::{key_gen, sign, verify, SigningMode, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
///
/// let message = b"Message to authenticate";
/// let context = b"";
/// let signature = sign(&private_key, message, context, SigningMode::Hedged)?;
///
/// // Verify with correct message
/// assert!(verify(&public_key, message, &signature, context)?);
///
/// // Verification fails with wrong message
/// let wrong_message = b"Different message";
/// assert!(!verify(&public_key, wrong_message, &signature, context)?);
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - Verification is constant-time to prevent timing side-channel attacks
/// - Both the message and context must match exactly for verification to succeed
/// - A valid signature proves the signer had access to the private key
/// - Invalid signatures return `false` rather than an error
///
/// # Reference
///
/// FIPS 204 Section 5.3 - ML-DSA.Verify
pub fn verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
    context: &[u8],
) -> Result<bool> {
    verify::verify(public_key, message, signature, context)
}

/// Sign a message with pre-hashing.
///
/// This function signs a pre-hashed version of the message rather than the message itself.
/// Pre-hashing is useful for signing large messages, as only the hash needs to be processed
/// by the signature algorithm. This is also known as HashML-DSA.
///
/// # Arguments
///
/// * `private_key` - The ML-DSA private key to use for signing
/// * `message` - The message to hash and sign (arbitrary length)
/// * `context` - Optional context string (up to 255 bytes) for domain separation
/// * `hash_function` - Hash function to use for pre-hashing
/// * `mode` - Signing mode (Hedged or Deterministic)
///
/// # Returns
///
/// A `Signature` that can be verified with `hash_verify` using the same hash function.
///
/// # Errors
///
/// - `Error::ContextTooLong` if the context exceeds 255 bytes
/// - `Error::RandomnessError` if RNG fails (only in Hedged mode)
/// - `Error::SigningError` if signature generation fails
///
/// # Example
///
/// ```no_run
/// use turtl::dsa::{key_gen, hash_sign, hash_verify, SigningMode, HashFunction, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
///
/// // Sign a large message using pre-hashing
/// let large_message = vec![0u8; 1024 * 1024]; // 1 MB
/// let context = b"";
/// let signature = hash_sign(
///     &private_key,
///     &large_message,
///     context,
///     HashFunction::SHA3_256,
///     SigningMode::Hedged
/// )?;
///
/// // Verify using the same hash function
/// let is_valid = hash_verify(
///     &public_key,
///     &large_message,
///     &signature,
///     context,
///     HashFunction::SHA3_256
/// )?;
/// assert!(is_valid);
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - Pre-hashing improves performance for large messages
/// - The hash function used for signing MUST match the one used for verification
/// - Pre-hashing provides collision resistance but not second-preimage resistance
/// - For maximum security with small messages, use `sign()` instead
///
/// # Reference
///
/// FIPS 204 Section 5.4 - HashML-DSA.Sign
pub fn hash_sign(
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
    hash_function: HashFunction,
    mode: SigningMode,
) -> Result<Signature> {
    sign::hash_sign(private_key, message, context, hash_function, mode)
}

/// Verify a signature with pre-hashing.
///
/// This function verifies a signature created with `hash_sign()`. The message is hashed
/// using the specified hash function before verification, matching the pre-hash mode
/// used during signing.
///
/// # Arguments
///
/// * `public_key` - The ML-DSA public key to use for verification
/// * `message` - The message that was signed (will be hashed before verification)
/// * `signature` - The signature to verify
/// * `context` - Context string used during signing (must match exactly)
/// * `hash_function` - Hash function to use (must match the one used for signing)
///
/// # Returns
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
///
/// # Errors
///
/// - `Error::ContextTooLong` if the context exceeds 255 bytes
/// - `Error::VerificationError` if verification process fails
/// - `Error::InvalidSignature` if signature format is invalid
///
/// # Example
///
/// ```no_run
/// use turtl::dsa::{key_gen, hash_sign, hash_verify, SigningMode, HashFunction, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
///
/// let message = vec![0u8; 1024 * 1024]; // Large message
/// let context = b"";
/// let signature = hash_sign(
///     &private_key,
///     &message,
///     context,
///     HashFunction::SHA3_256,
///     SigningMode::Hedged
/// )?;
///
/// // Verify with correct hash function
/// assert!(hash_verify(&public_key, &message, &signature, context, HashFunction::SHA3_256)?);
///
/// // Verification fails with wrong hash function
/// assert!(!hash_verify(&public_key, &message, &signature, context, HashFunction::SHA3_512)?);
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - The hash function MUST match the one used during signing
/// - Verification is constant-time to prevent timing side-channel attacks
/// - The context string must match exactly
/// - Using the wrong hash function will cause verification to fail
///
/// # Reference
///
/// FIPS 204 Section 5.4 - HashML-DSA.Verify
pub fn hash_verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
    context: &[u8],
    hash_function: HashFunction,
) -> Result<bool> {
    verify::hash_verify(public_key, message, signature, context, hash_function)
}
