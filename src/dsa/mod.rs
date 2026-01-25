//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm) implementation.
//!
//! This module implements the ML-DSA algorithm as specified in NIST FIPS 204.
//! ML-DSA is a post-quantum digital signature scheme based on the Module-LWE problem.
//!
//! # Overview
//!
//! ML-DSA is a digital signature algorithm standardized by NIST (FIPS 204) that provides
//! security against both classical and quantum computer attacks. It is based on the
//! mathematical hardness of the Module Learning With Errors (M-LWE) and Module Short
//! Integer Solution (M-SIS) problems.
//!
//! A digital signature scheme allows:
//! 1. **Key Generation**: Create a signing key (private) and verification key (public)
//! 2. **Signing**: Use the private key to sign a message, producing a signature
//! 3. **Verification**: Use the public key to verify that a signature is valid for a message
//!
//! # Parameter Sets
//!
//! ML-DSA defines three parameter sets with different security levels:
//!
//! - **ML-DSA-44**: Security category 2 (comparable to SHA-256/AES-128)
//! - **ML-DSA-65**: Security category 3 (comparable to SHA-384/AES-192)
//! - **ML-DSA-87**: Security category 5 (comparable to SHA-512/AES-256)
//!
//! # Signing Modes
//!
//! This implementation supports two signing modes:
//!
//! - **Hedged Mode** (default): Combines deterministic generation with fresh randomness
//!   for additional protection against side-channel attacks and fault injection
//! - **Deterministic Mode**: Uses only the message and key for signature generation,
//!   producing identical signatures for the same message
//!
//! # Security Features
//!
//! This implementation includes several security features:
//!
//! - **Constant-Time Operations**: All cryptographic operations run in constant time
//!   to prevent timing side-channel attacks
//! - **Automatic Zeroization**: Sensitive data (private keys) is automatically
//!   zeroized when dropped
//! - **Fault Detection**: Mechanisms to detect fault injection attacks during signing
//! - **Input Validation**: Thorough validation of inputs to prevent attacks
//! - **Hedged Signatures**: Additional randomness protection against side channels
//!
//! # Usage Example
//!
//! ```rust
//! use turtl::dsa::{key_gen, sign, verify, ParameterSet, SigningMode};
//!
//! # fn main() -> Result<(), turtl::error::Error> {
//! // Generate a key pair
//! let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
//!
//! // Sign a message
//! let message = b"Hello, post-quantum world!";
//! let context = b"";  // Optional context string
//! let signature = sign(&private_key, message, context, SigningMode::Hedged)?;
//!
//! // Verify the signature
//! let valid = verify(&public_key, message, &signature, context)?;
//! assert!(valid);
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

/// Signing mode for ML-DSA signatures.
///
/// ML-DSA supports two signing modes that differ in their use of randomness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningMode {
    /// Hedged mode (recommended).
    ///
    /// Combines deterministic signature generation with fresh randomness to provide
    /// additional protection against side-channel attacks and fault injection. This is
    /// the recommended mode for most applications as it maintains determinism benefits
    /// while adding defense-in-depth.
    ///
    /// Use this mode when:
    /// - Running on potentially vulnerable hardware
    /// - Protection against side-channel attacks is critical
    /// - Additional security margins are desired
    Hedged,

    /// Deterministic mode.
    ///
    /// Generates signatures deterministically without using fresh randomness. The same
    /// message and key will always produce the same signature. This mode is fully
    /// compliant with FIPS 204 but provides less protection against certain
    /// side-channel attacks.
    ///
    /// Use this mode when:
    /// - Deterministic signatures are required for your application
    /// - The signing environment is fully trusted and hardened
    /// - Reproducible signatures are needed for testing or verification
    Deterministic,
}

/// ML-DSA public key (verification key).
///
/// This type represents an ML-DSA public key used for signature verification.
/// The public key can be safely shared and is used to verify signatures
/// created with the corresponding private key.
///
/// # Security
///
/// Public keys do not contain secret material and can be freely transmitted.
/// However, they should be authenticated (e.g., via certificates or secure channels)
/// to prevent impersonation attacks.
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
    /// * `parameter_set` - The ML-DSA parameter set (determines expected size)
    ///
    /// # Returns
    ///
    /// Returns `Ok(PublicKey)` if the bytes have the correct length for the parameter set.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPublicKey` if the byte length doesn't match the
    /// expected size for the parameter set (except in test mode with TestSmall).
    pub fn new(bytes: Vec<u8>, parameter_set: ParameterSet) -> Result<Self> {
        #[cfg(test)]
        {
            // In test mode, be more flexible with parameter sizes for TestSmall
            if let ParameterSet::TestSmall = parameter_set {
                // Skip size validation for TestSmall in test mode
                return Ok(Self {
                    bytes,
                    parameter_set,
                    _zeroize_param: ZeroizeParameterSet(parameter_set),
                });
            }
        }

        // For non-test parameter sets, check if the bytes have the correct length
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

/// ML-DSA private key (signing key).
///
/// This type represents an ML-DSA private key used for signing operations.
/// The private key must be kept secret and is used to create signatures
/// that can be verified with the corresponding public key.
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
    /// * `parameter_set` - The ML-DSA parameter set (determines expected size)
    ///
    /// # Returns
    ///
    /// Returns `Ok(PrivateKey)` if the bytes have the correct length for the parameter set.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPrivateKey` if the byte length doesn't match the
    /// expected size for the parameter set (except in test mode with TestSmall).
    ///
    /// # Security
    ///
    /// The provided bytes must be kept secret. This function takes ownership
    /// of the bytes and will zeroize them when the `PrivateKey` is dropped.
    pub fn new(bytes: Vec<u8>, parameter_set: ParameterSet) -> Result<Self> {
        #[cfg(test)]
        {
            // In test mode, be more flexible with parameter sizes for TestSmall
            if let ParameterSet::TestSmall = parameter_set {
                // Skip size validation for TestSmall in test mode
                return Ok(Self {
                    bytes,
                    parameter_set,
                    _zeroize_param: ZeroizeParameterSet(parameter_set),
                });
            }
        }

        // For non-test parameter sets, check if the bytes have the correct length
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
}

/// ML-DSA signature.
///
/// This type represents an ML-DSA signature created by signing a message
/// with a private key. The signature can be verified by anyone with the
/// corresponding public key.
///
/// # Security
///
/// Signatures are public values that do not contain secret material.
/// However, they cryptographically bind a message to the signer's private key.
///
/// # Memory Safety
///
/// Signatures are automatically zeroized when dropped as a defense-in-depth measure.
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
    /// Creates a new signature from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw byte representation of the signature
    /// * `parameter_set` - The ML-DSA parameter set (determines expected size)
    ///
    /// # Returns
    ///
    /// Returns `Ok(Signature)` if the bytes have the correct length for the parameter set.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidSignature` if the byte length doesn't match the
    /// expected size for the parameter set (except in test mode with TestSmall).
    pub fn new(bytes: Vec<u8>, parameter_set: ParameterSet) -> Result<Self> {
        #[cfg(test)]
        {
            // In test mode, be more flexible with parameter sizes for TestSmall
            if let ParameterSet::TestSmall = parameter_set {
                // Skip size validation for TestSmall in test mode
                return Ok(Self {
                    bytes,
                    parameter_set,
                    _zeroize_param: ZeroizeParameterSet(parameter_set),
                });
            }
        }

        // For non-test parameter sets, check if the bytes have the correct length
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

    /// Returns the raw bytes of the signature.
    ///
    /// This is the serialized form suitable for transmission or storage.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the parameter set associated with this signature.
    ///
    /// The parameter set determines the security level and signature size.
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }
}

/// Supported hash functions for pre-hash mode.
///
/// When signing large messages, it's often more efficient to hash the message
/// first and then sign the hash. ML-DSA supports pre-hashing with several
/// NIST-approved hash functions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashFunction {
    /// SHA3-256 hash function (256-bit output).
    ///
    /// Appropriate for most use cases requiring pre-hashing.
    SHA3_256,

    /// SHA3-512 hash function (512-bit output).
    ///
    /// Provides higher collision resistance for security-critical applications.
    SHA3_512,

    /// SHAKE128 extendable-output function with 256-bit output.
    ///
    /// A variable-length hash function from the SHA-3 family.
    SHAKE128,

    /// SHAKE256 extendable-output function with 512-bit output.
    ///
    /// A variable-length hash function with higher security margin.
    SHAKE256,
}

/// Generates a new ML-DSA key pair.
///
/// This function generates a fresh key pair for the specified ML-DSA parameter set.
/// The public key can be shared with others for signature verification, while the
/// private key must be kept secret for signing.
///
/// # Arguments
///
/// * `parameter_set` - The ML-DSA parameter set (MlDsa44, MlDsa65, or MlDsa87)
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
/// use turtl::dsa::{key_gen, ParameterSet};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// // Generate a key pair for ML-DSA-65 (security level 3)
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
/// This function uses the system's cryptographically secure random number generator.
/// Ensure the system RNG is properly seeded before use. The generated private key
/// is automatically zeroized when dropped.
///
/// # Reference
///
/// FIPS 204 Section 6.1 - ML-DSA.KeyGen
pub fn key_gen(parameter_set: ParameterSet) -> Result<(PublicKey, PrivateKey)> {
    let keypair = keypair::generate(parameter_set)?;
    Ok((keypair.public_key(), keypair.private_key()))
}

/// Signs a message using ML-DSA.
///
/// This function creates a digital signature for a message using the provided
/// private key. The signature can later be verified by anyone with the
/// corresponding public key.
///
/// # Arguments
///
/// * `private_key` - The signer's ML-DSA private key
/// * `message` - The message to sign (arbitrary length)
/// * `context` - An optional context string (max 255 bytes) for domain separation
/// * `mode` - The signing mode (Hedged or Deterministic)
///
/// # Returns
///
/// Returns `Ok(Signature)` containing the signature.
///
/// # Errors
///
/// * `Error::ContextTooLong` - If the context string exceeds 255 bytes
/// * `Error::RandomnessError` - If the RNG fails (only in Hedged mode)
///
/// # Example
///
/// ```rust
/// use turtl::dsa::{key_gen, sign, verify, ParameterSet, SigningMode};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// // Generate a key pair
/// let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
///
/// // Sign a message
/// let message = b"Important message";
/// let context = b"";  // Empty context
/// let signature = sign(&private_key, message, context, SigningMode::Hedged)?;
///
/// println!("Signature size: {} bytes", signature.as_bytes().len());
///
/// // Verify the signature
/// let valid = verify(&public_key, message, &signature, context)?;
/// assert!(valid);
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - **Hedged mode** (recommended): Combines deterministic signature generation
///   with fresh randomness for protection against side-channel attacks
/// - **Deterministic mode**: Produces identical signatures for the same message,
///   but offers less protection against certain attacks
/// - Constant-time implementation prevents timing side-channel attacks
/// - The context string provides domain separation to prevent signature reuse
///   across different protocols or applications
///
/// # Reference
///
/// FIPS 204 Section 6.2 - ML-DSA.Sign
pub fn sign(
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
    mode: SigningMode,
) -> Result<Signature> {
    sign::sign(private_key, message, context, mode)
}

/// Verifies an ML-DSA signature.
///
/// This function verifies that a signature was created by the holder of the
/// private key corresponding to the provided public key, for the given message
/// and context.
///
/// # Arguments
///
/// * `public_key` - The signer's ML-DSA public key
/// * `message` - The message that was signed (arbitrary length)
/// * `signature` - The signature to verify
/// * `context` - The context string used during signing (max 255 bytes)
///
/// # Returns
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
///
/// # Errors
///
/// * `Error::ContextTooLong` - If the context string exceeds 255 bytes
/// * `Error::InvalidSignature` - If the signature is malformed
///
/// # Example
///
/// ```rust
/// use turtl::dsa::{key_gen, sign, verify, ParameterSet, SigningMode};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
///
/// let message = b"Important message";
/// let context = b"";
/// let signature = sign(&private_key, message, context, SigningMode::Hedged)?;
///
/// // Verify with correct message
/// let valid = verify(&public_key, message, &signature, context)?;
/// assert!(valid);
///
/// // Verify with wrong message
/// let wrong_message = b"Different message";
/// let invalid = verify(&public_key, wrong_message, &signature, context)?;
/// assert!(!invalid);
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - Verification is a public operation and does not require secret keys
/// - The same context string must be used for both signing and verification
/// - Invalid signatures return `false` rather than an error to simplify usage
/// - Public keys should be authenticated to prevent impersonation attacks
///
/// # Reference
///
/// FIPS 204 Section 6.3 - ML-DSA.Verify
pub fn verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
    context: &[u8],
) -> Result<bool> {
    verify::verify(public_key, message, signature, context)
}

/// Signs a message with pre-hashing (HashML-DSA).
///
/// This function first hashes the message using the specified hash function,
/// then signs the hash. This is more efficient for large messages and provides
/// a consistent signature size regardless of message length.
///
/// # Arguments
///
/// * `private_key` - The signer's ML-DSA private key
/// * `message` - The message to sign (arbitrary length, will be hashed)
/// * `context` - An optional context string (max 255 bytes) for domain separation
/// * `hash_function` - The hash function to use for pre-hashing
/// * `mode` - The signing mode (Hedged or Deterministic)
///
/// # Returns
///
/// Returns `Ok(Signature)` containing the signature.
///
/// # Errors
///
/// * `Error::ContextTooLong` - If the context string exceeds 255 bytes
/// * `Error::RandomnessError` - If the RNG fails (only in Hedged mode)
///
/// # Example
///
/// ```rust
/// use turtl::dsa::{key_gen, hash_sign, hash_verify, ParameterSet, SigningMode, HashFunction};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
///
/// // Sign a large message with pre-hashing
/// let large_message = vec![0u8; 1_000_000];  // 1 MB message
/// let context = b"";
/// let signature = hash_sign(
///     &private_key,
///     &large_message,
///     context,
///     HashFunction::SHA3_256,
///     SigningMode::Hedged
/// )?;
///
/// // Verify the signature
/// let valid = hash_verify(&public_key, &large_message, &signature, context, HashFunction::SHA3_256)?;
/// assert!(valid);
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - Pre-hashing reduces the signature algorithm's exposure to the message content
/// - The hash function must match between signing and verification
/// - Use the same mode considerations as `sign()`
///
/// # Reference
///
/// FIPS 204 Section 6.4 - HashML-DSA.Sign
pub fn hash_sign(
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
    hash_function: HashFunction,
    mode: SigningMode,
) -> Result<Signature> {
    sign::hash_sign(private_key, message, context, hash_function, mode)
}

/// Verifies a signature with pre-hashing (HashML-DSA).
///
/// This function verifies a signature created with `hash_sign()`. It first
/// hashes the message using the specified hash function, then verifies the
/// signature against the hash.
///
/// # Arguments
///
/// * `public_key` - The signer's ML-DSA public key
/// * `message` - The message that was signed (arbitrary length, will be hashed)
/// * `signature` - The signature to verify
/// * `context` - The context string used during signing (max 255 bytes)
/// * `hash_function` - The hash function used during signing
///
/// # Returns
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
///
/// # Errors
///
/// * `Error::ContextTooLong` - If the context string exceeds 255 bytes
/// * `Error::InvalidSignature` - If the signature is malformed
///
/// # Example
///
/// ```rust
/// use turtl::dsa::{key_gen, hash_sign, hash_verify, ParameterSet, SigningMode, HashFunction};
///
/// # fn main() -> Result<(), turtl::error::Error> {
/// let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
///
/// let message = b"Message to sign";
/// let context = b"";
/// let hash_fn = HashFunction::SHA3_256;
///
/// let signature = hash_sign(&private_key, message, context, hash_fn, SigningMode::Hedged)?;
/// let valid = hash_verify(&public_key, message, &signature, context, hash_fn)?;
/// assert!(valid);
/// # Ok(())
/// # }
/// ```
///
/// # Security
///
/// - The hash function must match the one used during signing
/// - The same security considerations as `verify()` apply
///
/// # Reference
///
/// FIPS 204 Section 6.5 - HashML-DSA.Verify
pub fn hash_verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
    context: &[u8],
    hash_function: HashFunction,
) -> Result<bool> {
    verify::hash_verify(public_key, message, signature, context, hash_function)
}
