//! Error types for the TURTL library.
//!
//! This module defines the error types used throughout TURTL. All functions
//! that can fail return a `Result<T, Error>` where `Error` is the enum
//! defined in this module.

#[cfg(feature = "std")]
use std::fmt;

#[cfg(not(feature = "std"))]
use core::fmt;

/// Error type for the TURTL library.
///
/// This enum represents all possible errors that can occur when using TURTL's
/// cryptographic operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Randomness generation failed.
    ///
    /// This error occurs when the system's cryptographically secure random number
    /// generator fails to produce random bytes. This is extremely rare and typically
    /// indicates a serious system-level problem, such as:
    /// - `/dev/urandom` or equivalent being unavailable
    /// - System entropy pool being exhausted (very rare on modern systems)
    /// - Hardware RNG failure
    ///
    /// # When it occurs
    ///
    /// - During key generation (`key_gen()`)
    /// - During encapsulation (`encapsulate()`)
    /// - During signature generation in hedged mode (`sign()` with `SigningMode::Hedged`)
    /// - During implicit rejection in decapsulation (rare edge case)
    RandomnessError,

    /// Invalid public key.
    ///
    /// This error indicates that a public key is malformed or has an incorrect size.
    ///
    /// # When it occurs
    ///
    /// - When creating a `PublicKey` with bytes that don't match the expected length
    ///   for the parameter set
    /// - When deserializing a public key from storage or network transmission
    /// - When extracting a public key from a private key fails
    InvalidPublicKey,

    /// Invalid private key.
    ///
    /// This error indicates that a private key is malformed or has an incorrect size.
    ///
    /// # When it occurs
    ///
    /// - When creating a `PrivateKey` with bytes that don't match the expected length
    ///   for the parameter set
    /// - When deserializing a private key from storage
    /// - When the internal structure of a private key is corrupted
    InvalidPrivateKey,

    /// Invalid ciphertext.
    ///
    /// This error indicates that a ciphertext is malformed or has an incorrect size.
    ///
    /// # When it occurs
    ///
    /// - When creating a `Ciphertext` with bytes that don't match the expected length
    ///   for the parameter set
    /// - When deserializing a ciphertext from network transmission
    ///
    /// # Note
    ///
    /// ML-KEM uses implicit rejection, so invalid ciphertexts during decapsulation
    /// do NOT produce this error. Instead, they return a pseudorandom shared secret.
    InvalidCiphertext,

    /// Invalid signature.
    ///
    /// This error indicates that a signature is malformed or has an incorrect size.
    ///
    /// # When it occurs
    ///
    /// - When creating a `Signature` with bytes that don't match the expected length
    ///   for the parameter set
    /// - When deserializing a signature from storage or network transmission
    ///
    /// # Note
    ///
    /// This error indicates a malformed signature structure, not a verification failure.
    /// Verification failures return `Ok(false)` from `verify()`.
    InvalidSignature,

    /// Context string too long.
    ///
    /// This error occurs when the context string provided to ML-DSA signing or
    /// verification exceeds the maximum allowed length of 255 bytes.
    ///
    /// # When it occurs
    ///
    /// - When calling `sign()` or `verify()` with a context longer than 255 bytes
    /// - When calling `hash_sign()` or `hash_verify()` with a context longer than 255 bytes
    ///
    /// # FIPS 204 Requirement
    ///
    /// The 255-byte limit is specified in FIPS 204 and is enforced by this implementation.
    ContextTooLong,

    /// Input/output error.
    ///
    /// This error wraps I/O errors that occur during file operations or other
    /// I/O-related tasks.
    ///
    /// # When it occurs
    ///
    /// - When reading or writing keys to/from files
    /// - When serializing or deserializing cryptographic objects
    /// - Other I/O operations in higher-level wrappers
    IoError(String),

    /// Verification failed.
    ///
    /// This error is reserved for explicit verification failures in contexts where
    /// returning a boolean would be inappropriate.
    ///
    /// # Note
    ///
    /// The public `verify()` functions return `Ok(false)` for invalid signatures
    /// rather than this error, making them more ergonomic to use.
    VerificationFailed,

    /// Invalid parameter set.
    ///
    /// This error occurs when an operation is attempted with an invalid or
    /// unsupported parameter set.
    ///
    /// # When it occurs
    ///
    /// - When trying to use a test-only parameter set in production code
    /// - When deserializing a parameter set with an unrecognized identifier
    /// - When mixing incompatible parameter sets (e.g., using ML-KEM-512 key
    ///   with ML-KEM-768 ciphertext)
    InvalidParameterSet,

    /// Encoding error.
    ///
    /// This error occurs when encoding or decoding cryptographic structures fails.
    ///
    /// # When it occurs
    ///
    /// - When polynomial encoding produces out-of-range values
    /// - When bit packing/unpacking fails
    /// - When internal serialization/deserialization fails
    EncodingError(String),

    /// Fault detected during cryptographic operation.
    ///
    /// This error indicates that a fault injection attack was detected during
    /// a cryptographic operation. The operation has been aborted to prevent
    /// leaking secret information.
    ///
    /// # When it occurs
    ///
    /// - When fault detection mechanisms detect an integrity violation
    /// - When redundant computations produce inconsistent results
    /// - When security invariants are violated during execution
    ///
    /// # Security
    ///
    /// This error is part of TURTL's defense against fault injection attacks,
    /// where an attacker tries to induce errors during computation to extract
    /// secret keys. If you encounter this error in normal operation, it may
    /// indicate:
    /// - Hardware failure or bit flips (cosmic rays, etc.)
    /// - Active fault injection attack
    /// - Software bug (please report!)
    FaultDetected,

    /// Invalid input parameter value.
    ///
    /// This error occurs when a function receives an invalid parameter value
    /// that doesn't meet the required constraints.
    ///
    /// # When it occurs
    ///
    /// - When parameters are out of valid ranges
    /// - When internal validation checks fail
    /// - When preconditions are not met
    InvalidParameter(String),

    /// Security boundary violation.
    ///
    /// This error indicates that an operation would violate security boundaries
    /// or invariants.
    ///
    /// # When it occurs
    ///
    /// - When attempting operations that could compromise security
    /// - When security-critical invariants would be violated
    /// - When boundary checks detect potential attacks
    ///
    /// # Security
    ///
    /// This error helps maintain security invariants and prevent misuse of
    /// cryptographic primitives. If encountered, review the operation for
    /// correctness.
    SecurityBoundaryViolation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomnessError => write!(f, "randomness generation failed"),
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidPrivateKey => write!(f, "invalid private key"),
            Self::InvalidCiphertext => write!(f, "invalid ciphertext"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::ContextTooLong => write!(f, "context string too long (max 255 bytes)"),
            Self::IoError(s) => write!(f, "I/O error: {}", s),
            Self::VerificationFailed => write!(f, "verification failed"),
            Self::InvalidParameterSet => write!(f, "invalid parameter set"),
            Self::EncodingError(s) => write!(f, "encoding error: {}", s),
            Self::FaultDetected => write!(f, "fault detected during cryptographic operation"),
            Self::InvalidParameter(s) => write!(f, "invalid parameter: {}", s),
            Self::SecurityBoundaryViolation => write!(f, "security boundary violation"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result type for the TURTL library.
///
/// This is a type alias for `core::result::Result<T, Error>` and is used
/// throughout TURTL for operations that can fail.
///
/// # Example
///
/// ```rust
/// use turtl::error::{Error, Result};
///
/// fn example_function() -> Result<String> {
///     Ok("Success".to_string())
/// }
/// ```
pub type Result<T> = core::result::Result<T, Error>;
