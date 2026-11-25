//! Error types for the TURTL library.
//!
//! This module defines the error types used throughout the TURTL cryptographic library.
//! All operations return a `Result<T, Error>` type, allowing for proper error handling.

use core::fmt;

/// Error type for the TURTL library.
///
/// This enum represents all possible errors that can occur during cryptographic operations
/// in the TURTL library, including both ML-KEM and ML-DSA operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Randomness generation failed.
    ///
    /// This error occurs when the cryptographically secure random number generator
    /// fails to generate the required randomness. This is extremely rare and typically
    /// indicates a system-level issue with the RNG.
    ///
    /// # When This Occurs
    /// - During key generation when generating random seeds
    /// - During encapsulation when generating random messages
    /// - During signature generation in hedged mode when generating random data
    RandomnessError,

    /// Invalid public key provided.
    ///
    /// This error occurs when a public key has an incorrect format, wrong length,
    /// or contains invalid data that doesn't conform to the expected structure.
    ///
    /// # When This Occurs
    /// - When deserializing a public key with incorrect byte length
    /// - When validating a public key that fails structural checks
    InvalidPublicKey,

    /// Invalid private key provided.
    ///
    /// This error occurs when a private key has an incorrect format, wrong length,
    /// or contains invalid data that doesn't conform to the expected structure.
    ///
    /// # When This Occurs
    /// - When deserializing a private key with incorrect byte length
    /// - When validating a private key that fails structural checks
    /// - When extracting a public key from a malformed private key
    InvalidPrivateKey,

    /// Invalid ciphertext provided.
    ///
    /// This error occurs when a ciphertext has an incorrect format, wrong length,
    /// or contains invalid data for the ML-KEM decapsulation operation.
    ///
    /// # When This Occurs
    /// - When deserializing a ciphertext with incorrect byte length
    /// - When validating a ciphertext that fails structural checks
    InvalidCiphertext,

    /// Invalid signature provided.
    ///
    /// This error occurs when a signature has an incorrect format, wrong length,
    /// or contains invalid data for the ML-DSA verification operation.
    ///
    /// # When This Occurs
    /// - When deserializing a signature with incorrect byte length
    /// - When validating a signature that fails structural checks
    InvalidSignature,

    /// Context string exceeds maximum allowed length.
    ///
    /// This error occurs when the context string provided to ML-DSA signing or
    /// verification operations exceeds the maximum allowed length of 255 bytes.
    ///
    /// # When This Occurs
    /// - When calling `sign()` or `verify()` with a context string longer than 255 bytes
    ///
    /// # Reference
    /// FIPS 204 Section 5.2 specifies the maximum context length
    ContextTooLong,

    /// Invalid parameter set specified.
    ///
    /// This error occurs when an unsupported or invalid parameter set is specified
    /// for cryptographic operations.
    ///
    /// # When This Occurs
    /// - When attempting to use incompatible parameter sets between operations
    /// - When deserializing data with an unrecognized parameter set
    InvalidParameterSet,

    /// Error during encoding or decoding operations.
    ///
    /// This error occurs when polynomial encoding or decoding operations fail,
    /// typically due to malformed input data or constraint violations.
    ///
    /// # When This Occurs
    /// - During polynomial compression/decompression
    /// - During bit packing/unpacking operations
    /// - When encoding constraints are violated
    EncodingError(String),

    /// Invalid input parameter value.
    ///
    /// This error occurs when a function parameter has an invalid value that
    /// violates the function's preconditions.
    ///
    /// # When This Occurs
    /// - When a seed passed to `KeyPair::from_seed` is not 32 bytes
    InvalidParameter(String),
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
            Self::InvalidParameterSet => write!(f, "invalid parameter set"),
            Self::EncodingError(s) => write!(f, "encoding error: {}", s),
            Self::InvalidParameter(s) => write!(f, "invalid parameter: {}", s),
        }
    }
}

impl std::error::Error for Error {}

/// Result type for the TURTL library
pub type Result<T> = core::result::Result<T, Error>;
