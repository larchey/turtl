//! Error types for the TURTL library.

use core::fmt;

#[cfg(feature = "std")]
use thiserror::Error;

/// Error type for the TURTL library
#[cfg_attr(feature = "std", derive(Error))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Randomness generation failed
    #[cfg_attr(feature = "std", error("randomness generation failed"))]
    RandomnessError,
    
    /// Invalid public key
    #[cfg_attr(feature = "std", error("invalid public key"))]
    InvalidPublicKey,
    
    /// Invalid private key
    #[cfg_attr(feature = "std", error("invalid private key"))]
    InvalidPrivateKey,
    
    /// Invalid ciphertext
    #[cfg_attr(feature = "std", error("invalid ciphertext"))]
    InvalidCiphertext,
    
    /// Invalid signature
    #[cfg_attr(feature = "std", error("invalid signature"))]
    InvalidSignature,
    
    /// Context string too long
    #[cfg_attr(feature = "std", error("context string too long (max 255 bytes)"))]
    ContextTooLong,
    
    /// Input/output error
    #[cfg_attr(feature = "std", error("I/O error: {0}"))]
    IoError(String),
    
    /// Verification failed
    #[cfg_attr(feature = "std", error("verification failed"))]
    VerificationFailed,
    
    /// Invalid parameter set
    #[cfg_attr(feature = "std", error("invalid parameter set"))]
    InvalidParameterSet,
    
    /// Encoding error
    #[cfg_attr(feature = "std", error("encoding error: {0}"))]
    EncodingError(String),
}

#[cfg(not(feature = "std"))]
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
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Result type for the TURTL library
pub type Result<T> = core::result::Result<T, Error>;