//! Error types for the TURTL library.

#[cfg(feature = "std")]
use std::fmt;

#[cfg(not(feature = "std"))]
use core::fmt;

/// Error type for the TURTL library
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Randomness generation failed
    RandomnessError,
    
    /// Invalid public key
    InvalidPublicKey,
    
    /// Invalid private key
    InvalidPrivateKey,
    
    /// Invalid ciphertext
    InvalidCiphertext,
    
    /// Invalid signature
    InvalidSignature,
    
    /// Context string too long
    ContextTooLong,
    
    /// Input/output error
    IoError(String),
    
    /// Verification failed
    VerificationFailed,
    
    /// Invalid parameter set
    InvalidParameterSet,
    
    /// Encoding error
    EncodingError(String),
    
    /// Fault detected during cryptographic operation
    FaultDetected,
    
    /// Invalid input parameter value
    InvalidParameter(String),
    
    /// Security boundary violation
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

/// Result type for the TURTL library
pub type Result<T> = core::result::Result<T, Error>;