//! Parameter sets for ML-KEM.
//! 
//! This module defines the parameter sets for ML-KEM as specified in NIST FIPS 203.

// We'll bring in Copy, Default, and Sized which ParameterSet already implements
use zeroize::Zeroize;

/// ML-KEM parameter sets
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ParameterSet {
    /// ML-KEM-512 (Security Category 1)
    #[default]
    MlKem512,
    /// ML-KEM-768 (Security Category 3)
    MlKem768,
    /// ML-KEM-1024 (Security Category 5)
    MlKem1024,
}

// Create a newtype wrapper for ParameterSet to avoid the conflicting impl
// of Zeroize for types that implement DefaultIsZeroes
#[derive(Clone, Copy, Debug, Default)]
pub struct ZeroizeParameterSet(pub ParameterSet);

impl Zeroize for ZeroizeParameterSet {
    fn zeroize(&mut self) {
        self.0 = ParameterSet::default();
    }
}

impl ParameterSet {
    /// Get the NIST security category
    pub fn security_category(&self) -> usize {
        match self {
            Self::MlKem512 => 1,
            Self::MlKem768 => 3,
            Self::MlKem1024 => 5,
        }
    }
    
    /// Get the modulus q for ML-KEM
    pub fn q(&self) -> i32 {
        3329 // Same for all ML-KEM parameter sets per FIPS 203
    }
    
    /// Get the value of parameter k (matrix dimension)
    pub fn k(&self) -> usize {
        match self {
            Self::MlKem512 => 2,
            Self::MlKem768 => 3,
            Self::MlKem1024 => 4,
        }
    }
    
    /// Get the value of parameter eta1 (coefficient range)
    pub fn eta1(&self) -> usize {
        match self {
            Self::MlKem512 => 3,
            Self::MlKem768 => 2,
            Self::MlKem1024 => 2,
        }
    }
    
    /// Get the value of parameter eta2 (coefficient range)
    pub fn eta2(&self) -> usize {
        match self {
            Self::MlKem512 => 2,
            Self::MlKem768 => 2,
            Self::MlKem1024 => 2,
        }
    }
    
    /// Get the value of parameter du (compression parameter)
    pub fn du(&self) -> usize {
        match self {
            Self::MlKem512 => 10,
            Self::MlKem768 => 10,
            Self::MlKem1024 => 11,
        }
    }
    
    /// Get the value of parameter dv (compression parameter)
    pub fn dv(&self) -> usize {
        match self {
            Self::MlKem512 => 4,
            Self::MlKem768 => 4,
            Self::MlKem1024 => 5,
        }
    }
    
    /// Get the size of the public key in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }
    
    /// Get the size of the private key in bytes
    pub fn private_key_size(&self) -> usize {
        match self {
            Self::MlKem512 => 1632,
            Self::MlKem768 => 2400,
            Self::MlKem1024 => 3168,
        }
    }
    
    /// Get the size of the ciphertext in bytes
    pub fn ciphertext_size(&self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }
    
    /// Get the required RBG security strength in bits
    pub fn required_rbg_strength(&self) -> usize {
        match self {
            Self::MlKem512 => 128,
            Self::MlKem768 => 192,
            Self::MlKem1024 => 256,
        }
    }
}