//! Parameter sets for ML-DSA.
//! 
//! This module defines the parameter sets for ML-DSA as specified in NIST FIPS 204.

// We'll bring in Copy, Default, and Sized which ParameterSet already implements
use zeroize::Zeroize;

/// ML-DSA parameter sets
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ParameterSet {
    /// ML-DSA-44 (Security Category 2)
    #[default]
    MlDsa44,
    /// ML-DSA-65 (Security Category 3)
    MlDsa65,
    /// ML-DSA-87 (Security Category 5)
    MlDsa87,
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
    /// Get the dimensions (k, l) of matrix A
    pub fn dimensions(&self) -> (usize, usize) {
        match self {
            Self::MlDsa44 => (4, 4),
            Self::MlDsa65 => (6, 5),
            Self::MlDsa87 => (8, 7),
        }
    }
    
    /// Get the modulus q for ML-DSA
    pub fn q(&self) -> i32 {
        8380417 // Same for all ML-DSA parameter sets per FIPS 204
    }
    
    /// Get the value of parameter d (number of dropped bits)
    pub fn d(&self) -> usize {
        13 // Same for all parameter sets
    }
    
    /// Get the value of parameter tau (number of ±1's in challenge polynomial)
    pub fn tau(&self) -> usize {
        match self {
            Self::MlDsa44 => 39,
            Self::MlDsa65 => 49,
            Self::MlDsa87 => 60,
        }
    }
    
    /// Get the value of parameter gamma1 (coefficient range for mask vector)
    pub fn gamma1(&self) -> usize {
        match self {
            Self::MlDsa44 => 1 << 17,
            Self::MlDsa65 => 1 << 19,
            Self::MlDsa87 => 1 << 19,
        }
    }
    
    /// Get the value of parameter gamma2 (low-order rounding range)
    /// Defined in FIPS 204 as (q-1)/alpha where alpha=88 for ML-DSA-44 and alpha=32 for ML-DSA-65/87
    pub fn gamma2(&self) -> usize {
        match self {
            Self::MlDsa44 => 95268, // Exact value: (8380417 - 1) / 88
            Self::MlDsa65 => 261888, // Exact value: (8380417 - 1) / 32
            Self::MlDsa87 => 261888, // Exact value: (8380417 - 1) / 32
        }
    }
    
    /// Get the value of parameter eta (private key range)
    pub fn eta(&self) -> usize {
        match self {
            Self::MlDsa44 => 2,
            Self::MlDsa65 => 4,
            Self::MlDsa87 => 2,
        }
    }
    
    /// Get the value of parameter beta (= tau * eta)
    pub fn beta(&self) -> usize {
        self.tau() * self.eta()
    }
    
    /// Get the value of parameter omega (max number of 1's in the hint)
    pub fn omega(&self) -> usize {
        match self {
            Self::MlDsa44 => 80,
            Self::MlDsa65 => 55,
            Self::MlDsa87 => 75,
        }
    }
    
    /// Get the size of the commitment challenge hash in bytes
    pub fn lambda(&self) -> usize {
        match self {
            Self::MlDsa44 => 128,
            Self::MlDsa65 => 192,
            Self::MlDsa87 => 256,
        }
    }
    
    /// Get the size of the public key in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }
    
    /// Get the size of the private key in bytes
    pub fn private_key_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 2560,
            Self::MlDsa65 => 4032,
            Self::MlDsa87 => 4896,
        }
    }
    
    /// Get the size of the signature in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }
    
    /// Get the security category
    pub fn security_category(&self) -> usize {
        match self {
            Self::MlDsa44 => 2,
            Self::MlDsa65 => 3,
            Self::MlDsa87 => 5,
        }
    }
    
    /// Get the required RBG security strength in bits
    pub fn required_rbg_strength(&self) -> usize {
        match self {
            Self::MlDsa44 => 192, // Recommended: 192, Minimum: 128
            Self::MlDsa65 => 192,
            Self::MlDsa87 => 256,
        }
    }
}