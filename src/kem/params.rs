//! Parameter sets for ML-KEM.
//! 
//! This module defines the parameter sets for ML-KEM as specified in NIST FIPS 203.

/// ML-KEM parameter sets
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParameterSet {
    /// ML-KEM-512 (Security Category 1)
    ML_KEM_512,
    /// ML-KEM-768 (Security Category 3)
    ML_KEM_768,
    /// ML-KEM-1024 (Security Category 5)
    ML_KEM_1024,
}

impl ParameterSet {
    /// Get the NIST security category
    pub fn security_category(&self) -> usize {
        match self {
            Self::ML_KEM_512 => 1,
            Self::ML_KEM_768 => 3,
            Self::ML_KEM_1024 => 5,
        }
    }
    
    /// Get the modulus q for ML-KEM
    pub fn q(&self) -> i32 {
        3329 // Same for all ML-KEM parameter sets per FIPS 203
    }
    
    /// Get the value of parameter k (matrix dimension)
    pub fn k(&self) -> usize {
        match self {
            Self::ML_KEM_512 => 2,
            Self::ML_KEM_768 => 3,
            Self::ML_KEM_1024 => 4,
        }
    }
    
    /// Get the value of parameter eta1 (coefficient range)
    pub fn eta1(&self) -> usize {
        match self {
            Self::ML_KEM_512 => 3,
            Self::ML_KEM_768 => 2,
            Self::ML_KEM_1024 => 2,
        }
    }
    
    /// Get the value of parameter eta2 (coefficient range)
    pub fn eta2(&self) -> usize {
        match self {
            Self::ML_KEM_512 => 2,
            Self::ML_KEM_768 => 2,
            Self::ML_KEM_1024 => 2,
        }
    }
    
    /// Get the value of parameter du (compression parameter)
    pub fn du(&self) -> usize {
        match self {
            Self::ML_KEM_512 => 10,
            Self::ML_KEM_768 => 10,
            Self::ML_KEM_1024 => 11,
        }
    }
    
    /// Get the value of parameter dv (compression parameter)
    pub fn dv(&self) -> usize {
        match self {
            Self::ML_KEM_512 => 4,
            Self::ML_KEM_768 => 4,
            Self::ML_KEM_1024 => 5,
        }
    }
    
    /// Get the size of the public key in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::ML_KEM_512 => 800,
            Self::ML_KEM_768 => 1184,
            Self::ML_KEM_1024 => 1568,
        }
    }
    
    /// Get the size of the private key in bytes
    pub fn private_key_size(&self) -> usize {
        match self {
            Self::ML_KEM_512 => 1632,
            Self::ML_KEM_768 => 2400,
            Self::ML_KEM_1024 => 3168,
        }
    }
    
    /// Get the size of the ciphertext in bytes
    pub fn ciphertext_size(&self) -> usize {
        match self {
            Self::ML_KEM_512 => 768,
            Self::ML_KEM_768 => 1088,
            Self::ML_KEM_1024 => 1568,
        }
    }
    
    /// Get the required RBG security strength in bits
    pub fn required_rbg_strength(&self) -> usize {
        match self {
            Self::ML_KEM_512 => 128,
            Self::ML_KEM_768 => 192,
            Self::ML_KEM_1024 => 256,
        }
    }
}