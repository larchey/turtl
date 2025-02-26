//! Parameter sets for ML-DSA.
//! 
//! This module defines the parameter sets for ML-DSA as specified in NIST FIPS 204.

/// ML-DSA parameter sets
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParameterSet {
    /// ML-DSA-44 (Security Category 2)
    ML_DSA_44,
    /// ML-DSA-65 (Security Category 3)
    ML_DSA_65,
    /// ML-DSA-87 (Security Category 5)
    ML_DSA_87,
}

impl ParameterSet {
    /// Get the dimensions (k, l) of matrix A
    pub fn dimensions(&self) -> (usize, usize) {
        match self {
            Self::ML_DSA_44 => (4, 4),
            Self::ML_DSA_65 => (6, 5),
            Self::ML_DSA_87 => (8, 7),
        }
    }
    
    /// Get the value of parameter d (number of dropped bits)
    pub fn d(&self) -> usize {
        13 // Same for all parameter sets
    }
    
    /// Get the value of parameter tau (number of ±1's in challenge polynomial)
    pub fn tau(&self) -> usize {
        match self {
            Self::ML_DSA_44 => 39,
            Self::ML_DSA_65 => 49,
            Self::ML_DSA_87 => 60,
        }
    }
    
    /// Get the value of parameter gamma1 (coefficient range for mask vector)
    pub fn gamma1(&self) -> usize {
        match self {
            Self::ML_DSA_44 => 1 << 17,
            Self::ML_DSA_65 => 1 << 19,
            Self::ML_DSA_87 => 1 << 19,
        }
    }
    
    /// Get the value of parameter gamma2 (low-order rounding range)
    pub fn gamma2(&self) -> usize {
        match self {
            Self::ML_DSA_44 => (8380417 - 1) / 88,
            Self::ML_DSA_65 => (8380417 - 1) / 32,
            Self::ML_DSA_87 => (8380417 - 1) / 32,
        }
    }
    
    /// Get the value of parameter eta (private key range)
    pub fn eta(&self) -> usize {
        match self {
            Self::ML_DSA_44 => 2,
            Self::ML_DSA_65 => 4,
            Self::ML_DSA_87 => 2,
        }
    }
    
    /// Get the value of parameter beta (= tau * eta)
    pub fn beta(&self) -> usize {
        self.tau() * self.eta()
    }
    
    /// Get the value of parameter omega (max number of 1's in the hint)
    pub fn omega(&self) -> usize {
        match self {
            Self::ML_DSA_44 => 80,
            Self::ML_DSA_65 => 55,
            Self::ML_DSA_87 => 75,
        }
    }
    
    /// Get the size of the commitment challenge hash in bytes
    pub fn lambda(&self) -> usize {
        match self {
            Self::ML_DSA_44 => 128,
            Self::ML_DSA_65 => 192,
            Self::ML_DSA_87 => 256,
        }
    }
    
    /// Get the size of the public key in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::ML_DSA_44 => 1312,
            Self::ML_DSA_65 => 1952,
            Self::ML_DSA_87 => 2592,
        }
    }
    
    /// Get the size of the private key in bytes
    pub fn private_key_size(&self) -> usize {
        match self {
            Self::ML_DSA_44 => 2560,
            Self::ML_DSA_65 => 4032,
            Self::ML_DSA_87 => 4896,
        }
    }
    
    /// Get the size of the signature in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            Self::ML_DSA_44 => 2420,
            Self::ML_DSA_65 => 3309,
            Self::ML_DSA_87 => 4627,
        }
    }
    
    /// Get the security category
    pub fn security_category(&self) -> usize {
        match self {
            Self::ML_DSA_44 => 2,
            Self::ML_DSA_65 => 3,
            Self::ML_DSA_87 => 5,
        }
    }
    
    /// Get the required RBG security strength in bits
    pub fn required_rbg_strength(&self) -> usize {
        match self {
            Self::ML_DSA_44 => 192, // Recommended: 192, Minimum: 128
            Self::ML_DSA_65 => 192,
            Self::ML_DSA_87 => 256,
        }
    }
}