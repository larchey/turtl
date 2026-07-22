//! Parameter sets for ML-DSA.
//!
//! This module defines the parameter sets for ML-DSA as specified in NIST FIPS 204.

// We'll bring in Copy, Default, and Sized which ParameterSet already implements
use zeroize::Zeroize;

/// ML-DSA parameter sets as defined in FIPS 204.
///
/// Each parameter set provides a different security level and has different key,
/// signature, and computational costs.
///
/// # Security Categories
///
/// NIST defines security categories that roughly correspond to the computational
/// effort required to break symmetric cryptographic algorithms:
///
/// - Category 2: Comparable to SHA-256/SHA3-256 collision resistance
/// - Category 3: Comparable to SHA-384/SHA3-384 collision resistance
/// - Category 5: Comparable to SHA-512/SHA3-512 collision resistance
///
/// # Choosing a Parameter Set
///
/// - Use **ML-DSA-44** for applications requiring security equivalent to SHA-256
/// - Use **ML-DSA-65** for a balance of security and performance (recommended for most applications)
/// - Use **ML-DSA-87** when you need the highest security level equivalent to SHA-512
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ParameterSet {
    /// ML-DSA-44 (Security Category 2, comparable to SHA-256).
    ///
    /// # Specifications
    ///
    /// - Security Category: 2
    /// - Public key size: 1312 bytes
    /// - Private key size: 2560 bytes
    /// - Signature size: 2420 bytes
    /// - Matrix dimensions (k, l): (4, 4)
    ///
    /// # When to Use
    ///
    /// Choose this parameter set when:
    /// - You need smaller keys and signatures
    /// - SHA-256 equivalent security is sufficient
    /// - Bandwidth or storage is constrained
    ///
    /// # Reference
    ///
    /// FIPS 204 Table 1
    #[default]
    MlDsa44,

    /// ML-DSA-65 (Security Category 3, comparable to SHA-384).
    ///
    /// # Specifications
    ///
    /// - Security Category: 3
    /// - Public key size: 1952 bytes
    /// - Private key size: 4032 bytes
    /// - Signature size: 3309 bytes
    /// - Matrix dimensions (k, l): (6, 5)
    ///
    /// # When to Use
    ///
    /// Choose this parameter set when:
    /// - You want a balance between security and performance
    /// - SHA-384 equivalent security is desired
    /// - This is the recommended default for most applications
    ///
    /// # Reference
    ///
    /// FIPS 204 Table 1
    MlDsa65,

    /// ML-DSA-87 (Security Category 5, comparable to SHA-512).
    ///
    /// # Specifications
    ///
    /// - Security Category: 5
    /// - Public key size: 2592 bytes
    /// - Private key size: 4896 bytes
    /// - Signature size: 4627 bytes
    /// - Matrix dimensions (k, l): (8, 7)
    ///
    /// # When to Use
    ///
    /// Choose this parameter set when:
    /// - You need the highest security level
    /// - SHA-512 equivalent security is required
    /// - You can afford larger keys and signatures
    ///
    /// # Reference
    ///
    /// FIPS 204 Table 1
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
    /// Get the dimensions (k, l) of matrix A.
    ///
    /// The matrix A in ML-DSA has dimensions k×l, where k is the number of rows
    /// and l is the number of columns. These dimensions determine the security
    /// level and sizes of keys and signatures.
    ///
    /// Returns:
    /// - (4, 4) for ML-DSA-44
    /// - (6, 5) for ML-DSA-65
    /// - (8, 7) for ML-DSA-87
    ///
    /// # Reference
    ///
    /// FIPS 204 Table 1
    pub fn dimensions(&self) -> (usize, usize) {
        match self {
            Self::MlDsa44 => (4, 4),
            Self::MlDsa65 => (6, 5),
            Self::MlDsa87 => (8, 7),
        }
    }

    /// Get the modulus q for ML-DSA.
    ///
    /// Returns 8380417 for all ML-DSA parameter sets as specified in FIPS 204.
    ///
    /// # Reference
    ///
    /// FIPS 204 Section 5
    pub fn q(&self) -> i32 {
        8380417 // Same for all ML-DSA parameter sets per FIPS 204
    }

    /// Get the value of parameter d (number of dropped bits).
    ///
    /// Returns 13 for all ML-DSA parameter sets as specified in FIPS 204.
    ///
    /// # Reference
    ///
    /// FIPS 204 Table 1
    pub fn d(&self) -> usize {
        13 // Same for all parameter sets
    }

    /// Get the value of parameter tau (number of ±1's in challenge polynomial).
    ///
    /// The challenge polynomial c has exactly tau coefficients equal to ±1,
    /// with the rest being 0.
    ///
    /// Returns:
    /// - 39 for ML-DSA-44
    /// - 49 for ML-DSA-65
    /// - 60 for ML-DSA-87
    ///
    /// # Reference
    ///
    /// FIPS 204 Table 1
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
            Self::MlDsa44 => 95232,  // Exact value: (8380417 - 1) / 88 = 95232
            Self::MlDsa65 => 261888, // Exact value: (8380417 - 1) / 32 = 261888
            Self::MlDsa87 => 261888, // Exact value: (8380417 - 1) / 32 = 261888
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

    /// Get the NIST security category.
    ///
    /// Returns the security category (2, 3, or 5) which indicates the computational
    /// effort required to break the cryptosystem, roughly equivalent to:
    /// - Category 2: SHA-256/SHA3-256 collision resistance
    /// - Category 3: SHA-384/SHA3-384 collision resistance
    /// - Category 5: SHA-512/SHA3-512 collision resistance
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
