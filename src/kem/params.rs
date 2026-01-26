//! Parameter sets for ML-KEM.
//!
//! This module defines the parameter sets for ML-KEM as specified in NIST FIPS 203.
//!
//! ML-KEM is defined over a polynomial ring R_q = Z_q\[X\]/(X^n + 1) where:
//! - n = 256 (the polynomial degree)
//! - q = 3329 (the modulus)
//!
//! Three parameter sets are defined (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
//! with different security levels and parameters.

// We'll bring in Copy, Default, and Sized which ParameterSet already implements
use zeroize::Zeroize;

/// ML-KEM parameter sets as defined in FIPS 203.
///
/// Each parameter set provides a different security level and has different key,
/// ciphertext, and computational costs.
///
/// # Security Categories
///
/// NIST defines security categories that roughly correspond to the computational
/// effort required to break symmetric cryptographic algorithms:
///
/// - Category 1: Comparable to AES-128 (112-128 bits of security)
/// - Category 3: Comparable to AES-192 (160-192 bits of security)
/// - Category 5: Comparable to AES-256 (224-256 bits of security)
///
/// # Choosing a Parameter Set
///
/// - Use **ML-KEM-512** when you need smaller keys/ciphertexts and security equivalent to AES-128
/// - Use **ML-KEM-768** for a balance of security and performance (recommended for most applications)
/// - Use **ML-KEM-1024** when you need the highest security level equivalent to AES-256
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ParameterSet {
    /// ML-KEM-512 (Security Category 1, equivalent to AES-128).
    ///
    /// # Specifications
    ///
    /// - Security Category: 1
    /// - Public key size: 800 bytes
    /// - Private key size: 1632 bytes
    /// - Ciphertext size: 768 bytes
    /// - Shared secret size: 32 bytes
    /// - Matrix dimension (k): 2
    ///
    /// # When to Use
    ///
    /// Choose this parameter set when:
    /// - You need smaller key and ciphertext sizes
    /// - AES-128 equivalent security is sufficient
    /// - Bandwidth or storage is constrained
    ///
    /// # Reference
    ///
    /// FIPS 203 Table 2
    #[default]
    MlKem512,

    /// ML-KEM-768 (Security Category 3, equivalent to AES-192).
    ///
    /// # Specifications
    ///
    /// - Security Category: 3
    /// - Public key size: 1184 bytes
    /// - Private key size: 2400 bytes
    /// - Ciphertext size: 1088 bytes
    /// - Shared secret size: 32 bytes
    /// - Matrix dimension (k): 3
    ///
    /// # When to Use
    ///
    /// Choose this parameter set when:
    /// - You want a balance between security and performance
    /// - AES-192 equivalent security is desired
    /// - This is the recommended default for most applications
    ///
    /// # Reference
    ///
    /// FIPS 203 Table 2
    MlKem768,

    /// ML-KEM-1024 (Security Category 5, equivalent to AES-256).
    ///
    /// # Specifications
    ///
    /// - Security Category: 5
    /// - Public key size: 1568 bytes
    /// - Private key size: 3168 bytes
    /// - Ciphertext size: 1568 bytes
    /// - Shared secret size: 32 bytes
    /// - Matrix dimension (k): 4
    ///
    /// # When to Use
    ///
    /// Choose this parameter set when:
    /// - You need the highest security level
    /// - AES-256 equivalent security is required
    /// - You can afford larger keys and ciphertexts
    ///
    /// # Reference
    ///
    /// FIPS 203 Table 2
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
    /// Get the polynomial ring degree n.
    ///
    /// Returns 256 for all ML-KEM parameter sets as specified in FIPS 203.
    ///
    /// # Reference
    ///
    /// FIPS 203 Section 4.1
    pub fn n(&self) -> usize {
        256 // Same for all ML-KEM parameter sets per FIPS 203
    }

    /// Get the NIST security category.
    ///
    /// Returns the security category (1, 3, or 5) which indicates the computational
    /// effort required to break the cryptosystem, roughly equivalent to:
    /// - Category 1: AES-128
    /// - Category 3: AES-192
    /// - Category 5: AES-256
    pub fn security_category(&self) -> usize {
        match self {
            Self::MlKem512 => 1,
            Self::MlKem768 => 3,
            Self::MlKem1024 => 5,
        }
    }

    /// Get the modulus q for ML-KEM.
    ///
    /// Returns 3329 for all ML-KEM parameter sets as specified in FIPS 203.
    ///
    /// # Reference
    ///
    /// FIPS 203 Section 4.1
    pub fn q(&self) -> i32 {
        3329 // Same for all ML-KEM parameter sets per FIPS 203
    }

    /// Get the value of parameter k (matrix dimension).
    ///
    /// The matrix A in ML-KEM is k×k, and this parameter determines the
    /// security level and sizes of keys and ciphertexts.
    ///
    /// Returns:
    /// - 2 for ML-KEM-512
    /// - 3 for ML-KEM-768
    /// - 4 for ML-KEM-1024
    ///
    /// # Reference
    ///
    /// FIPS 203 Table 2
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

    /// Get the value of parameter d (bits dropped in t)
    pub fn d(&self) -> usize {
        13 // Same for all parameter sets per FIPS 203
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

    /// Get the size of the shared secret in bytes (fixed at 32 bytes)
    pub fn shared_secret_size(&self) -> usize {
        32 // Same for all parameter sets
    }

    /// Get the required RBG security strength in bits
    pub fn required_rbg_strength(&self) -> usize {
        match self {
            Self::MlKem512 => 128,
            Self::MlKem768 => 192,
            Self::MlKem1024 => 256,
        }
    }

    /// Validate that the parameter set is consistent with FIPS 203
    pub fn validate(&self) -> Result<(), &'static str> {
        // These checks are redundant since we're using an enum with fixed values,
        // but they illustrate the validation that would be done in a more flexible implementation

        // Check polynomial degree
        if self.n() != 256 {
            return Err("Invalid polynomial degree n (must be 256)");
        }

        // Check modulus
        if self.q() != 3329 {
            return Err("Invalid modulus q (must be 3329)");
        }

        // Check k parameter
        let k = self.k();
        if !(2..=4).contains(&k) {
            return Err("Invalid k parameter (must be 2, 3, or 4)");
        }

        // Check eta parameters
        let eta1 = self.eta1();
        if !matches!(eta1, 2 | 3) {
            return Err("Invalid eta1 parameter (must be 2 or 3)");
        }

        let eta2 = self.eta2();
        if eta2 != 2 {
            return Err("Invalid eta2 parameter (must be 2)");
        }

        // Check compression parameters
        let du = self.du();
        if !matches!(du, 10 | 11) {
            return Err("Invalid du parameter (must be 10 or 11)");
        }

        let dv = self.dv();
        if !matches!(dv, 4 | 5) {
            return Err("Invalid dv parameter (must be 4 or 5)");
        }

        Ok(())
    }
}
