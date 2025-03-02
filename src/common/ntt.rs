//! Number-Theoretic Transform (NTT) implementations.
//! 
//! This module contains separate NTT implementations for ML-KEM and ML-DSA,
//! which use different moduli and parameters.

use crate::error::Result;
use super::poly::Polynomial;

/// NTT implementation for a specific cryptographic algorithm
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NTTType {
    /// ML-KEM (q = 3329)
    MLKEM,
    /// ML-DSA (q = 8380417)
    MLDSA,
}

/// Context structure for Number-Theoretic Transform operations
pub struct NTTContext {
    /// The type of NTT (determines modulus and parameters)
    ntt_type: NTTType,
    /// The modulus q
    pub modulus: i32,
    /// Montgomery reduction constant
    pub qinv: i32,
    /// Precomputed zeta values for NTT
    zetas: Vec<i32>,
    /// Montgomery constant R^2 mod q (for conversion to Montgomery form)
    r2: i32,
}

impl NTTContext {
    /// Create a new NTT context for the specified algorithm
    pub fn new(ntt_type: NTTType) -> Self {
        match ntt_type {
            NTTType::MLKEM => {
                // ML-KEM parameters from FIPS 203
                let modulus = 3329;
                let qinv = 3327; // q^(-1) mod 2^16 for ML-KEM
                let r2 = 1353; // 2^16 mod 3329
                
                // Precomputed zetas for ML-KEM (n = 256, q = 3329)
                // Root of unity ζ = 17
                let zetas = Self::precompute_zetas_mlkem();
                
                Self { ntt_type, modulus, qinv, zetas, r2 }
            },
            NTTType::MLDSA => {
                // ML-DSA parameters from FIPS 204
                let modulus = 8380417;
                let qinv = 58728449; // q^(-1) mod 2^32 for ML-DSA
                let r2 = 145; // 2^32^2 mod 8380417
                
                // Precomputed zetas for ML-DSA
                let zetas = Self::precompute_zetas_mldsa();
                
                Self { ntt_type, modulus, qinv, zetas, r2 }
            }
        }
    }
    
    /// Precompute zeta values for ML-KEM (q = 3329, ζ = 17)
    fn precompute_zetas_mlkem() -> Vec<i32> {
        // ML-KEM zeta values
        // These are precomputed powers of the primitive 256th root of unity (ζ = 17)
        // in bit-reversed order for the NTT algorithm
        vec![
            1, 1729, 2580, 3289, 2642, 630, 1897, 848,
            1062, 1919, 193, 797, 2786, 3260, 569, 1746,
            296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
            1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
            289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
            650, 1977, 2513, 632, 2865, 33, 1320, 1915,
            2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
            2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
            17, 2761, 583, 2649, 1637, 723, 2288, 1100,
            1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
            1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
            939, 2308, 2437, 2388, 733, 2337, 268, 641,
            1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
            1063, 319, 2773, 757, 2099, 561, 2466, 2594,
            2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
            1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
        ]
    }
    
    /// Precompute zeta values for ML-DSA (q = 8380417)
    fn precompute_zetas_mldsa() -> Vec<i32> {
        // ML-DSA zeta values
        // These are precomputed powers of the primitive 256th root of unity
        // for the ML-DSA modulus q = 8380417
        vec![
            0, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
            7778734, 3542485, 2682288, 2129892, 3764867, 7375178, 557458, 7159240,
            5010068, 4317364, 2663378, 6705802, 4855975, 7946292, 676590, 7044481,
            5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
            3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
            394148, 928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
            3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
            5483103, 3192354, 556856, 3870317, 2917338, 1853806, 3345963, 1858416,
            3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
            2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
            1528066, 482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034,
            4213992, 4892034, 1987814, 5183169, 1736313, 235407, 5130263, 3258457,
            5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
            7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816, 3374250,
            1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
            348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
            1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
            1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502, 4663471,
            8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
            6695264, 4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040,
            4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
            3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
            2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156, 6161950,
            7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
            6757063, 2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006,
            6903432, 1994046, 2491325, 6987258, 507927, 7192532, 7655613, 6545891,
            5346675, 8041997, 2647994, 3009748, 5767564, 4148469, 749577, 4357667,
            3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
            3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976,
            3105558, 7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265,
            6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
            8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983
        ]
    }
    
    /// Perform Montgomery reduction based on the current modulus
    #[inline(always)]
    fn montgomery_reduce(&self, a: i64) -> i32 {
        match self.ntt_type {
            NTTType::MLKEM => {
                // 16-bit Montgomery reduction for ML-KEM
                let mut t: i32 = ((a as i32) as u32 * (self.qinv as u32)) as i32 & 0xFFFF;
                t = (a as i32 - (t * self.modulus)) >> 16;
                if t < 0 {
                    t += self.modulus;
                }
                t
            },
            NTTType::MLDSA => {
                // 32-bit Montgomery reduction for ML-DSA
                let mut t = ((a as u32) as u64 * self.qinv as u64) as u32;
                t = ((a as i64 - (t as i64 * self.modulus as i64)) >> 32) as u32;
                t as i32
            }
        }
    }

    /// Convert to Montgomery form
    pub fn to_montgomery(&self, a: i32) -> i32 {
        self.montgomery_reduce(a as i64 * self.r2 as i64)
    }

    /// Convert from Montgomery form
    pub fn from_montgomery(&self, a: i32) -> i32 {
        self.montgomery_reduce(a as i64)
    }

    /// Forward NTT transform
    pub fn forward(&self, polynomial: &mut Polynomial) -> Result<()> {
        match self.ntt_type {
            NTTType::MLKEM => self.forward_mlkem(polynomial),
            NTTType::MLDSA => self.forward_mldsa(polynomial),
        }
    }
    
    /// Forward NTT transform for ML-KEM (q = 3329)
    fn forward_mlkem(&self, polynomial: &mut Polynomial) -> Result<()> {
        let mut len = 128;
        let mut k = 1;
        
        while len >= 2 {
            for start in (0..256).step_by(2 * len) {
                let zeta = self.zetas[k];
                k += 1;
                
                for j in start..(start + len) {
                    let t = ((zeta as i64 * polynomial.coeffs[j + len] as i64) % self.modulus as i64) as i32;
                    polynomial.coeffs[j + len] = (polynomial.coeffs[j] - t) % self.modulus;
                    if polynomial.coeffs[j + len] < 0 {
                        polynomial.coeffs[j + len] += self.modulus;
                    }
                    
                    polynomial.coeffs[j] = (polynomial.coeffs[j] + t) % self.modulus;
                    if polynomial.coeffs[j] >= self.modulus {
                        polynomial.coeffs[j] -= self.modulus;
                    }
                }
            }
            
            len >>= 1;
        }
        
        Ok(())
    }
    
    /// Forward NTT transform for ML-DSA (q = 8380417)
    fn forward_mldsa(&self, polynomial: &mut Polynomial) -> Result<()> {
        let mut len = 128;
        let mut m = 0;
        
        while len >= 1 {
            let mut start = 0;
            while start < 256 {
                m += 1;
                let zeta = self.zetas[m as usize % self.zetas.len()];
                
                for j in start..(start + len) {
                    let t = self.montgomery_reduce(
                        zeta as i64 * polynomial.coeffs[j + len] as i64
                    );
                    polynomial.coeffs[j + len] = polynomial.coeffs[j] - t;
                    polynomial.coeffs[j] = polynomial.coeffs[j] + t;
                    
                    // Ensure coefficients stay in the range [0, q-1]
                    if polynomial.coeffs[j] >= self.modulus {
                        polynomial.coeffs[j] -= self.modulus;
                    }
                    if polynomial.coeffs[j + len] < 0 {
                        polynomial.coeffs[j + len] += self.modulus;
                    }
                }
                
                start += 2 * len;
            }
            
            len >>= 1;
        }
        
        Ok(())
    }
    
    /// Inverse NTT transform
    pub fn inverse(&self, polynomial: &mut Polynomial) -> Result<()> {
        match self.ntt_type {
            NTTType::MLKEM => self.inverse_mlkem(polynomial),
            NTTType::MLDSA => self.inverse_mldsa(polynomial),
        }
    }
    
    /// Inverse NTT transform for ML-KEM
    fn inverse_mlkem(&self, polynomial: &mut Polynomial) -> Result<()> {
        // Implementation based on FIPS 203 specification
        let mut len = 2;
        let mut k = 127; // Start from the last zeta value
        
        while len <= 128 {
            for start in (0..256).step_by(2 * len) {
                let zeta_inv = self.modulus - self.zetas[k]; // -zeta mod q
                k -= 1;
                
                for j in start..(start + len) {
                    let t = polynomial.coeffs[j];
                    
                    polynomial.coeffs[j] = (t + polynomial.coeffs[j + len]) % self.modulus;
                    if polynomial.coeffs[j] >= self.modulus {
                        polynomial.coeffs[j] -= self.modulus;
                    }
                    
                    polynomial.coeffs[j + len] = (t - polynomial.coeffs[j + len]) % self.modulus;
                    if polynomial.coeffs[j + len] < 0 {
                        polynomial.coeffs[j + len] += self.modulus;
                    }
                    
                    polynomial.coeffs[j + len] = ((zeta_inv as i64 * polynomial.coeffs[j + len] as i64) 
                                               % self.modulus as i64) as i32;
                }
            }
            
            len <<= 1;
        }
        
        // Multiply by n^(-1) mod q = 3303 for ML-KEM
        let n_inv = 3303; // 256^(-1) mod 3329
        for i in 0..256 {
            polynomial.coeffs[i] = ((n_inv as i64 * polynomial.coeffs[i] as i64) 
                                  % self.modulus as i64) as i32;
            if polynomial.coeffs[i] >= self.modulus {
                polynomial.coeffs[i] -= self.modulus;
            }
        }
        
        Ok(())
    }
    
    /// Inverse NTT transform for ML-DSA
    fn inverse_mldsa(&self, polynomial: &mut Polynomial) -> Result<()> {
        let mut len = 1;
        let mut m = 256;
        
        while len < 256 {
            let mut start = 0;
            while start < 256 {
                m -= 1;
                let zeta_inv = self.modulus - self.zetas[m as usize % self.zetas.len()];
                
                for j in start..(start + len) {
                    let t = polynomial.coeffs[j];
                    
                    polynomial.coeffs[j] = t + polynomial.coeffs[j + len];
                    if polynomial.coeffs[j] >= self.modulus {
                        polynomial.coeffs[j] -= self.modulus;
                    }
                    
                    polynomial.coeffs[j + len] = t - polynomial.coeffs[j + len];
                    if polynomial.coeffs[j + len] < 0 {
                        polynomial.coeffs[j + len] += self.modulus;
                    }
                    
                    polynomial.coeffs[j + len] = self.montgomery_reduce(
                        zeta_inv as i64 * polynomial.coeffs[j + len] as i64
                    );
                }
                
                start += 2 * len;
            }
            
            len *= 2;
        }
        
        // Multiply by n^(-1) mod q
        let ninv = 8347681; // 256^(-1) mod 8380417 for ML-DSA
        for i in 0..256 {
            polynomial.coeffs[i] = self.montgomery_reduce(
                ninv as i64 * polynomial.coeffs[i] as i64
            );
        }
        
        Ok(())
    }
    
    /// Multiply two polynomials in the NTT domain
    pub fn multiply_ntt(&self, a: &Polynomial, b: &Polynomial) -> Result<Polynomial> {
        let mut result = Polynomial::new();
        
        for i in 0..256 {
            match self.ntt_type {
                NTTType::MLKEM => {
                    // For ML-KEM, simple coefficient-wise multiplication modulo q
                    result.coeffs[i] = ((a.coeffs[i] as i64 * b.coeffs[i] as i64) % self.modulus as i64) as i32;
                    if result.coeffs[i] < 0 {
                        result.coeffs[i] += self.modulus;
                    }
                },
                NTTType::MLDSA => {
                    // For ML-DSA, use Montgomery multiplication
                    result.coeffs[i] = self.montgomery_reduce(
                        a.coeffs[i] as i64 * b.coeffs[i] as i64
                    );
                }
            }
        }
        
        Ok(result)
    }

    /// Get the modulus based on NTT type
    pub fn get_modulus(&self) -> i32 {
        self.modulus
    }

    /// Get the NTT type
    pub fn get_ntt_type(&self) -> NTTType {
        self.ntt_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mlkem_ntt_roundtrip() {
        let ctx = NTTContext::new(NTTType::MLKEM);
        
        // Create a test polynomial
        let mut poly = Polynomial::new();
        for i in 0..256 {
            poly.coeffs[i] = (i as i32 * 7 + 1) % ctx.modulus;
        }
        
        // Save a copy
        let original = poly.clone();
        
        // Forward NTT
        ctx.forward(&mut poly).unwrap();
        
        // Inverse NTT
        ctx.inverse(&mut poly).unwrap();
        
        // Check that we get the original polynomial back
        for i in 0..256 {
            assert_eq!(poly.coeffs[i], original.coeffs[i]);
        }
    }
    
    #[test]
    fn test_mldsa_ntt_roundtrip() {
        let ctx = NTTContext::new(NTTType::MLDSA);
        
        // Create a test polynomial
        let mut poly = Polynomial::new();
        for i in 0..256 {
            poly.coeffs[i] = (i as i32 * 7 + 1) % ctx.modulus;
        }
        
        // Save a copy
        let original = poly.clone();
        
        // Forward NTT
        ctx.forward(&mut poly).unwrap();
        
        // Inverse NTT
        ctx.inverse(&mut poly).unwrap();
        
        // Check that we get the original polynomial back
        for i in 0..256 {
            assert_eq!(poly.coeffs[i], original.coeffs[i]);
        }
    }

    #[test]
    fn test_mlkem_ntt_multiplication() {
        let ctx = NTTContext::new(NTTType::MLKEM);
        
        // Create two test polynomials
        let mut a = Polynomial::new();
        let mut b = Polynomial::new();
        
        for i in 0..256 {
            a.coeffs[i] = (i as i32 * 3 + 1) % ctx.modulus;
            b.coeffs[i] = (i as i32 * 5 + 2) % ctx.modulus;
        }
        
        // Save copies
        let a_orig = a.clone();
        let b_orig = b.clone();
        
        // Transform to NTT domain
        ctx.forward(&mut a).unwrap();
        ctx.forward(&mut b).unwrap();
        
        // Multiply in NTT domain
        let mut c = ctx.multiply_ntt(&a, &b).unwrap();
        
        // Transform back
        ctx.inverse(&mut c).unwrap();
        
        // This should equal the convolution of a_orig and b_orig
        // Check a basic property: c[0] should be a[0]*b[0]
        assert_eq!(c.coeffs[0], (a_orig.coeffs[0] as i64 * b_orig.coeffs[0] as i64 % ctx.modulus as i64) as i32);
    }

    #[test]
    fn test_mldsa_ntt_multiplication() {
        let ctx = NTTContext::new(NTTType::MLDSA);
        
        // Create two test polynomials
        let mut a = Polynomial::new();
        let mut b = Polynomial::new();
        
        for i in 0..256 {
            a.coeffs[i] = (i as i32 * 3 + 1) % ctx.modulus;
            b.coeffs[i] = (i as i32 * 5 + 2) % ctx.modulus;
        }
        
        // Save copies
        let a_orig = a.clone();
        let b_orig = b.clone();
        
        // Transform to NTT domain
        ctx.forward(&mut a).unwrap();
        ctx.forward(&mut b).unwrap();
        
        // Multiply in NTT domain
        let mut c = ctx.multiply_ntt(&a, &b).unwrap();
        
        // Transform back
        ctx.inverse(&mut c).unwrap();
        
        // This should equal the convolution of a_orig and b_orig
        // Check a basic property: c[0] should be a[0]*b[0]
        assert_eq!(c.coeffs[0], (a_orig.coeffs[0] as i64 * b_orig.coeffs[0] as i64 % ctx.modulus as i64) as i32);
    }
}