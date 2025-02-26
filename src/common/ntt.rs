//! Number-Theoretic Transform (NTT) implementation.
//! 
//! This module implements the NTT and its inverse, which are used
//! for efficient polynomial multiplication in both ML-KEM and ML-DSA.

use crate::error::{Error, Result};
use super::poly::Polynomial;
use super::ring::FieldElement;

/// Pre-computed zeta values for the NTT
/// These are the powers of a primitive 512th root of unity modulo q
#[allow(clippy::unreadable_literal)]
const ZETAS: [i32; 256] = [
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
];

/// Context structure for Number-Theoretic Transform operations
pub struct NTTContext {
    /// The modulus q
    pub modulus: i32,
    /// Montgomery reduction constant
    pub qinv: i32,
}

impl NTTContext {
    /// Create a new NTT context for ML-KEM or ML-DSA
    pub fn new() -> Self {
        // ML-KEM and ML-DSA both use the same modulus q = 8380417
        let modulus = 8380417;
        // Montgomery reduction constant for 32-bit arithmetic
        let qinv = 58728449; // Inverse of q modulo 2^32
        
        Self { modulus, qinv }
    }
    
    /// Perform bit reversal on an 8-bit integer
    fn bit_rev_8(&self, mut value: u8) -> u8 {
        let mut result = 0u8;
        for i in 0..8 {
            result |= ((value & 1) << (7 - i));
            value >>= 1;
        }
        result
    }
    
    /// Perform Montgomery reduction
    #[inline(always)]
    fn montgomery_reduce(&self, a: i64) -> i32 {
        // Compute a / R mod q where R = 2^32
        let mut t = ((a as u32) as u64 * self.qinv as u64) as u32;
        t = (a as i64 - (t as i64 * self.modulus as i64)) >> 32;
        t as i32
    }

    /// Forward NTT transform
    pub fn forward(&self, polynomial: &mut Polynomial) -> Result<()> {
        let mut len = 128;
        let mut m = 0;
        
        while len >= 1 {
            let mut start = 0;
            while start < 256 {
                m += 1;
                let zeta = ZETAS[m as usize];
                
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
                    if polynomial.coeffs[j + len] >= self.modulus {
                        polynomial.coeffs[j + len] -= self.modulus;
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
        let mut len = 1;
        let mut m = 256;
        
        while len < 256 {
            let mut start = 0;
            while start < 256 {
                m -= 1;
                // Use negative zeta for inverse NTT
                let zeta = -ZETAS[m as usize];
                
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
                        zeta as i64 * polynomial.coeffs[j + len] as i64
                    );
                }
                
                start += 2 * len;
            }
            
            len *= 2;
        }
        
        // Multiply by n^(-1) mod q = 8347681
        let ninv = 8347681; // 256^(-1) mod q
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
            result.coeffs[i] = self.montgomery_reduce(
                a.coeffs[i] as i64 * b.coeffs[i] as i64
            );
        }
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ntt_roundtrip() {
        let ctx = NTTContext::new();
        
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
    fn test_ntt_multiplication() {
        let ctx = NTTContext::new();
        
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
        // Basic check: c[0] should be a[0]*b[0]
        assert_eq!(c.coeffs[0], (a_orig.coeffs[0] as i64 * b_orig.coeffs[0] as i64 % ctx.modulus as i64) as i32);
    }
}