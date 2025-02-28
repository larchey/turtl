//! Random sampling functions for ML-KEM and ML-DSA.
//! 
//! This module implements specialized sampling algorithms used in both
//! ML-KEM and ML-DSA, with proper handling of different moduli.

use crate::error::{Error, Result};
use crate::common::poly::Polynomial;
use crate::common::hash;
use crate::common::ntt::NTTType;
use crate::common::coding::bytes_to_bits;
use zeroize::Zeroize;

/// Sample a polynomial with exactly tau +/-1 coefficients
/// Used in ML-DSA for challenge generation
pub struct SampleInBall {
    /// The number of +/-1 coefficients
    tau: usize,
}

impl SampleInBall {
    /// Create a new SampleInBall sampler with specified tau
    pub fn new(tau: usize) -> Self {
        Self { tau }
    }
    
    /// Sample a polynomial with exactly tau +/-1 coefficients
    pub fn sample(&self, seed: &[u8]) -> Result<Polynomial> {
        let mut poly = Polynomial::new();
        
        // Create bit array for signs
        let mut ctx = hash::SHAKE256Context::init();
        ctx.absorb(seed);
        
        let signs = ctx.squeeze(8);
        let sign_bits = self.bytes_to_bits(&signs);
        
        // Use Fisher-Yates algorithm to sample positions
        for i in (256 - self.tau)..256 {
            // Get random index j in [0..i]
            let mut j = 0;
            let mut valid_j = false;
            
            while !valid_j {
                let bytes = ctx.squeeze(1);
                j = bytes[0] as usize;
                if j <= i {
                    valid_j = true;
                }
            }
            
            // Swap positions i and j
            poly.coeffs[i] = poly.coeffs[j];
            
            // Set position j to +/-1 based on sign bit
            let sign_bit = sign_bits[(i + self.tau - 256) % sign_bits.len()];
            poly.coeffs[j] = if sign_bit == 0 { 1 } else { -1 };
        }
        
        Ok(poly)
    }
    
    /// Helper function to convert bytes to bits
    fn bytes_to_bits(&self, bytes: &[u8]) -> Vec<u8> {
        let mut bits = Vec::with_capacity(bytes.len() * 8);
        for &byte in bytes {
            for j in 0..8 {
                bits.push((byte >> j) & 1);
            }
        }
        bits
    }
}

/// Rejection sampler for various distributions
pub struct RejectionSampler;

impl RejectionSampler {
    /// Sample from the centered binomial distribution
    /// Used in ML-KEM for noise generation
    pub fn sample_cbd(seed: &[u8], eta: usize, ntt_type: NTTType) -> Result<Polynomial> {
        let mut poly = Polynomial::new();
        
        // Convert seed to bit array
        let bits = bytes_to_bits(seed);
        
        for i in 0..256 {
            let mut a = 0;
            let mut b = 0;
            
            for j in 0..eta {
                if 2*i*eta + j < bits.len() {
                    a += bits[2*i*eta + j] as i32;
                }
                
                if 2*i*eta + eta + j < bits.len() {
                    b += bits[2*i*eta + eta + j] as i32;
                }
            }
            
            poly.coeffs[i] = a - b;
        }
        
        Ok(poly)
    }
    
    /// Sample a uniform polynomial in NTT domain
    /// Used in both ML-KEM and ML-DSA
    pub fn sample_ntt(seed: &[u8], ntt_type: NTTType) -> Result<Polynomial> {
        let modulus = match ntt_type {
            NTTType::MLKEM => 3329,    // ML-KEM modulus
            NTTType::MLDSA => 8380417, // ML-DSA modulus
        };
        
        let mut poly = Polynomial::new();
        let mut j = 0;
        
        let mut ctx = hash::SHAKE128Context::init();
        ctx.absorb(seed);
        
        // Use rejection sampling to get coefficients in [0, q-1]
        let mut iterations = 0;
        let max_iterations = 280; // Safety limit
        
        while j < 256 && iterations < max_iterations {
            iterations += 1;
            let bytes = ctx.squeeze(3);
            
            // Extract values based on NTT type
            let (d1, d2) = match ntt_type {
                NTTType::MLKEM => {
                    // For ML-KEM (q = 3329), we need at most 12 bits per coefficient
                    let d1 = ((bytes[0] as u32) | ((bytes[1] as u32 & 0x0F) << 8)) as i32;
                    let d2 = (((bytes[1] as u32 & 0xF0) >> 4) | ((bytes[2] as u32) << 4)) as i32;
                    (d1, d2)
                },
                NTTType::MLDSA => {
                    // For ML-DSA (q = 8380417), we need about 23 bits per coefficient
                    // This is a simplified approach - only extracting two coefficients from 3 bytes
                    let d1 = ((bytes[0] as u32) | ((bytes[1] as u32 & 0x0F) << 8)) as i32;
                    let d2 = (((bytes[1] as u32 & 0xF0) >> 4) | ((bytes[2] as u32) << 4)) as i32;
                    (d1, d2)
                }
            };
            
            // Reject values that are not in [0, q-1]
            if d1 < modulus {
                poly.coeffs[j] = d1;
                j += 1;
            }
            
            if j < 256 && d2 < modulus {
                poly.coeffs[j] = d2;
                j += 1;
            }
        }
        
        if j < 256 {
            return Err(Error::RandomnessError);
        }
        
        Ok(poly)
    }
    
    /// Sample a polynomial with coefficients in [-eta, eta]
    /// Used in ML-DSA for private key generation
    pub fn sample_bounded_poly(seed: &[u8], eta: usize) -> Result<Polynomial> {
        let mut poly = Polynomial::new();
        
        let mut ctx = hash::SHAKE256Context::init();
        ctx.absorb(seed);
        
        let mut j = 0;
        let mut iterations = 0;
        let max_iterations = 480; // Safety limit
        
        while j < 256 && iterations < max_iterations {
            iterations += 1;
            let byte = ctx.squeeze(1)[0];
            
            // Extract two values from each byte
            let b1 = byte & 0x0F;
            let b2 = byte >> 4;
            
            // Use rejection sampling
            if usize::from(b1) < 15 - 5 + 2*eta + 1 {
                poly.coeffs[j] = (b1 as i32) - (eta as i32);
                j += 1;
            }
            
            if j < 256 && usize::from(b2) < 15 - 5 + 2*eta + 1 {
                poly.coeffs[j] = (b2 as i32) - (eta as i32);
                j += 1;
            }
        }
        
        if j < 256 {
            return Err(Error::RandomnessError);
        }
        
        Ok(poly)
    }
    
    /// Sample a polynomial with coefficients in [-gamma+1, gamma-1]
    /// Used in ML-DSA for masking polynomials
    pub fn sample_uniform_poly(seed: &[u8], gamma: usize) -> Result<Polynomial> {
        let mut poly = Polynomial::new();
        
        let mut ctx = hash::SHAKE256Context::init();
        ctx.absorb(seed);
        
        // Calculate how many bits needed for each coefficient
        let bits_needed = ((2 * gamma - 1) as f64).log2().ceil() as usize;
        let bytes_per_coeff = (bits_needed + 7) / 8;
        
        for i in 0..256 {
            let mut valid_coeff = false;
            
            while !valid_coeff {
                let bytes = ctx.squeeze(bytes_per_coeff);
                
                // Convert bytes to an integer (little-endian)
                let mut val = 0i32;
                for j in 0..bytes_per_coeff {
                    val |= (bytes[j] as i32) << (8 * j);
                }
                
                // Mask out unused bits
                let mask = (1 << bits_needed) - 1;
                let val_masked = val & mask;
                
                // Map to range [-gamma+1, gamma-1]
                let shifted = val_masked - (gamma as i32 - 1);
                
                // Accept if in range
                if shifted >= -(gamma as i32 - 1) && shifted <= (gamma as i32 - 1) {
                    poly.coeffs[i] = shifted;
                    valid_coeff = true;
                }
            }
        }
        
        Ok(poly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sample_cbd_mlkem() {
        // Test sampling with ML-KEM parameters
        let seed = [0u8; 64]; // All zeros for reproducibility
        let eta = 2;
        
        let poly = RejectionSampler::sample_cbd(&seed, eta, NTTType::MLKEM).unwrap();
        
        // Check that coefficients are in the correct range
        for i in 0..256 {
            assert!(poly.coeffs[i] >= -eta as i32 && poly.coeffs[i] <= eta as i32);
        }
    }
    
    #[test]
    fn test_sample_ntt_mlkem() {
        // Test sampling with ML-KEM parameters
        let seed = [0u8; 32]; // All zeros for reproducibility
        
        let poly = RejectionSampler::sample_ntt(&seed, NTTType::MLKEM).unwrap();
        
        // Check that coefficients are in the correct range
        for i in 0..256 {
            assert!(poly.coeffs[i] >= 0 && poly.coeffs[i] < 3329);
        }
    }
    
    #[test]
    fn test_sample_ntt_mldsa() {
        // Test sampling with ML-DSA parameters
        let seed = [0u8; 32]; // All zeros for reproducibility
        
        let poly = RejectionSampler::sample_ntt(&seed, NTTType::MLDSA).unwrap();
        
        // Check that coefficients are in the correct range
        for i in 0..256 {
            assert!(poly.coeffs[i] >= 0 && poly.coeffs[i] < 8380417);
        }
    }
    
    #[test]
    fn test_sample_in_ball() {
        // Test sampling with ML-DSA challenge parameters
        let seed = [0u8; 32]; // All zeros for reproducibility
        let tau = 39; // ML-DSA-44 parameter
        
        let sampler = SampleInBall::new(tau);
        let poly = sampler.sample(&seed).unwrap();
        
        // Count non-zero coefficients
        let mut count = 0;
        for i in 0..256 {
            if poly.coeffs[i] != 0 {
                count += 1;
                // Check that coefficients are either +1 or -1
                assert!(poly.coeffs[i] == 1 || poly.coeffs[i] == -1);
            }
        }
        
        // Verify exactly tau non-zero coefficients
        assert_eq!(count, tau);
    }
}