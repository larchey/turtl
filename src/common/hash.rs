//! Hash function wrappers for ML-KEM and ML-DSA.
//! 
//! This module provides wrappers around SHAKE and SHA3 hash functions
//! used in both ML-KEM and ML-DSA algorithms.

use sha3::{Shake128, Shake256, Sha3_256, Sha3_512, Digest, digest::{Update, ExtendableOutput, XofReader}};
use crate::error::{Error, Result};
use sha3::digest::Update;

/// Hash/XOF function type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashFunction {
    /// SHA3-256 hash function
    SHA3_256,
    /// SHA3-512 hash function
    SHA3_512,
    /// SHAKE128 extendable-output function
    SHAKE128,
    /// SHAKE256 extendable-output function
    SHAKE256,
}

/// Wrapper for SHAKE256 extendable-output function
pub fn shake256(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, input);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

/// Wrapper for SHAKE128 extendable-output function
pub fn shake128(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake128::default();
    Update::update(&mut hasher, input);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; output_len];
    reader.read(&mut output);
    output
}

/// Wrapper for SHA3-256 hash function
pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Update::update(&mut hasher, input);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Wrapper for SHA3-512 hash function
pub fn sha3_512(input: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    Update::update(&mut hasher, input);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// Generate two 32-byte outputs from a single input using SHA3-512
pub fn g_function(input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let output = sha3_512(input);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    
    a.copy_from_slice(&output[0..32]);
    b.copy_from_slice(&output[32..64]);
    
    (a, b)
}

/// H function (SHAKE256 wrapper) as used in ML-KEM and ML-DSA
pub fn h_function(input: &[u8], output_len: usize) -> Vec<u8> {
    shake256(input, output_len)
}

/// SHAKE256 context for incremental operations
pub struct SHAKE256Context {
    inner: Shake256,
}

impl SHAKE256Context {
    /// Initialize a new SHAKE256 context
    pub fn init() -> Self {
        Self { inner: Shake256::default() }
    }
    
    /// Absorb input data
    pub fn absorb(&mut self, input: &[u8]) {
        self.inner.update(input);
    }
    
    /// Squeeze output bytes
    pub fn squeeze(&mut self, output_len: usize) -> Vec<u8> {
        let mut output = vec![0u8; output_len];
        let mut reader = self.inner.clone().finalize_xof();
        reader.read(&mut output);
        output
    }
}

/// SHAKE128 context for incremental operations
pub struct SHAKE128Context {
    inner: Shake128,
}

impl SHAKE128Context {
    /// Initialize a new SHAKE128 context
    pub fn init() -> Self {
        Self { inner: Shake128::default() }
    }
    
    /// Absorb input data
    pub fn absorb(&mut self, input: &[u8]) {
        self.inner.update(input);
    }
    
    /// Squeeze output bytes
    pub fn squeeze(&mut self, output_len: usize) -> Vec<u8> {
        let mut output = vec![0u8; output_len];
        let mut reader = self.inner.clone().finalize_xof();
        reader.read(&mut output);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_shake256() {
        let input = b"TURTL test input";
        let output = shake256(input, 32);
        
        // Output should be 32 bytes
        assert_eq!(output.len(), 32);
        
        // Output should be deterministic
        let output2 = shake256(input, 32);
        assert_eq!(output, output2);
    }
    
    #[test]
    fn test_shake128() {
        let input = b"TURTL test input";
        let output = shake128(input, 16);
        
        // Output should be 16 bytes
        assert_eq!(output.len(), 16);
        
        // Output should be deterministic
        let output2 = shake128(input, 16);
        assert_eq!(output, output2);
    }
    
    #[test]
    fn test_g_function() {
        let input = b"TURTL test input";
        let (a, b) = g_function(input);
        
        // Each output should be 32 bytes
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
        
        // Outputs should be different
        assert_ne!(a, b);
    }
    
    #[test]
    fn test_shake256_context() {
        let mut ctx = SHAKE256Context::init();
        
        // Absorb data in multiple chunks
        ctx.absorb(b"TURTL ");
        ctx.absorb(b"test ");
        ctx.absorb(b"input");
        
        // Squeeze output
        let output1 = ctx.squeeze(32);
        
        // Squeeze more output
        let output2 = ctx.squeeze(32);
        
        // Outputs should be different
        assert_ne!(output1, output2);
        
        // Compare with one-shot approach
        let expected = shake256(b"TURTL test input", 32);
        assert_eq!(output1, expected);
    }
}