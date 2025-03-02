//! Auxiliary functions for ML-KEM.
//! 
//! This module provides helper functions used in the ML-KEM implementation.
/// Convert between bytes and bits
pub(crate) fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for &byte in bytes {
        for j in 0..8 {
            bits.push((byte >> j) & 1);
        }
    }
    bits
}



/// Compute the ceiling of log base 2 of an integer
pub(crate) fn ceil_log2(x: u32) -> u32 {
    if x <= 1 {
        return 0;
    }
    32 - (x - 1).leading_zeros()
}

