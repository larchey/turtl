//! Auxiliary functions for ML-KEM.
//!
//! This module provides helper functions used in the ML-KEM implementation.
use zeroize::Zeroizing;

/// Convert between bytes and bits
///
/// The buffer is wiped on drop: it often holds bits of secret coefficients.
pub(crate) fn bytes_to_bits(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut bits = Zeroizing::new(Vec::with_capacity(bytes.len() * 8));
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
