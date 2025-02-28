//! Auxiliary functions for ML-KEM.
//! 
//! This module provides helper functions used in the ML-KEM implementation.

use crate::error::{Error, Result};
use crate::common::poly::Polynomial;

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

/// Convert between bits and bytes
pub(crate) fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    let num_bytes = (bits.len() + 7) / 8;
    let mut bytes = vec![0u8; num_bytes];
    
    for (i, &bit) in bits.iter().enumerate() {
        if bit != 0 {
            bytes[i / 8] |= 1 << (i % 8);
        }
    }
    
    bytes
}

/// Compute the ceiling of log base 2 of an integer
pub(crate) fn ceil_log2(x: u32) -> u32 {
    if x <= 1 {
        return 0;
    }
    32 - (x - 1).leading_zeros()
}

/// Montgomery reduction for modular arithmetic
pub(crate) fn montgomery_reduce(a: i64) -> i32 {
    const QINV: u32 = 58728449; // q^(-1) mod 2^32
    const Q: u32 = 8380417;
    
    let mut t = ((a as u32) as u64 * QINV as u64) as u32;
    let temp = (a as i64 - (t as i64 * Q as i64)) >> 32;
    t = temp as u32;
    t as i32
}

/// Bit-reverse a number with a given bit width
pub(crate) fn bit_reverse(mut x: u32, bit_width: u32) -> u32 {
    let mut result = 0u32;
    for _ in 0..bit_width {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    result
}