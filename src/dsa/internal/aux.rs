//! Auxiliary functions for ML-DSA.
//! 
//! This module provides helper functions used in the ML-DSA implementation.

use crate::error::{Error, Result};
use crate::common::poly::Polynomial;
use crate::dsa::ParameterSet;

/// Convert from Montgomery form to standard form
pub(crate) fn from_montgomery(x: i32, q: i32, qinv: i32) -> i32 {
    montgomery_multiply(x, 1, q, qinv)
}

/// Convert to Montgomery form
pub(crate) fn to_montgomery(x: i32, q: i32, qinv: i32, r2modq: i32) -> i32 {
    montgomery_multiply(x, r2modq, q, qinv)
}

/// Montgomery multiplication
pub(crate) fn montgomery_multiply(a: i32, b: i32, q: i32, qinv: i32) -> i32 {
    let t = (a as i64 * b as i64) as i32;
    let m = ((t as u32).wrapping_mul(qinv as u32)) as u32;
    let u = ((t as i64 + (m as i64 * q as i64)) >> 32) as i32;
    
    if u >= q {
        u - q
    } else {
        u
    }
}

/// Count the number of one bits in a byte
pub(crate) fn popcount(x: u8) -> u32 {
    x.count_ones()
}

/// Bit-reverse an 8-bit integer
pub(crate) fn bit_reverse_8(mut x: u8) -> u8 {
    let mut result = 0u8;
    for i in 0..8 {
        result |= ((x & 1) << (7 - i));
        x >>= 1;
    }
    result
}

/// Constant-time conditional swap of two polynomials
pub(crate) fn cswap(a: &mut Polynomial, b: &mut Polynomial, swap: bool) {
    let mask = if swap { -1i32 } else { 0i32 };
    
    for i in 0..256 {
        let t = mask & (a.coeffs[i] ^ b.coeffs[i]);
        a.coeffs[i] ^= t;
        b.coeffs[i] ^= t;
    }
}

/// Constant-time conditional selection between two integers
pub(crate) fn cselect(a: i32, b: i32, selector: bool) -> i32 {
    let mask = if selector { -1i32 } else { 0i32 };
    
    (mask & (b ^ a)) ^ a
}

/// Power2Round for ML-DSA
pub(crate) fn power2round(r: i32, d: usize) -> (i32, i32) {
    let r0 = r & ((1 << d) - 1);
    let r1 = (r - r0) >> d;
    
    (r1, r0)
}

/// Decompose for ML-DSA - returns high and low bits
pub(crate) fn decompose(r: i32, alpha: usize, q: i32) -> (i32, i32) {
    // Centered remainder modulo 2*alpha
    let mut r0 = r % (2 * alpha as i32);
    if r0 > alpha as i32 {
        r0 -= 2 * alpha as i32;
    } else if r0 <= -(alpha as i32) {
        r0 += 2 * alpha as i32;
    }
    
    // Quotient
    let r1 = (r - r0) / (2 * alpha as i32);
    
    (r1, r0)
}

/// Make hint for high bits
pub(crate) fn make_hint(z: i32, ct0: i32, alpha: usize, q: i32) -> i32 {
    let (z1, _) = decompose(z, alpha, q);
    let (v1, _) = decompose(z - ct0, alpha, q);
    
    if z1 != v1 { 1 } else { 0 }
}

/// Use hint to recover high bits
pub(crate) fn use_hint(h: i32, r: i32, alpha: usize, q: i32) -> i32 {
    let (r1, r0) = decompose(r, alpha, q);
    
    if h == 1 {
        let d = if r0 > 0 { 1 } else { -1 };
        (r1 + d) % ((q - 1) / (2 * alpha as i32))
    } else {
        r1
    }
}

/// Calculate the bit length of a positive integer
pub(crate) fn bitlen(n: usize) -> usize {
    if n == 0 { 
        return 0; 
    }
    
    (n as f64).log2().ceil() as usize
}

/// Convert a polynomial to centered representation
pub(crate) fn to_centered_representation(poly: &mut Polynomial, q: i32) {
    let half_q = q / 2;
    for i in 0..256 {
        if poly.coeffs[i] > half_q {
            poly.coeffs[i] -= q;
        }
    }
}

/// Check if a polynomial's coefficients are within range
pub(crate) fn check_range(poly: &Polynomial, bound: i32) -> bool {
    for &coeff in &poly.coeffs {
        if coeff.abs() >= bound {
            return false;
        }
    }
    true
}

/// Count the number of 1's in a hint polynomial vector
pub(crate) fn count_ones(hint: &[Polynomial]) -> usize {
    let mut count = 0;
    for poly in hint {
        for &coeff in &poly.coeffs {
            if coeff == 1 {
                count += 1;
            }
        }
    }
    count
}