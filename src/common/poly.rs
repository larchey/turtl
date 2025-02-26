//! Polynomial operations for ML-KEM and ML-DSA.
//! 
//! This module implements basic polynomial arithmetic in the ring 
//! ℤq[X]/(X^256 + 1) used by both ML-KEM and ML-DSA.

use crate::error::{Error, Result};
use zeroize::Zeroize;

/// A polynomial in the ring ℤq[X]/(X^256 + 1)
#[derive(Clone, Debug, Zeroize)]
pub struct Polynomial {
    /// Coefficients of the polynomial
    pub coeffs: [i32; 256],
}

impl Polynomial {
    /// Create a new zero polynomial
    pub fn new() -> Self {
        Self { coeffs: [0; 256] }
    }
    
    /// Create a new polynomial from an array of coefficients
    pub fn from_coeffs(coeffs: [i32; 256]) -> Self {
        Self { coeffs }
    }
    
    /// Create a new polynomial with all coefficients set to a single value
    pub fn from_value(value: i32) -> Self {
        Self { coeffs: [value; 256] }
    }
    
    /// Add another polynomial to this one (modulo q)
    pub fn add_assign(&mut self, other: &Self, modulus: i32) {
        for i in 0..256 {
            self.coeffs[i] = (self.coeffs[i] + other.coeffs[i]) % modulus;
        }
    }
    
    /// Subtract another polynomial from this one (modulo q)
    pub fn sub_assign(&mut self, other: &Self, modulus: i32) {
        for i in 0..256 {
            self.coeffs[i] = (self.coeffs[i] - other.coeffs[i]) % modulus;
            if self.coeffs[i] < 0 {
                self.coeffs[i] += modulus;
            }
        }
    }

    /// Multiply this polynomial by a scalar (modulo q)
    pub fn scalar_mul_assign(&mut self, scalar: i32, modulus: i32) {
        for i in 0..256 {
            self.coeffs[i] = (self.coeffs[i] as i64 * scalar as i64 % modulus as i64) as i32;
        }
    }

    /// Compute the infinity norm of this polynomial
    pub fn infinity_norm(&self) -> i32 {
        let mut max = 0;
        for &coeff in &self.coeffs {
            let abs = coeff.abs();
            if abs > max {
                max = abs;
            }
        }
        max
    }

    /// Return the central representative modulo q
    /// Converts coefficients from [0, q-1] to [-q/2, q/2]
    pub fn to_centered_representation(&mut self, modulus: i32) {
        let half_q = modulus / 2;
        for i in 0..256 {
            if self.coeffs[i] > half_q {
                self.coeffs[i] -= modulus;
            }
        }
    }

    /// Check if all coefficients are within a given range
    pub fn coeffs_in_range(&self, min: i32, max: i32) -> bool {
        self.coeffs.iter().all(|&c| c >= min && c <= max)
    }

    /// Count the number of non-zero coefficients
    pub fn hamming_weight(&self) -> usize {
        self.coeffs.iter().filter(|&&c| c != 0).count()
    }
}

impl PartialEq for Polynomial {
fn eq(&self, other: &Self) -> bool {
    self.coeffs == other.coeffs
}
}

impl Eq for Polynomial {}

#[cfg(test)]
mod tests {
use super::*;

#[test]
fn test_polynomial_addition() {
    let modulus = 8380417; // q value used in ML-KEM and ML-DSA
    
    let mut a = Polynomial::new();
    let mut b = Polynomial::new();
    
    for i in 0..256 {
        a.coeffs[i] = i as i32;
        b.coeffs[i] = (2 * i) as i32;
    }
    
    a.add_assign(&b, modulus);
    
    for i in 0..256 {
        assert_eq!(a.coeffs[i], (3 * i) as i32);
    }
}

#[test]
fn test_polynomial_subtraction() {
    let modulus = 8380417; // q value used in ML-KEM and ML-DSA
    
    let mut a = Polynomial::new();
    let mut b = Polynomial::new();
    
    for i in 0..256 {
        a.coeffs[i] = (5 * i) as i32;
        b.coeffs[i] = (2 * i) as i32;
    }
    
    a.sub_assign(&b, modulus);
    
    for i in 0..256 {
        assert_eq!(a.coeffs[i], (3 * i) as i32);
    }
}

#[test]
fn test_infinity_norm() {
    let mut poly = Polynomial::new();
    
    poly.coeffs[0] = 5;
    poly.coeffs[100] = -10;
    poly.coeffs[200] = 7;
    
    assert_eq!(poly.infinity_norm(), 10);
}
}