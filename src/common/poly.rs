//! Polynomial operations for ML-KEM and ML-DSA.
//!
//! This module implements basic polynomial arithmetic in the ring
//! ℤq\[X\]/(X^256 + 1) used by both ML-KEM and ML-DSA.

use super::reduce::{barrett_for, ct_mod};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A polynomial in the ring ℤq\[X\]/(X^256 + 1)
#[derive(Clone, Debug)]
pub struct Polynomial {
    /// Coefficients of the polynomial
    pub coeffs: [i32; 256],
}

// Manual implementation of Zeroize
impl Zeroize for Polynomial {
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
    }
}

impl ZeroizeOnDrop for Polynomial {}

// Polynomials carry secrets (s, e, y, decoded private keys, ...), so every one
// is wiped when it goes out of scope.
impl Drop for Polynomial {
    fn drop(&mut self) {
        self.coeffs.zeroize();
    }
}

impl Default for Polynomial {
    fn default() -> Self {
        Self::new()
    }
}

impl Polynomial {
    /// Create a new zero polynomial
    pub fn new() -> Self {
        Self { coeffs: [0; 256] }
    }

    /// Add another polynomial to this one (modulo q)
    pub fn add_assign(&mut self, other: &Self, modulus: i32) {
        let m = barrett_for(modulus);
        for i in 0..256 {
            self.coeffs[i] = ct_mod(self.coeffs[i] as i64 + other.coeffs[i] as i64, modulus, m);
        }
    }

    /// Subtract another polynomial from this one (modulo q)
    pub fn sub_assign(&mut self, other: &Self, modulus: i32) {
        let m = barrett_for(modulus);
        for i in 0..256 {
            self.coeffs[i] = ct_mod(self.coeffs[i] as i64 - other.coeffs[i] as i64, modulus, m);
        }
    }

    /// Compute the infinity norm of this polynomial
    /// For ML-DSA, this uses centered representation to compute the norm
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

    /// Compute the infinity norm using centered representation modulo q
    /// This is needed for ML-DSA norm checks
    ///
    /// Branchless: the coefficients are secret during signing.
    pub fn infinity_norm_centered(&self, modulus: i32) -> i32 {
        let half_q = modulus / 2;
        let mut max = 0i32;
        for &coeff in &self.coeffs {
            // centered = coeff - q if coeff > q/2
            let centered = coeff - (modulus & ((half_q - coeff) >> 31));
            let sign = centered >> 31;
            let abs = (centered ^ sign) - sign;
            // max = max(max, abs)
            let diff = max - abs;
            max -= diff & (diff >> 31);
        }
        max
    }

    /// Return the central representative modulo q
    /// Converts coefficients from [0, q-1] to [-q/2, q/2]
    pub fn to_centered_representation(&mut self, modulus: i32) {
        let half_q = modulus / 2;
        for c in self.coeffs.iter_mut() {
            *c -= modulus & ((half_q - *c) >> 31);
        }
    }

    /// Reduce all coefficients modulo q
    pub fn reduce_modulo(&mut self, modulus: i32) {
        let m = barrett_for(modulus);
        for c in self.coeffs.iter_mut() {
            *c = ct_mod(*c as i64, modulus, m);
        }
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
    fn test_polynomial_mlkem_addition() {
        let modulus = 3329; // q value used in ML-KEM

        let mut a = Polynomial::new();
        let mut b = Polynomial::new();

        for i in 0..256 {
            a.coeffs[i] = i as i32;
            b.coeffs[i] = (2 * i) as i32;
        }

        a.add_assign(&b, modulus);

        for i in 0..256 {
            assert_eq!(a.coeffs[i], (3 * i) as i32 % modulus);
        }
    }

    #[test]
    fn test_polynomial_mldsa_addition() {
        let modulus = 8380417; // q value used in ML-DSA

        let mut a = Polynomial::new();
        let mut b = Polynomial::new();

        for i in 0..256 {
            a.coeffs[i] = i as i32;
            b.coeffs[i] = (2 * i) as i32;
        }

        a.add_assign(&b, modulus);

        for i in 0..256 {
            assert_eq!(a.coeffs[i], (3 * i) as i32 % modulus);
        }
    }

    #[test]
    fn test_polynomial_mlkem_subtraction() {
        let modulus = 3329; // q value used in ML-KEM

        let mut a = Polynomial::new();
        let mut b = Polynomial::new();

        for i in 0..256 {
            a.coeffs[i] = (5 * i) as i32;
            b.coeffs[i] = (2 * i) as i32;
        }

        a.sub_assign(&b, modulus);

        for i in 0..256 {
            let expected = (3 * i) as i32 % modulus;
            assert_eq!(a.coeffs[i], expected);
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

    #[test]
    fn test_centered_representation() {
        let modulus = 3329; // ML-KEM modulus
        let mut poly = Polynomial::new();

        poly.coeffs[0] = 0; // Should remain 0
        poly.coeffs[1] = 1664; // Should remain 1664 (< q/2)
        poly.coeffs[2] = 1665; // Should become -1664 (q/2 < 1665 < q)
        poly.coeffs[3] = 3328; // Should become -1 (3328 = q-1)

        poly.to_centered_representation(modulus);

        assert_eq!(poly.coeffs[0], 0);
        assert_eq!(poly.coeffs[1], 1664);
        assert_eq!(poly.coeffs[2], -1664);
        assert_eq!(poly.coeffs[3], -1);
    }
}
