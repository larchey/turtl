//! Fault Detection and Countermeasures
//!
//! This module contains utility functions for detecting and preventing fault
//! injection attacks on cryptographic operations, as recommended by NIST.
//!
//! Fault attacks attempt to induce errors in the cryptographic computations
//! (through power glitches, clock manipulation, etc.) to extract secret information.
//! These countermeasures perform validation checks that detect such attacks.

use crate::error::{Error, Result};

/// Performs a constant-time equality check between two byte slices.
///
/// This function is resistant to timing attacks by ensuring that the time taken
/// to compare the byte slices is independent of the data values.
///
/// # Arguments
///
/// * `a` - First byte slice
/// * `b` - Second byte slice
///
/// # Returns
///
/// `true` if the slices are equal, `false` otherwise
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Verifies that a value is within expected bounds.
///
/// Many fault attacks manipulate values to be outside of their normal range.
/// This function verifies that values stay within expected bounds.
///
/// # Arguments
///
/// * `value` - The value to check
/// * `min` - Minimum allowed value
/// * `max` - Maximum allowed value
///
/// # Returns
///
/// `Ok(())` if value is within bounds, or an error if out of bounds
pub fn verify_bounds<T: PartialOrd>(value: T, min: T, max: T) -> Result<()> {
    if value < min || value > max {
        return Err(Error::FaultDetected);
    }

    Ok(())
}
