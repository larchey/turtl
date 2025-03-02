//! Fault Detection and Countermeasures
//! 
//! This module contains utility functions for detecting and preventing fault
//! injection attacks on cryptographic operations, as recommended by NIST.
//! 
//! Fault attacks attempt to induce errors in the cryptographic computations
//! (through power glitches, clock manipulation, etc.) to extract secret information.
//! These countermeasures perform validation checks that detect such attacks.

use crate::error::{Error, Result};
use crate::kem::{Ciphertext, SharedSecret};

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

/// Verifies the re-encryption during ML-KEM decapsulation.
/// 
/// This is a critical countermeasure against fault attacks on decapsulation.
/// It verifies that re-encrypting the decrypted message with the public key
/// yields the same ciphertext, ensuring that no fault was injected.
/// 
/// # Arguments
/// 
/// * `ciphertext` - The original ciphertext
/// * `re_encrypted` - The re-encrypted ciphertext
/// 
/// # Returns
/// 
/// `Ok(())` if verification passes, or an error if it fails
pub fn verify_re_encryption(
    ciphertext: &Ciphertext,
    re_encrypted: &Ciphertext
) -> Result<()> {
    if !ct_eq(ciphertext.as_bytes(), re_encrypted.as_bytes()) {
        return Err(Error::VerificationFailed);
    }
    
    Ok(())
}

/// Performs double-checking of signature verification.
/// 
/// This countermeasure executes the verification computation twice and checks
/// that both results match, which can detect certain fault injections.
/// 
/// # Arguments
/// 
/// * `result1` - Result of first verification
/// * `result2` - Result of second verification
/// 
/// # Returns
/// 
/// `Ok(())` if both results match, or an error if they differ
pub fn verify_signature_checks(result1: bool, result2: bool) -> Result<()> {
    if result1 != result2 {
        return Err(Error::FaultDetected);
    }
    
    Ok(())
}

/// Verifies the integrity of a shared secret.
/// 
/// Checks that the shared secret is not corrupted or altered, which
/// could happen during fault attacks.
/// 
/// # Arguments
/// 
/// * `ss1` - First copy of shared secret
/// * `ss2` - Second copy of shared secret
/// 
/// # Returns
/// 
/// `Ok(())` if integrity check passes, or an error if it fails
pub fn verify_shared_secret_integrity(
    ss1: &SharedSecret,
    ss2: &SharedSecret
) -> Result<()> {
    if !ct_eq(ss1.as_bytes(), ss2.as_bytes()) {
        return Err(Error::FaultDetected);
    }
    
    Ok(())
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