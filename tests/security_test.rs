//! Tests for security features in TURTL.
//! 
//! This module tests the security features including constant-time operations
//! and fault detection mechanisms.

use turtl::security::constant_time;
use turtl::security::fault_detection;
use turtl::error::Error;
use turtl::common::ntt::{NTTContext, NTTType};

#[test]
fn test_constant_time_operations() {
    // Test conditional move
    let mut x = 10u32;
    constant_time::ct_cmov(&mut x, 20, true);
    assert_eq!(x, 20, "ct_cmov should set value when condition is true");
    
    constant_time::ct_cmov(&mut x, 30, false);
    assert_eq!(x, 20, "ct_cmov should not change value when condition is false");
    
    // Test conditional select
    let result = constant_time::ct_select(5, 10, true);
    assert_eq!(result, 5, "ct_select should return first value when condition is true");
    
    let result = constant_time::ct_select(5, 10, false);
    assert_eq!(result, 10, "ct_select should return second value when condition is false");
    
    // Test conditional swap
    let mut a = 1u32;
    let mut b = 2u32;
    constant_time::ct_cswap(&mut a, &mut b, true);
    assert_eq!(a, 2, "ct_cswap should swap values when condition is true");
    assert_eq!(b, 1, "ct_cswap should swap values when condition is true");
    
    constant_time::ct_cswap(&mut a, &mut b, false);
    assert_eq!(a, 2, "ct_cswap should not swap values when condition is false");
    assert_eq!(b, 1, "ct_cswap should not swap values when condition is false");
}

#[test]
fn test_constant_time_comparisons() {
    // Test equality comparison
    assert!(constant_time::ct_eq_u32(100, 100), "Equal values should return true");
    assert!(!constant_time::ct_eq_u32(100, 101), "Unequal values should return false");
    
    // Test zero check
    assert!(constant_time::ct_is_zero_u32(0), "Zero value should return true");
    assert!(!constant_time::ct_is_zero_u32(1), "Non-zero value should return false");
    
    // Test byte operations
    assert!(constant_time::ct_is_zero_u8(0), "Zero byte should return true");
    assert!(!constant_time::ct_is_zero_u8(255), "Non-zero byte should return false");
}

#[test]
fn test_slice_operations() {
    // Test slice equality
    let a = vec![1u8, 2, 3, 4];
    let b = vec![1u8, 2, 3, 4];
    let c = vec![1u8, 2, 3, 5];
    
    assert!(fault_detection::ct_eq(&a, &b), "Equal slices should return true");
    assert!(!fault_detection::ct_eq(&a, &c), "Different slices should return false");
    
    // Test slice constant-time swap
    let mut x = vec![1u8, 2, 3];
    let mut y = vec![4u8, 5, 6];
    let x_orig = x.clone();
    let y_orig = y.clone();
    
    constant_time::ct_cswap_slice(&mut x, &mut y, true);
    assert_eq!(x, y_orig, "Slices should be swapped when condition is true");
    assert_eq!(y, x_orig, "Slices should be swapped when condition is true");
}

#[test]
fn test_fault_detection() {
    // Test bounds checking
    let result = fault_detection::verify_bounds(5, 1, 10);
    assert!(result.is_ok(), "Value within bounds should pass");
    
    let result = fault_detection::verify_bounds(0, 1, 10);
    assert!(result.is_err(), "Value below bounds should fail");
    match result {
        Err(Error::FaultDetected) => (),
        _ => panic!("Expected FaultDetected error"),
    }
    
    let result = fault_detection::verify_bounds(11, 1, 10);
    assert!(result.is_err(), "Value above bounds should fail");
    match result {
        Err(Error::FaultDetected) => (),
        _ => panic!("Expected FaultDetected error"),
    }
}

#[test]
fn test_signature_verification_checks() {
    // Test matching verification results
    let result = fault_detection::verify_signature_checks(true, true);
    assert!(result.is_ok(), "Matching verification results should pass");
    
    let result = fault_detection::verify_signature_checks(false, false);
    assert!(result.is_ok(), "Matching verification results should pass (both false)");
    
    // Test mismatching verification results
    let result = fault_detection::verify_signature_checks(true, false);
    assert!(result.is_err(), "Mismatching verification results should fail");
    match result {
        Err(Error::FaultDetected) => (),
        _ => panic!("Expected FaultDetected error"),
    }
}

#[test]
fn test_shared_secret_integrity() {
    // Create two identical shared secrets
    let mut ss1_bytes = [0u8; 32];
    let mut ss2_bytes = [0u8; 32];
    
    for i in 0..32 {
        ss1_bytes[i] = i as u8;
        ss2_bytes[i] = i as u8;
    }
    
    let ss1 = turtl::kem::SharedSecret::new(ss1_bytes);
    let ss2 = turtl::kem::SharedSecret::new(ss2_bytes);
    
    // Test matching shared secrets
    let result = fault_detection::verify_shared_secret_integrity(&ss1, &ss2);
    assert!(result.is_ok(), "Matching shared secrets should pass");
    
    // Test mismatching shared secrets
    let mut ss3_bytes = ss1_bytes;
    ss3_bytes[0] ^= 1; // Flip a bit
    let ss3 = turtl::kem::SharedSecret::new(ss3_bytes);
    
    let result = fault_detection::verify_shared_secret_integrity(&ss1, &ss3);
    assert!(result.is_err(), "Mismatching shared secrets should fail");
    match result {
        Err(Error::FaultDetected) => (),
        _ => panic!("Expected FaultDetected error"),
    }
}

/// Test that the secure Montgomery reduction implementation properly
/// handles inputs that could be manipulated by fault attacks
#[test]
fn test_montgomery_reduction_fault_resistance() {
    // Create NTT contexts for both algorithms
    let mlkem_ctx = NTTContext::new(NTTType::MLKEM);
    let mldsa_ctx = NTTContext::new(NTTType::MLDSA);
    
    // Test that the secure implementation handles out-of-range inputs gracefully
    
    // 1. Test inputs that are negative
    let negative_input = -1000i64;
    let result_mlkem = mlkem_ctx.montgomery_reduce_secure(negative_input);
    let result_mldsa = mldsa_ctx.montgomery_reduce_secure(negative_input);
    
    // Results should be valid modular values (in range [0, q-1])
    assert!(result_mlkem >= 0 && result_mlkem < mlkem_ctx.modulus);
    assert!(result_mldsa >= 0 && result_mldsa < mldsa_ctx.modulus);
    
    // 2. Test inputs that are too large (larger than q^2)
    let too_large_mlkem = (mlkem_ctx.modulus as i64) * (mlkem_ctx.modulus as i64) * 2;
    let too_large_mldsa = (mldsa_ctx.modulus as i64) * (mldsa_ctx.modulus as i64) * 2;
    
    let result_large_mlkem = mlkem_ctx.montgomery_reduce_secure(too_large_mlkem);
    let result_large_mldsa = mldsa_ctx.montgomery_reduce_secure(too_large_mldsa);
    
    // Results should be valid modular values (in range [0, q-1])
    assert!(result_large_mlkem >= 0 && result_large_mlkem < mlkem_ctx.modulus);
    assert!(result_large_mldsa >= 0 && result_large_mldsa < mldsa_ctx.modulus);
    
    // 3. Test normal inputs are in the valid range
    let normal_input = 100i64;
    let secure_result_mlkem = mlkem_ctx.montgomery_reduce_secure(normal_input);
    
    // Result should be in valid range [0, q-1]
    assert!(secure_result_mlkem >= 0 && secure_result_mlkem < mlkem_ctx.modulus);
}

/// Test that the secure Montgomery conversion properly handles
/// inputs that could be manipulated by fault attacks
#[test]
fn test_montgomery_conversion_fault_resistance() {
    // Create NTT contexts for both algorithms
    let mlkem_ctx = NTTContext::new(NTTType::MLKEM);
    let mldsa_ctx = NTTContext::new(NTTType::MLDSA);
    
    // Test that the secure implementation handles out-of-range inputs gracefully
    
    // 1. Test inputs that are negative
    let negative_input = -100i32;
    let result_mlkem = mlkem_ctx.to_montgomery_secure(negative_input);
    let result_mldsa = mldsa_ctx.to_montgomery_secure(negative_input);
    
    // Results should be valid modular values (in range [0, q-1])
    assert!(result_mlkem >= 0 && result_mlkem < mlkem_ctx.modulus);
    assert!(result_mldsa >= 0 && result_mldsa < mldsa_ctx.modulus);
    
    // 2. Test inputs that are too large (larger than q)
    let too_large_mlkem = mlkem_ctx.modulus * 2;
    let too_large_mldsa = mldsa_ctx.modulus * 2;
    
    let result_large_mlkem = mlkem_ctx.to_montgomery_secure(too_large_mlkem);
    let result_large_mldsa = mldsa_ctx.to_montgomery_secure(too_large_mldsa);
    
    // Results should be valid modular values (in range [0, q-1])
    assert!(result_large_mlkem >= 0 && result_large_mlkem < mlkem_ctx.modulus);
    assert!(result_large_mldsa >= 0 && result_large_mldsa < mldsa_ctx.modulus);
    
    // 3. Test that normal inputs produce values in the valid range
    let normal_input = 100i32;
    let secure_result_mlkem = mlkem_ctx.to_montgomery_secure(normal_input);
    
    // The result should be in the valid range [0, q-1]
    assert!(secure_result_mlkem >= 0 && secure_result_mlkem < mlkem_ctx.modulus);
}