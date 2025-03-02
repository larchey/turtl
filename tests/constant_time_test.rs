//! Tests for constant-time operations in the TURTL library.
//! 
//! This module tests the constant-time operation utilities used for
//! side-channel resistance. These tests verify the correctness of the
//! operations but not their timing characteristics, which would require
//! specialized equipment.

use turtl::security::constant_time;

#[test]
fn test_ct_cmov() {
    // Test conditional move operation
    let mut r = 10u32;
    
    // When condition is true, r should be set to x
    constant_time::ct_cmov(&mut r, 20, true);
    assert_eq!(r, 20, "cmov with true condition should set r to x");
    
    // When condition is false, r should remain unchanged
    constant_time::ct_cmov(&mut r, 30, false);
    assert_eq!(r, 20, "cmov with false condition should leave r unchanged");
}

#[test]
fn test_ct_cmov_u64() {
    // Test conditional move operation for u64
    let mut r = 0x1234567890ABCDEFu64;
    
    // When condition is true, r should be set to x
    constant_time::ct_cmov_u64(&mut r, 0xFEDCBA0987654321, true);
    assert_eq!(r, 0xFEDCBA0987654321, "cmov_u64 with true condition should set r to x");
    
    // When condition is false, r should remain unchanged
    constant_time::ct_cmov_u64(&mut r, 0x0000000000000000, false);
    assert_eq!(r, 0xFEDCBA0987654321, "cmov_u64 with false condition should leave r unchanged");
}

#[test]
fn test_ct_cmov_u128() {
    // Test conditional move operation for u128
    let mut r = 0x1234567890ABCDEF1234567890ABCDEFu128;
    
    // When condition is true, r should be set to x
    constant_time::ct_cmov_u128(&mut r, 0xFEDCBA0987654321FEDCBA0987654321, true);
    assert_eq!(r, 0xFEDCBA0987654321FEDCBA0987654321, "cmov_u128 with true condition should set r to x");
    
    // When condition is false, r should remain unchanged
    constant_time::ct_cmov_u128(&mut r, 0, false);
    assert_eq!(r, 0xFEDCBA0987654321FEDCBA0987654321, "cmov_u128 with false condition should leave r unchanged");
}

#[test]
fn test_ct_cmov_byte() {
    // Test conditional move operation for bytes
    let mut r = 10u8;
    
    // When condition is true, r should be set to x
    constant_time::ct_cmov_byte(&mut r, 20, true);
    assert_eq!(r, 20, "cmov_byte with true condition should set r to x");
    
    // When condition is false, r should remain unchanged
    constant_time::ct_cmov_byte(&mut r, 30, false);
    assert_eq!(r, 20, "cmov_byte with false condition should leave r unchanged");
}

#[test]
fn test_ct_cswap() {
    // Test conditional swap operation
    let mut a = 10u32;
    let mut b = 20u32;
    
    // When condition is true, a and b should be swapped
    constant_time::ct_cswap(&mut a, &mut b, true);
    assert_eq!(a, 20, "cswap with true condition should swap a and b");
    assert_eq!(b, 10, "cswap with true condition should swap a and b");
    
    // When condition is false, a and b should remain unchanged
    constant_time::ct_cswap(&mut a, &mut b, false);
    assert_eq!(a, 20, "cswap with false condition should leave a and b unchanged");
    assert_eq!(b, 10, "cswap with false condition should leave a and b unchanged");
}

#[test]
fn test_ct_cswap_u64() {
    // Test conditional swap operation for u64
    let mut a = 0x1234567890ABCDEFu64;
    let mut b = 0xFEDCBA0987654321u64;
    
    // When condition is true, a and b should be swapped
    constant_time::ct_cswap_u64(&mut a, &mut b, true);
    assert_eq!(a, 0xFEDCBA0987654321, "cswap_u64 with true condition should swap a and b");
    assert_eq!(b, 0x1234567890ABCDEF, "cswap_u64 with true condition should swap a and b");
    
    // When condition is false, a and b should remain unchanged
    constant_time::ct_cswap_u64(&mut a, &mut b, false);
    assert_eq!(a, 0xFEDCBA0987654321, "cswap_u64 with false condition should leave a and b unchanged");
    assert_eq!(b, 0x1234567890ABCDEF, "cswap_u64 with false condition should leave a and b unchanged");
}

#[test]
fn test_ct_cswap_u128() {
    // Test conditional swap operation for u128
    let mut a = 0x1234567890ABCDEF1234567890ABCDEFu128;
    let mut b = 0xFEDCBA0987654321FEDCBA0987654321u128;
    
    // When condition is true, a and b should be swapped
    constant_time::ct_cswap_u128(&mut a, &mut b, true);
    assert_eq!(a, 0xFEDCBA0987654321FEDCBA0987654321, "cswap_u128 with true condition should swap a and b");
    assert_eq!(b, 0x1234567890ABCDEF1234567890ABCDEF, "cswap_u128 with true condition should swap a and b");
    
    // When condition is false, a and b should remain unchanged
    constant_time::ct_cswap_u128(&mut a, &mut b, false);
    assert_eq!(a, 0xFEDCBA0987654321FEDCBA0987654321, "cswap_u128 with false condition should leave a and b unchanged");
    assert_eq!(b, 0x1234567890ABCDEF1234567890ABCDEF, "cswap_u128 with false condition should leave a and b unchanged");
}

#[test]
fn test_ct_cswap_byte() {
    // Test conditional swap operation for bytes
    let mut a = 10u8;
    let mut b = 20u8;
    
    // When condition is true, a and b should be swapped
    constant_time::ct_cswap_byte(&mut a, &mut b, true);
    assert_eq!(a, 20, "cswap_byte with true condition should swap a and b");
    assert_eq!(b, 10, "cswap_byte with true condition should swap a and b");
    
    // When condition is false, a and b should remain unchanged
    constant_time::ct_cswap_byte(&mut a, &mut b, false);
    assert_eq!(a, 20, "cswap_byte with false condition should leave a and b unchanged");
    assert_eq!(b, 10, "cswap_byte with false condition should leave a and b unchanged");
}

#[test]
fn test_ct_cswap_slice() {
    // Test conditional swap operation for slices
    let mut a = vec![1u8, 2, 3, 4];
    let mut b = vec![5u8, 6, 7, 8];
    
    let a_orig = a.clone();
    let b_orig = b.clone();
    
    // When condition is true, a and b should be swapped
    constant_time::ct_cswap_slice(&mut a, &mut b, true);
    assert_eq!(a, b_orig, "cswap_slice with true condition should swap a and b");
    assert_eq!(b, a_orig, "cswap_slice with true condition should swap a and b");
    
    // When condition is false, a and b should remain unchanged
    constant_time::ct_cswap_slice(&mut a, &mut b, false);
    assert_eq!(a, b_orig, "cswap_slice with false condition should leave a and b unchanged");
    assert_eq!(b, a_orig, "cswap_slice with false condition should leave a and b unchanged");
}

#[test]
fn test_ct_select() {
    // Test conditional select operation
    let x = 10u32;
    let y = 20u32;
    
    // When condition is true, result should be x
    let result = constant_time::ct_select(x, y, true);
    assert_eq!(result, x, "select with true condition should return x");
    
    // When condition is false, result should be y
    let result = constant_time::ct_select(x, y, false);
    assert_eq!(result, y, "select with false condition should return y");
}

#[test]
fn test_ct_select_u64() {
    // Test conditional select operation for u64
    let x = 0x1234567890ABCDEFu64;
    let y = 0xFEDCBA0987654321u64;
    
    // When condition is true, result should be x
    let result = constant_time::ct_select_u64(x, y, true);
    assert_eq!(result, x, "select_u64 with true condition should return x");
    
    // When condition is false, result should be y
    let result = constant_time::ct_select_u64(x, y, false);
    assert_eq!(result, y, "select_u64 with false condition should return y");
}

#[test]
fn test_ct_select_u128() {
    // Test conditional select operation for u128
    let x = 0x1234567890ABCDEF1234567890ABCDEFu128;
    let y = 0xFEDCBA0987654321FEDCBA0987654321u128;
    
    // When condition is true, result should be x
    let result = constant_time::ct_select_u128(x, y, true);
    assert_eq!(result, x, "select_u128 with true condition should return x");
    
    // When condition is false, result should be y
    let result = constant_time::ct_select_u128(x, y, false);
    assert_eq!(result, y, "select_u128 with false condition should return y");
}

#[test]
fn test_ct_select_byte() {
    // Test conditional select operation for bytes
    let x = 10u8;
    let y = 20u8;
    
    // When condition is true, result should be x
    let result = constant_time::ct_select_byte(x, y, true);
    assert_eq!(result, x, "select_byte with true condition should return x");
    
    // When condition is false, result should be y
    let result = constant_time::ct_select_byte(x, y, false);
    assert_eq!(result, y, "select_byte with false condition should return y");
}

#[test]
fn test_ct_eq_u32() {
    // Test constant-time equality check
    assert!(constant_time::ct_eq_u32(10, 10), "Equal values should return true");
    assert!(!constant_time::ct_eq_u32(10, 20), "Unequal values should return false");
}

#[test]
fn test_ct_eq_u64() {
    // Test constant-time equality check for u64
    assert!(constant_time::ct_eq_u64(0x1234567890ABCDEF, 0x1234567890ABCDEF), "Equal values should return true");
    assert!(!constant_time::ct_eq_u64(0x1234567890ABCDEF, 0xFEDCBA0987654321), "Unequal values should return false");
}

#[test]
fn test_ct_eq_u128() {
    // Test constant-time equality check for u128
    assert!(constant_time::ct_eq_u128(0x1234567890ABCDEF1234567890ABCDEF, 0x1234567890ABCDEF1234567890ABCDEF), "Equal values should return true");
    assert!(!constant_time::ct_eq_u128(0x1234567890ABCDEF1234567890ABCDEF, 0xFEDCBA0987654321FEDCBA0987654321), "Unequal values should return false");
}

#[test]
fn test_ct_is_zero_u32() {
    // Test constant-time zero check
    assert!(constant_time::ct_is_zero_u32(0), "Zero should return true");
    assert!(!constant_time::ct_is_zero_u32(10), "Non-zero should return false");
    assert!(!constant_time::ct_is_zero_u32(0xFFFFFFFF), "Max value should return false");
}

#[test]
fn test_ct_is_zero_u64() {
    // Test constant-time zero check for u64
    assert!(constant_time::ct_is_zero_u64(0), "Zero should return true");
    assert!(!constant_time::ct_is_zero_u64(10), "Non-zero should return false");
    assert!(!constant_time::ct_is_zero_u64(0xFFFFFFFFFFFFFFFF), "Max value should return false");
}

#[test]
fn test_ct_is_zero_u128() {
    // Test constant-time zero check for u128
    assert!(constant_time::ct_is_zero_u128(0), "Zero should return true");
    assert!(!constant_time::ct_is_zero_u128(10), "Non-zero should return false");
    assert!(!constant_time::ct_is_zero_u128(u128::MAX), "Max value should return false");
}

#[test]
fn test_ct_is_zero_u8() {
    // Test constant-time zero check for bytes
    assert!(constant_time::ct_is_zero_u8(0), "Zero should return true");
    assert!(!constant_time::ct_is_zero_u8(10), "Non-zero should return false");
    assert!(!constant_time::ct_is_zero_u8(0xFF), "Max value should return false");
}