//! Tests for error handling in the TURTL library.
//! 
//! This module tests the robustness of the error handling mechanisms
//! by purposely introducing invalid inputs and boundary conditions.

use turtl::kem::{PublicKey, PrivateKey, Ciphertext, ParameterSet};
use turtl::error::Error;
use turtl::security::fault_detection;

#[test]
fn test_invalid_public_key_size() {
    // Create an invalid public key (wrong size)
    let invalid_pk_bytes = vec![0u8; 100]; // Wrong size for any parameter set
    let result = PublicKey::new(invalid_pk_bytes, ParameterSet::MlKem512);
    assert!(result.is_err());
    match result {
        Err(Error::InvalidPublicKey) => (),
        _ => panic!("Expected InvalidPublicKey error"),
    }
}

#[test]
fn test_invalid_private_key_size() {
    // Create an invalid private key (wrong size)
    let invalid_sk_bytes = vec![0u8; 100]; // Wrong size for any parameter set
    let result = PrivateKey::new(invalid_sk_bytes, ParameterSet::MlKem512);
    assert!(result.is_err());
    match result {
        Err(Error::InvalidPrivateKey) => (),
        _ => panic!("Expected InvalidPrivateKey error"),
    }
}

#[test]
fn test_invalid_ciphertext_size() {
    // Create an invalid ciphertext (wrong size)
    let invalid_ct_bytes = vec![0u8; 100]; // Wrong size for any parameter set
    let result = Ciphertext::new(invalid_ct_bytes, ParameterSet::MlKem512);
    assert!(result.is_err());
    match result {
        Err(Error::InvalidCiphertext) => (),
        _ => panic!("Expected InvalidCiphertext error"),
    }
}

#[test]
fn test_fault_detection_constant_time_eq() {
    // Test constant-time equality check
    let a = vec![1, 2, 3, 4];
    let b = vec![1, 2, 3, 4];
    let c = vec![1, 2, 3, 5];
    let d = vec![1, 2, 3];
    
    assert!(fault_detection::ct_eq(&a, &b), "Equal arrays should return true");
    assert!(!fault_detection::ct_eq(&a, &c), "Unequal arrays should return false");
    assert!(!fault_detection::ct_eq(&a, &d), "Different length arrays should return false");
}

#[test]
fn test_bounds_checking() {
    // Test the bounds checking function
    let result = fault_detection::verify_bounds(10, 1, 100);
    assert!(result.is_ok(), "Value within bounds should pass");
    
    let result = fault_detection::verify_bounds(0, 1, 100);
    assert!(result.is_err(), "Value below bounds should fail");
    match result {
        Err(Error::FaultDetected) => (),
        _ => panic!("Expected FaultDetected error"),
    }
    
    let result = fault_detection::verify_bounds(101, 1, 100);
    assert!(result.is_err(), "Value above bounds should fail");
    match result {
        Err(Error::FaultDetected) => (),
        _ => panic!("Expected FaultDetected error"),
    }
}