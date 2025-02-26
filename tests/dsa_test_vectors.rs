//! Test vectors for ML-DSA.
//! 
//! This module contains test vectors for ML-DSA key generation,
//! signing, and verification as specified in FIPS 204.

use turtl::dsa::{self, ParameterSet, KeyPair, PublicKey, PrivateKey, Signature, SigningMode};
use turtl::error::Result;

// Test vectors
const ML_DSA_44_SEED: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
];

const ML_DSA_44_MESSAGE: &[u8] = b"TURTL Test Message for ML-DSA-44";

// Example expected values (simplified for brevity - in a real implementation
// these would be actual test vectors from the NIST validation program)
const ML_DSA_44_PUBLIC_KEY: &str = "expected_public_key_hex";
const ML_DSA_44_PRIVATE_KEY: &str = "expected_private_key_hex";
const ML_DSA_44_SIGNATURE: &str = "expected_signature_hex";

#[test]
fn test_ml_dsa_44_key_generation() -> Result<()> {
    // Generate key pair from seed
    let keypair = KeyPair::from_seed(&ML_DSA_44_SEED, ParameterSet::ML_DSA_44)?;
    
    // Get public and private keys
    let public_key = keypair.public_key();
    let private_key = keypair.private_key();
    
    // Check sizes
    assert_eq!(public_key.as_bytes().len(), ParameterSet::ML_DSA_44.public_key_size());
    assert_eq!(private_key.as_bytes().len(), ParameterSet::ML_DSA_44.private_key_size());
    
    // In a real test, we would compare against expected values
    // assert_eq!(hex::encode(public_key.as_bytes()), ML_DSA_44_PUBLIC_KEY);
    // assert_eq!(hex::encode(private_key.as_bytes()), ML_DSA_44_PRIVATE_KEY);
    
    Ok(())
}

#[test]
fn test_ml_dsa_44_sign_verify() -> Result<()> {
    // Generate key pair
    let keypair = KeyPair::from_seed(&ML_DSA_44_SEED, ParameterSet::ML_DSA_44)?;
    
    // Sign message
    let context = b"";
    let signature = dsa::sign(&keypair.private_key(), ML_DSA_44_MESSAGE, context, SigningMode::Deterministic)?;
    
    // Check size
    assert_eq!(signature.as_bytes().len(), ParameterSet::ML_DSA_44.signature_size());
    
    // Verify signature
    let is_valid = dsa::verify(&keypair.public_key(), ML_DSA_44_MESSAGE, &signature, context)?;
    
    // Signature should be valid
    assert!(is_valid);
    
    Ok(())
}

#[test]
fn test_ml_dsa_65_key_generation() -> Result<()> {
    // Generate key pair
    let keypair = KeyPair::generate(ParameterSet::ML_DSA_65)?;
    
    // Check sizes
    assert_eq!(keypair.public_key().as_bytes().len(), ParameterSet::ML_DSA_65.public_key_size());
    assert_eq!(keypair.private_key().as_bytes().len(), ParameterSet::ML_DSA_65.private_key_size());
    
    Ok(())
}

#[test]
fn test_ml_dsa_87_key_generation() -> Result<()> {
    // Generate key pair
    let keypair = KeyPair::generate(ParameterSet::ML_DSA_87)?;
    
    // Check sizes
    assert_eq!(keypair.public_key().as_bytes().len(), ParameterSet::ML_DSA_87.public_key_size());
    assert_eq!(keypair.private_key().as_bytes().len(), ParameterSet::ML_DSA_87.private_key_size());
    
    Ok(())
}

#[test]
fn test_ml_dsa_all_sign_verify() -> Result<()> {
    for param_set in &[
        ParameterSet::ML_DSA_44,
        ParameterSet::ML_DSA_65,
        ParameterSet::ML_DSA_87
    ] {
        // Generate key pair
        let keypair = KeyPair::generate(*param_set)?;
        
        // Sign message
        let message = b"Test message for ML-DSA";
        let context = b"";
        let signature = dsa::sign(&keypair.private_key(), message, context, SigningMode::Hedged)?;
        
        // Verify signature
        let is_valid = dsa::verify(&keypair.public_key(), message, &signature, context)?;
        
        // Signature should be valid
        assert!(is_valid);
        
        // Test with modified message (should fail)
        let modified_message = b"Modified test message for ML-DSA";
        let is_valid_modified = dsa::verify(&keypair.public_key(), modified_message, &signature, context)?;
        
        // Signature should be invalid for modified message
        assert!(!is_valid_modified);
    }
    
    Ok(())
}

#[test]
fn test_deterministic_signing() -> Result<()> {
    // Generate key pair
    let keypair = KeyPair::generate(ParameterSet::ML_DSA_44)?;
    
    // Sign message with deterministic mode
    let message = b"Test message for deterministic signing";
    let context = b"";
    
    let sig1 = dsa::sign(&keypair.private_key(), message, context, SigningMode::Deterministic)?;
    let sig2 = dsa::sign(&keypair.private_key(), message, context, SigningMode::Deterministic)?;
    
    // Signatures should be identical
    assert_eq!(sig1.as_bytes(), sig2.as_bytes());
    
    // Verify both signatures
    assert!(dsa::verify(&keypair.public_key(), message, &sig1, context)?);
    assert!(dsa::verify(&keypair.public_key(), message, &sig2, context)?);
    
    Ok(())
}

#[test]
fn test_context_strings() -> Result<()> {
    // Generate key pair
    let keypair = KeyPair::generate(ParameterSet::ML_DSA_44)?;
    
    // Sign with a context string
    let message = b"Test message with context";
    let context = b"Test Context";
    
    let signature = dsa::sign(&keypair.private_key(), message, context, SigningMode::Hedged)?;
    
    // Verify with correct context
    assert!(dsa::verify(&keypair.public_key(), message, &signature, context)?);
    
    // Verify with wrong context (should fail)
    let wrong_context = b"Wrong Context";
    assert!(!dsa::verify(&keypair.public_key(), message, &signature, wrong_context)?);
    
    Ok(())
}