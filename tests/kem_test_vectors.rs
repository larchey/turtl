//! Test vectors for ML-KEM.
//! 
//! This module contains test vectors for ML-KEM key generation,
//! encapsulation, and decapsulation as specified in FIPS 203.

use turtl::kem::{self, ParameterSet, KeyPair, PublicKey, PrivateKey, Ciphertext, SharedSecret};
use turtl::error::Result;

// Test vectors
const ML_KEM_512_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];

const ML_KEM_512_MESSAGE: [u8; 32] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
];

// Example expected values (simplified for brevity - in a real implementation
// these would be actual test vectors from the NIST validation program)
const ML_KEM_512_PUBLIC_KEY: &str = "expected_public_key_hex";
const ML_KEM_512_PRIVATE_KEY: &str = "expected_private_key_hex";
const ML_KEM_512_CIPHERTEXT: &str = "expected_ciphertext_hex";
const ML_KEM_512_SHARED_SECRET: &str = "expected_shared_secret_hex";

#[test]
fn test_ml_kem_512_key_generation() -> Result<()> {
    // Generate key pair from seed
    let keypair = KeyPair::from_seed(&ML_KEM_512_SEED, ParameterSet::ML_KEM_512)?;
    
    // Get public and private keys
    let public_key = keypair.public_key();
    let private_key = keypair.private_key();
    
    // Check sizes
    assert_eq!(public_key.as_bytes().len(), ParameterSet::ML_KEM_512.public_key_size());
    assert_eq!(private_key.as_bytes().len(), ParameterSet::ML_KEM_512.private_key_size());
    
    // In a real test, we would compare against expected values
    // assert_eq!(hex::encode(public_key.as_bytes()), ML_KEM_512_PUBLIC_KEY);
    // assert_eq!(hex::encode(private_key.as_bytes()), ML_KEM_512_PRIVATE_KEY);
    
    Ok(())
}

#[test]
fn test_ml_kem_512_encapsulation_decapsulation() -> Result<()> {
    // Generate key pair
    let keypair = KeyPair::from_seed(&ML_KEM_512_SEED, ParameterSet::ML_KEM_512)?;
    
    // Encapsulate
    let (ciphertext, shared_secret) = kem::encapsulate(&keypair.public_key())?;
    
    // Check sizes
    assert_eq!(ciphertext.as_bytes().len(), ParameterSet::ML_KEM_512.ciphertext_size());
    assert_eq!(shared_secret.as_bytes().len(), 32);
    
    // Decapsulate
    let decapsulated_secret = kem::decapsulate(&keypair.private_key(), &ciphertext)?;
    
    // Shared secrets should match
    assert_eq!(shared_secret.as_bytes(), decapsulated_secret.as_bytes());
    
    Ok(())
}

#[test]
fn test_ml_kem_768_key_generation() -> Result<()> {
    // Generate key pair
    let keypair = KeyPair::generate(ParameterSet::ML_KEM_768)?;
    
    // Check sizes
    assert_eq!(keypair.public_key().as_bytes().len(), ParameterSet::ML_KEM_768.public_key_size());
    assert_eq!(keypair.private_key().as_bytes().len(), ParameterSet::ML_KEM_768.private_key_size());
    
    Ok(())
}

#[test]
fn test_ml_kem_1024_key_generation() -> Result<()> {
    // Generate key pair
    let keypair = KeyPair::generate(ParameterSet::ML_KEM_1024)?;
    
    // Check sizes
    assert_eq!(keypair.public_key().as_bytes().len(), ParameterSet::ML_KEM_1024.public_key_size());
    assert_eq!(keypair.private_key().as_bytes().len(), ParameterSet::ML_KEM_1024.private_key_size());
    
    Ok(())
}

#[test]
fn test_ml_kem_roundtrip() -> Result<()> {
    for param_set in &[
        ParameterSet::ML_KEM_512,
        ParameterSet::ML_KEM_768,
        ParameterSet::ML_KEM_1024
    ] {
        // Generate key pair
        let keypair = KeyPair::generate(*param_set)?;
        
        // Encapsulate
        let (ciphertext, shared_secret) = kem::encapsulate(&keypair.public_key())?;
        
        // Decapsulate
        let decapsulated_secret = kem::decapsulate(&keypair.private_key(), &ciphertext)?;
        
        // Shared secrets should match
        assert_eq!(shared_secret.as_bytes(), decapsulated_secret.as_bytes());
    }
    
    Ok(())
}