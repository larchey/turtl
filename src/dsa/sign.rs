//! ML-DSA signing implementation.
//! 
//! This module implements the signing algorithms for ML-DSA.

use crate::error::{Error, Result};
use super::{PrivateKey, Signature, SigningMode, HashFunction};
use super::internal::{ml_dsa_sign_internal, ml_dsa_hash_sign_internal};
use rand::{rngs::OsRng, RngCore};

/// Sign a message using ML-DSA
pub fn sign(
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
    mode: SigningMode,
) -> Result<Signature> {
    // Check if context is valid (max 255 bytes)
    if context.len() > 255 {
        return Err(Error::ContextTooLong);
    }
    
    // Generate randomness for hedged mode or use zeros for deterministic mode
    let mut rnd = [0u8; 32];
    if let SigningMode::Hedged = mode {
        OsRng.fill_bytes(&mut rnd);
    }
    
    // Format message with domain separator and context
    // Domain separator 0 for regular signing
    let domain_separator = 0u8;
    let formatted_message = format_message(message, context, domain_separator)?;
    
    // Call internal signing function
    let signature_bytes = ml_dsa_sign_internal(
        private_key.as_bytes(),
        &formatted_message,
        &rnd,
        private_key.parameter_set()
    )?;
    
    // Create signature object
    Signature::new(signature_bytes, private_key.parameter_set())
}

/// Sign a message with pre-hashing using ML-DSA
pub fn hash_sign(
    private_key: &PrivateKey,
    message: &[u8],
    context: &[u8],
    hash_function: HashFunction,
    mode: SigningMode,
) -> Result<Signature> {
    // Check if context is valid (max 255 bytes)
    if context.len() > 255 {
        return Err(Error::ContextTooLong);
    }
    
    // Generate randomness for hedged mode or use zeros for deterministic mode
    let mut rnd = [0u8; 32];
    if let SigningMode::Hedged = mode {
        OsRng.fill_bytes(&mut rnd);
    }
    
    // Call internal hash-then-sign function
    let signature_bytes = ml_dsa_hash_sign_internal(
        private_key.as_bytes(),
        message,
        context,
        hash_function,
        &rnd,
        private_key.parameter_set()
    )?;
    
    // Create signature object
    Signature::new(signature_bytes, private_key.parameter_set())
}

/// Format message with domain separator and context
fn format_message(message: &[u8], context: &[u8], domain_separator: u8) -> Result<Vec<u8>> {
    let mut formatted = Vec::with_capacity(2 + context.len() + message.len());
    
    // Add domain separator
    formatted.push(domain_separator);
    
    // Add context length
    formatted.push(context.len() as u8);
    
    // Add context
    formatted.extend_from_slice(context);
    
    // Add message
    formatted.extend_from_slice(message);
    
    Ok(formatted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsa::{key_gen, verify, ParameterSet};
    
    #[test]
    fn test_sign_verify() -> Result<()> {
        // Generate a key pair
        let (public_key, private_key) = key_gen(ParameterSet::ML_DSA_44)?;
        
        // Test message
        let message = b"TURTL test message";
        let context = b"";
        
        // Sign the message
        let signature = sign(&private_key, message, context, SigningMode::Hedged)?;
        
        // Verify the signature
        let is_valid = verify(&public_key, message, &signature, context)?;
        
        assert!(is_valid);
        Ok(())
    }
    
    #[test]
    fn test_deterministic_signing() -> Result<()> {
        // Generate a key pair
        let (public_key, private_key) = key_gen(ParameterSet::ML_DSA_44)?;
        
        // Test message
        let message = b"TURTL deterministic signature test";
        let context = b"";
        
        // Sign the message deterministically
        let signature1 = sign(&private_key, message, context, SigningMode::Deterministic)?;
        let signature2 = sign(&private_key, message, context, SigningMode::Deterministic)?;
        
        // Both signatures should be identical
        assert_eq!(signature1.as_bytes(), signature2.as_bytes());
        
        // Verify the signature
        let is_valid = verify(&public_key, message, &signature1, context)?;
        
        assert!(is_valid);
        Ok(())
    }
}