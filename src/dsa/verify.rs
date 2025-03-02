//! ML-DSA verification implementation.
//! 
//! This module implements the verification algorithms for ML-DSA.

use crate::error::{Error, Result};
use super::{PublicKey, Signature, HashFunction};
use super::internal::{ml_dsa_verify_internal, ml_dsa_hash_verify_internal};

/// Verify a signature using ML-DSA
pub fn verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
    context: &[u8],
) -> Result<bool> {
    // Check if context is valid (max 255 bytes)
    if context.len() > 255 {
        return Err(Error::ContextTooLong);
    }
    
    // Check that the parameter sets match
    if public_key.parameter_set() != signature.parameter_set() {
        return Err(Error::InvalidParameterSet);
    }
    
    // Format message with domain separator and context
    // Domain separator 0 for regular signing
    let domain_separator = 0u8;
    let formatted_message = format_message(message, context, domain_separator)?;
    
    // Call internal verification function
    ml_dsa_verify_internal(
        public_key.as_bytes(),
        &formatted_message,
        signature.as_bytes(),
        public_key.parameter_set()
    )
}

/// Verify a signature with pre-hashing using ML-DSA
pub fn hash_verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
    context: &[u8],
    hash_function: HashFunction,
) -> Result<bool> {
    // Check if context is valid (max 255 bytes)
    if context.len() > 255 {
        return Err(Error::ContextTooLong);
    }
    
    // Check that the parameter sets match
    if public_key.parameter_set() != signature.parameter_set() {
        return Err(Error::InvalidParameterSet);
    }
    
    // Call internal hash-then-verify function
    ml_dsa_hash_verify_internal(
        public_key.as_bytes(),
        message,
        signature.as_bytes(),
        context,
        hash_function,
        public_key.parameter_set()
    )
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
    use crate::dsa::{key_gen, sign, SigningMode, ParameterSet};
    
    #[test]
    fn test_verify_valid_signature() -> Result<()> {
        // Generate a key pair
        let (public_key, private_key) = key_gen(ParameterSet::MlDsa44)?;
        
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
    fn test_verify_invalid_signature() -> Result<()> {
        // Generate a key pair
        let (public_key, private_key) = key_gen(ParameterSet::MlDsa44)?;
        
        // Test message
        let message = b"TURTL test message";
        let wrong_message = b"TURTL wrong message";
        let context = b"";
        
        // Sign the message
        let signature = sign(&private_key, message, context, SigningMode::Hedged)?;
        
        // Verify with wrong message
        let is_valid = verify(&public_key, wrong_message, &signature, context)?;
        
        assert!(!is_valid);
        Ok(())
    }
}