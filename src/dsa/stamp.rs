//! ML-DSA Stamp - High-level signing utilities.
//! 
//! This module provides convenient wrappers for ML-DSA signing operations.

use crate::error::{Error, Result};
use super::{PrivateKey, Signature, SigningMode, HashFunction};
use super::sign::{sign, hash_sign};

/// ML-DSA Stamp for streamlined document signing
#[derive(Clone, Debug)]
pub struct Stamp {
    /// The private key used for signing
    private_key: PrivateKey,
    /// The signing mode to use (hedged or deterministic)
    mode: SigningMode,
    /// Optional context string
    context: Vec<u8>,
}

impl Stamp {
    /// Create a new Stamp from a private key
    pub fn new(private_key: PrivateKey) -> Self {
        Self {
            private_key,
            mode: SigningMode::Hedged, // Default to hedged mode
            context: Vec::new(),
        }
    }
    
    /// Create a new Stamp with a specific signing mode
    pub fn with_mode(private_key: PrivateKey, mode: SigningMode) -> Self {
        Self {
            private_key,
            mode,
            context: Vec::new(),
        }
    }
    
    /// Set a context string for all signatures
    pub fn with_context(mut self, context: &[u8]) -> Result<Self> {
        if context.len() > 255 {
            return Err(Error::ContextTooLong);
        }
        self.context = context.to_vec();
        Ok(self)
    }
    
    /// Sign a document
    pub fn stamp_document(&self, document: &[u8]) -> Result<Signature> {
        sign(&self.private_key, document, &self.context, self.mode)
    }
    
    /// Sign a document with pre-hashing
    pub fn stamp_document_with_hash(&self, document: &[u8], hash_function: HashFunction) -> Result<Signature> {
        hash_sign(&self.private_key, document, &self.context, hash_function, self.mode)
    }
    
    /// Get the parameter set associated with this stamp
    pub fn parameter_set(&self) -> super::ParameterSet {
        self.private_key.parameter_set()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsa::{key_gen, verify, ParameterSet};
    
    #[test]
    fn test_stamp_document() -> Result<()> {
        // Generate a key pair
        let (public_key, private_key) = key_gen(ParameterSet::ML_DSA_44)?;
        
        // Create a stamp
        let stamp = Stamp::new(private_key);
        
        // Test document
        let document = b"TURTL test document";
        
        // Sign the document
        let signature = stamp.stamp_document(document)?;
        
        // Verify the signature
        let is_valid = verify(&public_key, document, &signature, &[])?;
        
        assert!(is_valid);
        Ok(())
    }
    
    #[test]
    fn test_stamp_with_context() -> Result<()> {
        // Generate a key pair
        let (public_key, private_key) = key_gen(ParameterSet::ML_DSA_44)?;
        
        // Create a stamp with context
        let context = b"TURTL context";
        let stamp = Stamp::new(private_key).with_context(context)?;
        
        // Test document
        let document = b"TURTL test document";
        
        // Sign the document
        let signature = stamp.stamp_document(document)?;
        
        // Verify the signature with correct context
        let is_valid = verify(&public_key, document, &signature, context)?;
        assert!(is_valid);
        
        // Verify with wrong context should fail
        let wrong_context = b"wrong context";
        let is_valid = verify(&public_key, document, &signature, wrong_context)?;
        assert!(!is_valid);
        
        Ok(())
    }
}