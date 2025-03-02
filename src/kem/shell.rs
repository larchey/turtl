//! ML-KEM Shell - Key derivation utilities for ML-KEM shared secrets.
//! 
//! The Shell provides a protective layer around the shared secret,
//! making it easy to derive various keys for encryption, authentication, etc.

use crate::error::{Error, Result};
use super::SharedSecret;
use crate::common::hash::shake256;

/// ML-KEM Shell for key derivation and usage
#[derive(Clone, Debug)]
pub struct Shell {
    /// The underlying shared secret
    shared_secret: SharedSecret,
}

impl Shell {
    /// Create a new Shell from a shared secret
    pub fn new(shared_secret: SharedSecret) -> Self {
        Self { shared_secret }
    }
    
    /// Get the raw shared secret
    pub fn shared_secret(&self) -> &SharedSecret {
        &self.shared_secret
    }
    
    /// Derive an encryption key for AES-256
    pub fn derive_encryption_key(&self) -> [u8; 32] {
        // Create a context with proper length and null termination
        let context = b"enc-key\0";
        
        let mut result = [0u8; 32];
        // Combine context and shared secret for derivation
        let input = [context.as_ref(), self.shared_secret.as_bytes()].concat();
        let derived = shake256(&input, 32);
        result.copy_from_slice(&derived);
        
        result
    }
    
    /// Derive an authentication key for HMAC
    pub fn derive_authentication_key(&self) -> [u8; 32] {
        // Create a context with proper length and null termination
        let context = b"auth-key\0";
        
        let mut result = [0u8; 32];
        // Combine context and shared secret for derivation
        let input = [context.as_ref(), self.shared_secret.as_bytes()].concat();
        let derived = shake256(&input, 32);
        result.copy_from_slice(&derived);
        
        result
    }
    
    /// Derive multiple keys at once
    pub fn derive_key_pair(&self) -> ([u8; 32], [u8; 32]) {
        // Create a context with proper length and null termination
        let context = b"key-pair\0";
        
        // Combine context and shared secret for derivation
        let input = [context.as_ref(), self.shared_secret.as_bytes()].concat();
        let derived = shake256(&input, 64);
        
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        
        key1.copy_from_slice(&derived[0..32]);
        key2.copy_from_slice(&derived[32..64]);
        
        (key1, key2)
    }
    
    /// Derive a key for a specific purpose
    pub fn derive_key_for_context(&self, context: &[u8]) -> Result<[u8; 32]> {
        if context.len() > 64 {
            return Err(Error::EncodingError("Context too long".to_string()));
        }
        
        let mut result = [0u8; 32];
        let derived = shake256(&[context, self.shared_secret.as_bytes()].concat(), 32);
        result.copy_from_slice(&derived);
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_derivation() {
        // Create a dummy shared secret
        let secret_bytes = [42u8; 32];
        let shared_secret = SharedSecret::new(secret_bytes);
        
        // Create a shell
        let shell = Shell::new(shared_secret);
        
        // Derive keys
        let enc_key = shell.derive_encryption_key();
        let auth_key = shell.derive_authentication_key();
        
        // Keys should be different
        assert_ne!(enc_key, auth_key);
        
        // Keys should be deterministic
        let enc_key2 = shell.derive_encryption_key();
        assert_eq!(enc_key, enc_key2);
    }
    
    #[test]
    fn test_key_pair_derivation() {
        // Create a dummy shared secret
        let secret_bytes = [42u8; 32];
        let shared_secret = SharedSecret::new(secret_bytes);
        
        // Create a shell
        let shell = Shell::new(shared_secret);
        
        // Derive key pair
        let (key1, key2) = shell.derive_key_pair();
        
        // Keys should be different
        assert_ne!(key1, key2);
        
        // Keys should be deterministic
        let (key1_again, key2_again) = shell.derive_key_pair();
        assert_eq!(key1, key1_again);
        assert_eq!(key2, key2_again);
    }
    
    #[test]
    fn test_contextual_key_derivation() {
        // Create a dummy shared secret
        let secret_bytes = [42u8; 32];
        let shared_secret = SharedSecret::new(secret_bytes);
        
        // Create a shell
        let shell = Shell::new(shared_secret);
        
        // Derive keys for different contexts
        let key1 = shell.derive_key_for_context(b"context1").unwrap();
        let key2 = shell.derive_key_for_context(b"context2").unwrap();
        
        // Keys for different contexts should be different
        assert_ne!(key1, key2);
        
        // Keys for the same context should be the same
        let key1_again = shell.derive_key_for_context(b"context1").unwrap();
        assert_eq!(key1, key1_again);
    }
}