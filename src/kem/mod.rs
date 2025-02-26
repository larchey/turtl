//! ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) implementation.
//! 
//! This module implements the ML-KEM algorithm as specified in NIST FIPS 203.
//! ML-KEM is a post-quantum key encapsulation mechanism based on the Module-LWE problem.

use crate::error::{Error, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod params;
pub mod keypair;
pub mod encapsulate;
pub mod decapsulate;
pub mod shell;
mod internal;

pub use params::ParameterSet;
pub use keypair::KeyPair;

/// ML-KEM public key (encapsulation key)
#[derive(Clone, Debug, Zeroize)]
pub struct PublicKey {
    /// Raw byte representation of the public key
    bytes: Vec<u8>,
    /// Parameter set associated with this key
    parameter_set: ParameterSet,
}

impl PublicKey {
    /// Create a new public key from raw bytes
    pub fn new(bytes: Vec<u8>, parameter_set: ParameterSet) -> Result<Self> {
        // Check if the bytes have the correct length for the parameter set
        let expected_len = parameter_set.public_key_size();
        if bytes.len() != expected_len {
            return Err(Error::InvalidPublicKey);
        }
        
        Ok(Self {
            bytes,
            parameter_set,
        })
    }
    
    /// Get the raw bytes of the public key
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    
    /// Get the parameter set associated with this key
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }
}

/// ML-KEM private key (decapsulation key)
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    /// Raw byte representation of the private key
    bytes: Vec<u8>,
    /// Parameter set associated with this key
    parameter_set: ParameterSet,
}

impl PrivateKey {
    /// Create a new private key from raw bytes
    pub fn new(bytes: Vec<u8>, parameter_set: ParameterSet) -> Result<Self> {
        // Check if the bytes have the correct length for the parameter set
        let expected_len = parameter_set.private_key_size();
        if bytes.len() != expected_len {
            return Err(Error::InvalidPrivateKey);
        }
        
        Ok(Self {
            bytes,
            parameter_set,
        })
    }
    
    /// Get the raw bytes of the private key
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    
    /// Get the parameter set associated with this key
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }
}

/// ML-KEM ciphertext
#[derive(Clone, Debug, Zeroize)]
pub struct Ciphertext {
    /// Raw byte representation of the ciphertext
    bytes: Vec<u8>,
    /// Parameter set associated with this ciphertext
    parameter_set: ParameterSet,
}

impl Ciphertext {
    /// Create a new ciphertext from raw bytes
    pub fn new(bytes: Vec<u8>, parameter_set: ParameterSet) -> Result<Self> {
        // Check if the bytes have the correct length for the parameter set
        let expected_len = parameter_set.ciphertext_size();
        if bytes.len() != expected_len {
            return Err(Error::InvalidCiphertext);
        }
        
        Ok(Self {
            bytes,
            parameter_set,
        })
    }
    
    /// Get the raw bytes of the ciphertext
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    
    /// Get the parameter set associated with this ciphertext
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }
}

/// ML-KEM shared secret
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SharedSecret {
    /// Raw byte representation of the shared secret
    bytes: [u8; 32],
}

impl SharedSecret {
    /// Create a new shared secret from raw bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
    
    /// Get the raw bytes of the shared secret
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Generate a new ML-KEM key pair
pub fn key_gen(parameter_set: ParameterSet) -> Result<(PublicKey, PrivateKey)> {
    keypair::generate(parameter_set)
}

/// Encapsulate a shared secret using a public key
pub fn encapsulate(public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
    encapsulate::encapsulate(public_key)
}

/// Decapsulate a shared secret using a private key and ciphertext
pub fn decapsulate(private_key: &PrivateKey, ciphertext: &Ciphertext) -> Result<SharedSecret> {
    decapsulate::decapsulate(private_key, ciphertext)
}