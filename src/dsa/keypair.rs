//! ML-DSA key generation implementation.
//! 
//! This module implements the key generation algorithm for ML-DSA.

use crate::error::{Error, Result};
use super::{ParameterSet, PublicKey, PrivateKey};
use crate::common::hash;
use rand::{RngCore, CryptoRng, rngs::OsRng};
use super::internal::{ml_dsa_keygen_internal, seed_to_keypair};

/// ML-DSA key pair
#[derive(Clone, Debug)]
pub struct KeyPair {
    /// Public key
    public_key: PublicKey,
    /// Private key
    private_key: PrivateKey,
}

impl KeyPair {
    /// Generate a new ML-DSA key pair
    pub fn generate(parameter_set: ParameterSet) -> Result<Self> {
        generate(parameter_set)
    }
    
    /// Create a new key pair from existing public and private keys
    pub fn from_keys(public_key: PublicKey, private_key: PrivateKey) -> Result<Self> {
        // Ensure both keys use the same parameter set
        if public_key.parameter_set() != private_key.parameter_set() {
            return Err(Error::InvalidParameterSet);
        }
        
        Ok(Self {
            public_key,
            private_key,
        })
    }
    
    /// Create a key pair from a seed
    pub fn from_seed(seed: &[u8], parameter_set: ParameterSet) -> Result<Self> {
        if seed.len() != 32 {
            return Err(Error::InvalidParameterSet);
        }
        
        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(seed);
        
        seed_to_keypair(&seed_array, parameter_set)
    }
    
    /// Get the public key
    pub fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }
    
    /// Get the private key
    pub fn private_key(&self) -> PrivateKey {
        self.private_key.clone()
    }
    
    /// Get the parameter set associated with this key pair
    pub fn parameter_set(&self) -> ParameterSet {
        self.public_key.parameter_set()
    }
}

/// Generate a new ML-DSA key pair
pub fn generate(parameter_set: ParameterSet) -> Result<KeyPair> {
    // Generate a random 32-byte seed
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    
    // Generate key pair from seed
    seed_to_keypair(&seed, parameter_set)
}

/// Generate a key pair with a provided RNG
pub fn generate_with_rng<R>(parameter_set: ParameterSet, rng: &mut R) -> Result<KeyPair> 
where 
    R: RngCore + CryptoRng 
{
    // Generate a random 32-byte seed
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    
    // Generate key pair from seed
    seed_to_keypair(&seed, parameter_set)
}