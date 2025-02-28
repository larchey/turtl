//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm) implementation.
//! 
//! This module implements the ML-DSA algorithm as specified in NIST FIPS 204.
//! ML-DSA is a post-quantum digital signature scheme based on the Module-LWE problem.

use crate::error::{Error, Result};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod params;
pub mod keypair;
pub mod sign;
pub mod verify;
pub mod stamp;
mod internal;

pub use params::ParameterSet;
pub use keypair::KeyPair;

/// Signing mode
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningMode {
    /// Default mode that uses fresh randomness for protection against side-channel attacks
    Hedged,
    /// Deterministic mode that does not use fresh randomness
    Deterministic,
}

/// ML-DSA public key
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

/// ML-DSA private key
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

/// ML-DSA signature
#[derive(Clone, Debug, Zeroize)]
pub struct Signature {
    /// Raw byte representation of the signature
    bytes: Vec<u8>,
    /// Parameter set associated with this signature
    parameter_set: ParameterSet,
}

impl Signature {
    /// Create a new signature from raw bytes
    pub fn new(bytes: Vec<u8>, parameter_set: ParameterSet) -> Result<Self> {
        // Check if the bytes have the correct length for the parameter set
        let expected_len = parameter_set.signature_size();
        if bytes.len() != expected_len {
            return Err(Error::InvalidSignature);
        }
        
        Ok(Self {
            bytes,
            parameter_set,
        })
    }
    
    /// Get the raw bytes of the signature
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    
    /// Get the parameter set associated with this signature
    pub fn parameter_set(&self) -> ParameterSet {
        self.parameter_set
    }
}

/// Supported hash functions for pre-hash mode
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashFunction {
    /// SHA3-256
    SHA3_256,
    /// SHA3-512
    SHA3_512,
    /// SHAKE128 with 256-bit output
    SHAKE128,
    /// SHAKE256 with 512-bit output
    SHAKE256,
}

/// Generate a new ML-DSA key pair
pub fn key_gen(parameter_set: ParameterSet) -> Result<(PublicKey, PrivateKey)> {
    let keypair = keypair::generate(parameter_set)?;
    Ok((keypair.public_key(), keypair.private_key()))
}

/// Sign a message
pub fn sign(
    private_key: &PrivateKey, 
    message: &[u8], 
    context: &[u8],
    mode: SigningMode,
) -> Result<Signature> {
    sign::sign(private_key, message, context, mode)
}

/// Verify a signature
pub fn verify(
    public_key: &PublicKey, 
    message: &[u8], 
    signature: &Signature,
    context: &[u8],
) -> Result<bool> {
    verify::verify(public_key, message, signature, context)
}

/// Sign a message with pre-hashing
pub fn hash_sign(
    private_key: &PrivateKey, 
    message: &[u8], 
    context: &[u8],
    hash_function: HashFunction,
    mode: SigningMode,
) -> Result<Signature> {
    sign::hash_sign(private_key, message, context, hash_function, mode)
}

/// Verify a signature with pre-hashing
pub fn hash_verify(
    public_key: &PublicKey, 
    message: &[u8], 
    signature: &Signature,
    context: &[u8],
    hash_function: HashFunction,
) -> Result<bool> {
    verify::hash_verify(public_key, message, signature, context, hash_function)
}