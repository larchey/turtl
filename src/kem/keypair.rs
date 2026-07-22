//! ML-KEM key generation implementation.
//!
//! This module implements the key generation algorithm for ML-KEM.

use super::internal::seed_to_keypair;
use super::{ParameterSet, PrivateKey, PublicKey};
use crate::error::{Error, Result};
use rand::{rngs::OsRng, CryptoRng, RngCore};

/// ML-KEM key pair
#[derive(Clone, Debug)]
pub struct KeyPair {
    /// Public key (encapsulation key)
    public_key: PublicKey,
    /// Private key (decapsulation key)
    private_key: PrivateKey,
}

impl KeyPair {
    /// Generate a new ML-KEM key pair
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

    /// Create a key pair from the two 32-byte seeds `d` and `z`, matching
    /// FIPS 203 ML-KEM.KeyGen_internal(d, z). This is the deterministic,
    /// KAT-reproducible entry point.
    pub fn from_seeds(d: &[u8; 32], z: &[u8; 32], parameter_set: ParameterSet) -> Result<Self> {
        seed_to_keypair(d, z, parameter_set)
    }

    /// Create a key pair from a single 32-byte seed, used as both `d` and `z`.
    ///
    /// For NIST-vector reproduction use [`KeyPair::from_seeds`] with independent
    /// `d` and `z`.
    pub fn from_seed(seed: &[u8], parameter_set: ParameterSet) -> Result<Self> {
        if seed.len() != 32 {
            return Err(Error::InvalidParameterSet);
        }

        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(seed);

        seed_to_keypair(&seed_array, &seed_array, parameter_set)
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

/// Generate a new ML-KEM key pair
pub fn generate(parameter_set: ParameterSet) -> Result<KeyPair> {
    generate_with_rng(parameter_set, &mut OsRng)
}

/// Generate a key pair with a provided RNG
pub fn generate_with_rng<R>(parameter_set: ParameterSet, rng: &mut R) -> Result<KeyPair>
where
    R: RngCore + CryptoRng,
{
    // FIPS 203 KeyGen draws two independent 32-byte seeds d and z.
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    rng.fill_bytes(&mut d);
    rng.fill_bytes(&mut z);

    seed_to_keypair(&d, &z, parameter_set)
}
