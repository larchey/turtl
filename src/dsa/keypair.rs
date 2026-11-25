//! ML-DSA key generation implementation.
//!
//! This module implements the key generation algorithm for ML-DSA.

use super::internal::seed_to_keypair;
use super::{ParameterSet, PrivateKey, PublicKey};
use crate::error::{Error, Result};
use rand::{rngs::OsRng, CryptoRng, RngCore};
use zeroize::Zeroizing;

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
        let seed_array: Zeroizing<[u8; 32]> = Zeroizing::new(
            seed.try_into()
                .map_err(|_| Error::InvalidParameter("seed must be exactly 32 bytes".into()))?,
        );

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
    generate_with_rng(parameter_set, &mut OsRng)
}

/// Generate a key pair with a provided RNG
pub fn generate_with_rng<R>(parameter_set: ParameterSet, rng: &mut R) -> Result<KeyPair>
where
    R: RngCore + CryptoRng,
{
    // Generate a random 32-byte seed
    let mut seed = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(seed.as_mut());

    // Generate key pair from seed
    seed_to_keypair(&seed, parameter_set)
}
