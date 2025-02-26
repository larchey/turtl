//! Internal implementation details for ML-KEM.
//! 
//! This module contains the core algorithms used for ML-KEM key generation,
//! encapsulation, and decapsulation as specified in NIST FIPS 203.

use crate::error::{Error, Result};
use crate::kem::{ParameterSet, PublicKey, PrivateKey, Ciphertext, SharedSecret};
use crate::common::{ntt::NTTContext, poly::Polynomial, hash};
use zeroize::Zeroize;

pub mod k_pke;
pub mod aux;

/// Generate a keypair from a seed.
pub(crate) fn seed_to_keypair(seed: &[u8; 32], parameter_set: ParameterSet) -> Result<super::KeyPair> {
    // Call the internal key generation function
    let (public_key_bytes, private_key_bytes) = ml_kem_keygen_internal(seed, parameter_set)?;
    
    // Create public and private key objects
    let public_key = PublicKey::new(public_key_bytes, parameter_set)?;
    let private_key = PrivateKey::new(private_key_bytes, parameter_set)?;
    
    // Return the key pair
    Ok(super::KeyPair::from_keys(public_key, private_key)?)
}

/// Internal function for ML-KEM key generation
pub(crate) fn ml_kem_keygen_internal(
    seed: &[u8; 32], 
    parameter_set: ParameterSet
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Implementation of ML-KEM.KeyGen_internal from FIPS 203
    
    // 1. Expand the seed to get rho, rho', and K
    let k = parameter_set.k();
    let expanded = hash::h_function(&[seed, &[k as u8, 0]].concat(), 128);
    
    let mut rho = [0u8; 32];
    let mut rhoprime = [0u8; 64];
    let mut key_seed = [0u8; 32];
    
    rho.copy_from_slice(&expanded[0..32]);
    rhoprime.copy_from_slice(&expanded[32..96]);
    key_seed.copy_from_slice(&expanded[96..128]);
    
    // 2-4. Generate matrix A, vectors s1 and s2
    let (matrix_a, s1, s2) = k_pke::generate_key_components(&rho, &rhoprime, parameter_set)?;
    
    // 5. Compute t = As1 + s2
    let t = k_pke::compute_public_t(&matrix_a, &s1, &s2)?;
    
    // 6. Compress t
    let (t1, t0) = k_pke::power2round(&t, parameter_set)?;
    
    // 7-10. Encode the keys
    let public_key_bytes = k_pke::encode_public_key(&rho, &t1, parameter_set)?;
    let tr = hash::h_function(&public_key_bytes, 64);
    let private_key_bytes = k_pke::encode_private_key(&rho, &key_seed, &tr, &s1, &s2, &t0, parameter_set)?;
    
    Ok((public_key_bytes, private_key_bytes))
}

/// Internal function for ML-KEM encapsulation
pub(crate) fn ml_kem_encaps_internal(
    public_key_bytes: &[u8],
    message: &[u8; 32],
    parameter_set: ParameterSet
) -> Result<(Vec<u8>, [u8; 32])> {
    // Implementation of ML-KEM.Encaps_internal from FIPS 203
    
    // 1. Derive key K and randomness r from message and hash of public key
    let public_key_hash = hash::h_function(public_key_bytes, 32);
    let (k, r) = hash::g_function(&[message, &public_key_hash].concat());
    
    // 2. Encrypt message using PKE with derived randomness
    let ciphertext = k_pke::encrypt(public_key_bytes, message, &r, parameter_set)?;
    
    Ok((ciphertext, k))
}

/// Internal function for ML-KEM decapsulation
pub(crate) fn ml_kem_decaps_internal(
    private_key_bytes: &[u8],
    ciphertext: &[u8],
    parameter_set: ParameterSet
) -> Result<[u8; 32]> {
    // Implementation of ML-KEM.Decaps_internal from FIPS 203
    
    // 1-4. Extract components from the private key
    let (dk_pke, ek_pke, h, z) = k_pke::decode_private_key(private_key_bytes, parameter_set)?;
    
    // 5. Decrypt the ciphertext
    let m_prime = k_pke::decrypt(&dk_pke, ciphertext, parameter_set)?;
    
    // 6. Re-derive K' and r'
    let (k_prime, r_prime) = hash::g_function(&[&m_prime, &h].concat());
    
    // 7-8. Alternative K in case of failure
    let k_bar = hash::h_function(&[&z, ciphertext].concat(), 32);
    
    // 9. Re-encrypt using derived randomness
    let c_prime = k_pke::encrypt(&ek_pke, &m_prime, &r_prime, parameter_set)?;
    
    // 10-11. Check if ciphertexts match
    let mut k = k_prime;
    if ciphertext != &c_prime[..] {
        k.copy_from_slice(&k_bar);
    }
    
    Ok(k)
}

pub(crate) fn encapsulate_internal(public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
    // Generate a random 32-byte message
    use rand::{rngs::OsRng, RngCore};
    let mut m = [0u8; 32];
    OsRng.fill_bytes(&mut m);
    
    // Call the internal encapsulation function
    let (ciphertext_bytes, shared_secret_bytes) = ml_kem_encaps_internal(
        public_key.as_bytes(),
        &m,
        public_key.parameter_set()
    )?;
    
    // Create ciphertext and shared secret objects
    let ciphertext = Ciphertext::new(ciphertext_bytes, public_key.parameter_set())?;
    let shared_secret = SharedSecret::new(shared_secret_bytes);
    
    Ok((ciphertext, shared_secret))
}

pub(crate) fn decapsulate_internal(private_key: &PrivateKey, ciphertext: &Ciphertext) -> Result<SharedSecret> {
    // Check that the parameter sets match
    if private_key.parameter_set() != ciphertext.parameter_set() {
        return Err(Error::InvalidParameterSet);
    }
    
    // Call the internal decapsulation function
    let shared_secret_bytes = ml_kem_decaps_internal(
        private_key.as_bytes(),
        ciphertext.as_bytes(),
        private_key.parameter_set()
    )?;
    
    // Create shared secret object
    let shared_secret = SharedSecret::new(shared_secret_bytes);
    
    Ok(shared_secret)
}