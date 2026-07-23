//! Internal implementation details for ML-KEM.
//!
//! This module contains the core algorithms used for ML-KEM key generation,
//! encapsulation, and decapsulation as specified in NIST FIPS 203.

use crate::common::hash;
use crate::error::{Error, Result};
use crate::kem::{Ciphertext, ParameterSet, PrivateKey, PublicKey, SharedSecret};

pub mod aux;
pub mod k_pke;

/// Generate a keypair from the two 32-byte seeds d and z (FIPS 203 KeyGen_internal).
pub(crate) fn seed_to_keypair(
    d: &[u8; 32],
    z: &[u8; 32],
    parameter_set: ParameterSet,
) -> Result<super::KeyPair> {
    let (public_key_bytes, private_key_bytes) = ml_kem_keygen_internal(d, z, parameter_set)?;

    let public_key = PublicKey::new(public_key_bytes, parameter_set)?;
    let private_key = PrivateKey::new(private_key_bytes, parameter_set)?;

    super::KeyPair::from_keys(public_key, private_key)
}

/// ML-KEM.KeyGen_internal (FIPS 203): expand d into (rho, sigma) with G, and
/// append the independent implicit-rejection value z to the private key.
pub(crate) fn ml_kem_keygen_internal(
    d: &[u8; 32],
    z: &[u8; 32],
    parameter_set: ParameterSet,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let k = parameter_set.k();

    // 1. (rho, sigma) = G(d || k), where G = SHA3-512.
    let mut g_input = Vec::with_capacity(33);
    g_input.extend_from_slice(d);
    g_input.push(k as u8);
    let (rho, sigma) = hash::g_function(&g_input);

    // 2-4. Generate matrix A-hat, secret vector s, and error vector e
    let (matrix_a, s, e) = k_pke::generate_key_components(&rho, &sigma, parameter_set)?;

    // 5. Compute t-hat = A-hat·s-hat + e-hat (all in the NTT domain, FIPS 203)
    let (t_hat, s_hat) = k_pke::compute_public_t(&matrix_a, &s, &e)?;

    // 6-7. Encode the public key: ek_pke = ByteEncode_12(t-hat) || ρ
    let public_key_bytes = k_pke::encode_public_key(&rho, &t_hat, parameter_set)?;

    // 8. Compute H(ek_pke) = SHA3-256(ek_pke) (32 bytes), per FIPS 203
    let tr = hash::sha3_256(&public_key_bytes).to_vec();

    // 9-10. Encode the private key: dk_pke || ek_pke || H(ek_pke) || z
    // where dk_pke = ByteEncode_12(s-hat) (NTT domain, FIPS 203)
    let dk_pke = k_pke::encode_private_key_pke(&s_hat)?;
    let mut private_key_bytes = Vec::new();
    private_key_bytes.extend(&dk_pke);
    private_key_bytes.extend(&public_key_bytes);
    private_key_bytes.extend(&tr);
    private_key_bytes.extend(z);

    Ok((public_key_bytes, private_key_bytes))
}

/// Internal function for ML-KEM encapsulation
pub(crate) fn ml_kem_encaps_internal(
    public_key_bytes: &[u8],
    message: &[u8; 32],
    parameter_set: ParameterSet,
) -> Result<(Vec<u8>, [u8; 32])> {
    // Implementation of ML-KEM.Encaps_internal from FIPS 203

    // 1. Derive key K and randomness r from message and H(ek) = SHA3-256(ek)
    let public_key_hash = hash::sha3_256(public_key_bytes).to_vec();
    let mut msg_data = Vec::with_capacity(message.len() + public_key_hash.len());
    msg_data.extend_from_slice(message);
    msg_data.extend_from_slice(&public_key_hash);
    let (k, r) = hash::g_function(&msg_data);

    // 2. Encrypt message using PKE with derived randomness
    let ciphertext = k_pke::encrypt(public_key_bytes, message, &r, parameter_set)?;

    Ok((ciphertext, k))
}

/// Internal function for ML-KEM decapsulation
pub(crate) fn ml_kem_decaps_internal(
    private_key_bytes: &[u8],
    ciphertext: &[u8],
    parameter_set: ParameterSet,
) -> Result<[u8; 32]> {
    // Implementation of ML-KEM.Decaps_internal from FIPS 203

    // 1-4. Extract components from the private key
    let (dk_pke, ek_pke, h, z) = k_pke::decode_private_key(private_key_bytes, parameter_set)?;

    // 5. Decrypt the ciphertext
    let m_prime = k_pke::decrypt(&dk_pke, ciphertext, parameter_set)?;

    // 6. Re-derive K' and r'
    let mut prime_data = Vec::with_capacity(m_prime.len() + h.len());
    prime_data.extend_from_slice(&m_prime);
    prime_data.extend_from_slice(&h);
    let (k_prime, r_prime) = hash::g_function(&prime_data);

    // 7-8. Alternative K in case of failure
    let k_bar = hash::h_function(&[&z, ciphertext].concat(), 32);

    // 9. Re-encrypt using derived randomness
    let c_prime = k_pke::encrypt(&ek_pke, &m_prime, &r_prime, parameter_set)?;

    // 10-11. Select K' if the ciphertext re-encrypts correctly, else the
    // implicit-rejection value K_bar — in constant time.
    use crate::security::constant_time;
    use crate::security::fault_detection;

    let is_equal =
        ciphertext.len() == c_prime.len() && fault_detection::ct_eq(ciphertext, &c_prime);

    let mut k = [0u8; 32];
    for i in 0..32 {
        k[i] = constant_time::ct_select_byte(k_prime[i], k_bar[i], is_equal);
    }

    Ok(k)
}

pub(crate) fn encapsulate_internal(public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
    // Generate a random 32-byte message
    use rand::{rngs::OsRng, RngCore};
    let mut m = [0u8; 32];
    OsRng.fill_bytes(&mut m);

    // Call the internal encapsulation function
    let (ciphertext_bytes, shared_secret_bytes) =
        ml_kem_encaps_internal(public_key.as_bytes(), &m, public_key.parameter_set())?;

    // Create ciphertext and shared secret objects
    let ciphertext = Ciphertext::new(ciphertext_bytes, public_key.parameter_set())?;
    let shared_secret = SharedSecret::new(shared_secret_bytes);

    Ok((ciphertext, shared_secret))
}

pub(crate) fn decapsulate_internal(
    private_key: &PrivateKey,
    ciphertext: &Ciphertext,
) -> Result<SharedSecret> {
    // Check that the parameter sets match
    if private_key.parameter_set() != ciphertext.parameter_set() {
        return Err(Error::InvalidParameterSet);
    }

    let shared_secret_bytes = ml_kem_decaps_internal(
        private_key.as_bytes(),
        ciphertext.as_bytes(),
        private_key.parameter_set(),
    )?;

    Ok(SharedSecret::new(shared_secret_bytes))
}
