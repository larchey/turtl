//! Internal implementation details for ML-DSA.
//! 
//! This module contains the core algorithms used for ML-DSA key generation,
//! signing, and verification as specified in NIST FIPS 204.

use crate::error::{Error, Result};
use crate::dsa::{ParameterSet, PublicKey, PrivateKey, Signature, HashFunction};
use crate::common::{ntt::NTTContext, poly::Polynomial, hash, sample::SampleInBall};
use zeroize::Zeroize;
use crate::common::ntt::NTTType;

pub mod aux;

/// Generate a keypair from a seed.
pub(crate) fn seed_to_keypair(seed: &[u8; 32], parameter_set: ParameterSet) -> Result<super::KeyPair> {
    // Call the internal key generation function
    let (public_key_bytes, private_key_bytes) = ml_dsa_keygen_internal(seed, parameter_set)?;
    
    // Create public and private key objects
    let public_key = PublicKey::new(public_key_bytes, parameter_set)?;
    let private_key = PrivateKey::new(private_key_bytes, parameter_set)?;
    
    // Return the key pair
    Ok(super::KeyPair::from_keys(public_key, private_key)?)
}

/// Implement ML-DSA key generation from seed
pub(crate) fn ml_dsa_keygen_internal(
    seed: &[u8; 32], 
    parameter_set: ParameterSet
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Implementation of ML-DSA.KeyGen_internal from FIPS 204
    
    // Get parameter values
    let (k, l) = parameter_set.dimensions();
    let eta = parameter_set.eta();
    let d = parameter_set.d();
    
    // 1. Expand the seed to get rho, sigma, and K
    let domain_bytes = [k as u8, l as u8];
    let expanded = hash::h_function(&[seed, &domain_bytes].concat(), 128);
    
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 64];
    let mut key_seed = [0u8; 32];
    
    rho.copy_from_slice(&expanded[0..32]);
    sigma.copy_from_slice(&expanded[32..96]);
    key_seed.copy_from_slice(&expanded[96..128]);
    
    // 2-4. Generate matrix A, vectors s1 and s2
    let ntt_ctx = NTTContext::new(NTTType::MLDSA);
    let matrix_a = expand_a(&rho, k, l)?;
    let (s1, s2) = expand_s(&sigma, l, k, eta)?;
    
    // 5. Compute t = As1 + s2
    let t = compute_public_t(&matrix_a, &s1, &s2, &ntt_ctx)?;
    
    // 6. Power2Round to get t1 and t0
    let (t1, t0) = power2round(&t, d)?;
    
    // 7-10. Encode the keys
    let public_key_bytes = encode_public_key(&rho, &t1, parameter_set)?;
    let tr = hash::h_function(&public_key_bytes, 64);
    let private_key_bytes = encode_private_key(&rho, &key_seed, &tr, &s1, &s2, &t0, parameter_set)?;
    
    Ok((public_key_bytes, private_key_bytes))
}

/// Internal function for ML-DSA signing
pub(crate) fn ml_dsa_sign_internal(
    private_key_bytes: &[u8],
    message: &[u8],
    rnd: &[u8; 32],
    parameter_set: ParameterSet
) -> Result<Vec<u8>> {
    // Extract components from private key
    let (rho, key, tr, s1, s2, t0) = decode_private_key(private_key_bytes, parameter_set)?;
    
    // Get parameters
    let (k, l) = parameter_set.dimensions();
    let gamma1 = parameter_set.gamma1();
    let gamma2 = parameter_set.gamma2();
    let tau = parameter_set.tau();
    let beta = parameter_set.beta();
    let omega = parameter_set.omega();
    
    // Create NTT context
    let ntt_ctx = NTTContext::new(NTTType::MLDSA);
    
    // Generate matrix A
    let matrix_a = expand_a(&rho, k, l)?;
    
    // Convert to NTT domain
    let mut s1_hat = Vec::with_capacity(l);
    let mut s2_hat = Vec::with_capacity(k);
    let mut t0_hat = Vec::with_capacity(k);
    
    for i in 0..l {
        let mut s1_i = s1[i].clone();
        ntt_ctx.forward(&mut s1_i)?;
        s1_hat.push(s1_i);
    }
    
    for i in 0..k {
        let mut s2_i = s2[i].clone();
        ntt_ctx.forward(&mut s2_i)?;
        s2_hat.push(s2_i);
        
        let mut t0_i = t0[i].clone();
        ntt_ctx.forward(&mut t0_i)?;
        t0_hat.push(t0_i);
    }
    
    // Compute mu = H(tr || message)
    let mu = hash::h_function(&[&tr, message].concat(), 64);
    
    // Generate rho' = H(K || rnd || mu)
    let rho_prime = hash::h_function(&[&key, rnd, &mu].concat(), 64);
    
    // Initialize counter
    let mut kappa = 0u16;
    
    // Loop until a valid signature is found
    loop {
        // Generate y
        let y = expand_mask(&rho_prime, kappa, l, gamma1)?;
        
        // Compute w = Ay
        let mut w = compute_w(&matrix_a, &y, &ntt_ctx)?;
        
        // Decompose w and compute w1
        let mut w1 = Vec::with_capacity(k);
        let mut w0 = Vec::with_capacity(k);
        
        for i in 0..k {
            let (w1_i, w0_i) = decompose(&w[i], gamma2)?;
            w1.push(w1_i);
            w0.push(w0_i);
        }
        
        // Compute c = H(mu || w1)
        let w1_encoded = encode_w1(&w1)?;
        let c_tilde = hash::h_function(&[&mu, &w1_encoded].concat(), parameter_set.lambda() / 4);
        
        // Sample c from challenge space
        let c = sample_in_ball(&c_tilde, tau)?;
        
        // Convert c to NTT domain
        let mut c_hat = c.clone();
        ntt_ctx.forward(&mut c_hat)?;
        
        // Compute z = y + c*s1
        let mut z = y.clone();
        for i in 0..l {
            let mut cs1_i = ntt_ctx.multiply_ntt(&c_hat, &s1_hat[i])?;
            ntt_ctx.inverse(&mut cs1_i)?;
            z[i].add_assign(&cs1_i, ntt_ctx.modulus);
        }
        
        // Check if z is small enough
        let mut z_ok = true;
        for i in 0..l {
            if z[i].infinity_norm() >= gamma1 - beta {
                z_ok = false;
                break;
            }
        }
        
        if !z_ok {
            kappa += 1;
            continue;
        }
        
        // Compute r0 = LowBits(w - c*s2, gamma2)
        let mut r0 = Vec::with_capacity(k);
        let mut cs2 = Vec::with_capacity(k);
        
        for i in 0..k {
            let mut cs2_i = ntt_ctx.multiply_ntt(&c_hat, &s2_hat[i])?;
            ntt_ctx.inverse(&mut cs2_i)?;
            cs2.push(cs2_i.clone());
            
            let mut w_prime = w[i].clone();
            w_prime.sub_assign(&cs2_i, ntt_ctx.modulus);
            
            let (_, r0_i) = decompose(&w_prime, gamma2)?;
            r0.push(r0_i);
        }
        
        // Check if r0 is small enough
        let mut r0_ok = true;
        for i in 0..k {
            if r0[i].infinity_norm() >= gamma2 - beta {
                r0_ok = false;
                break;
            }
        }
        
        if !r0_ok {
            kappa += 1;
            continue;
        }
        
        // Compute ct0
        let mut ct0 = Vec::with_capacity(k);
        for i in 0..k {
            let mut ct0_i = ntt_ctx.multiply_ntt(&c_hat, &t0_hat[i])?;
            ntt_ctx.inverse(&mut ct0_i)?;
            ct0.push(ct0_i);
        }
        
        // Create hints
        let mut h = Vec::with_capacity(k);
        for i in 0..k {
            let mut w_prime = w[i].clone();
            w_prime.sub_assign(&cs2[i], ntt_ctx.modulus);
            
            // Add ct0 to w'
            w_prime.add_assign(&ct0[i], ntt_ctx.modulus);
            
            let h_i = make_hint(&w_prime, &ct0[i], gamma2)?;
            h.push(h_i);
        }
        
        // Count total number of 1's in hints
        let ones_count = count_ones(&h);
        
        // Check if number of 1's is within limit
        if ones_count > omega {
            kappa += 1;
            continue;
        }
        
        // Encode the signature
        return encode_signature(&c_tilde, &z, &h, parameter_set);
    }
}

/// Internal function for ML-DSA verification
pub(crate) fn ml_dsa_verify_internal(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
    parameter_set: ParameterSet
) -> Result<bool> {
    // Decode public key
    let (rho, t1) = decode_public_key(public_key_bytes, parameter_set)?;
    
    // Decode signature
    let (c_tilde, z, h) = decode_signature(signature_bytes, parameter_set)?;
    
    // Get parameters
    let (k, l) = parameter_set.dimensions();
    let gamma1 = parameter_set.gamma1();
    let gamma2 = parameter_set.gamma2();
    let beta = parameter_set.beta();
    let tau = parameter_set.tau();
    
    // Check if z is small enough
    for i in 0..l {
        if z[i].infinity_norm() >= gamma1 - beta {
            return Ok(false);
        }
    }
    
    // Create NTT context
    let ntt_ctx = NTTContext::new(NTTType::MLDSA);

    // Generate matrix A
    let matrix_a = expand_a(&rho, k, l)?;
    
    // Compute tr
    let tr = hash::h_function(public_key_bytes, 64);
    
    // Compute mu = H(tr || message)
    let mu = hash::h_function(&[&tr, message].concat(), 64);
    
    // Sample c from challenge space
    let c = sample_in_ball(&c_tilde, tau)?;
    
    // Convert c to NTT domain
    let mut c_hat = c.clone();
    ntt_ctx.forward(&mut c_hat)?;
    
    // Compute Az
    let az = compute_w(&matrix_a, &z, &ntt_ctx)?;
    
    // Compute c*t1*2^d
    let mut ct1 = Vec::with_capacity(k);
    for i in 0..k {
        let mut t1_hat = t1[i].clone();
        ntt_ctx.forward(&mut t1_hat)?;
        
        let mut ct1_i = ntt_ctx.multiply_ntt(&c_hat, &t1_hat)?;
        ntt_ctx.inverse(&mut ct1_i)?;
        
        // Multiply by 2^d
        for j in 0..256 {
            ct1_i.coeffs[j] <<= parameter_set.d();
        }
        
        ct1.push(ct1_i);
    }
    
    // Compute w' = Az - c*t1*2^d
    let mut w_prime = Vec::with_capacity(k);
    for i in 0..k {
        let mut w_i = az[i].clone();
        w_i.sub_assign(&ct1[i], ntt_ctx.modulus);
        w_prime.push(w_i);
    }
    
    // Use hints to compute w1
    let mut w1 = Vec::with_capacity(k);
    for i in 0..k {
        let w1_i = use_hint(&h[i], &w_prime[i], gamma2)?;
        w1.push(w1_i);
    }
    
    // Encode w1
    let w1_encoded = encode_w1(&w1)?;
    
    // Compute c' = H(mu || w1)
    let c_prime = hash::h_function(&[&mu, &w1_encoded].concat(), parameter_set.lambda() / 4);
    
    // Compare c_tilde and c_prime
    if c_tilde == c_prime {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Internal function for ML-DSA hash-then-sign
pub(crate) fn ml_dsa_hash_sign_internal(
    private_key_bytes: &[u8],
    message: &[u8],
    context: &[u8],
    hash_function: HashFunction,
    rnd: &[u8; 32],
    parameter_set: ParameterSet
) -> Result<Vec<u8>> {
    // Format with domain separator 1 (for pre-hash)
    let domain_separator = 1u8;
    
    // Create context header
    let mut ctx_header = Vec::with_capacity(2 + context.len());
    ctx_header.push(domain_separator);
    ctx_header.push(context.len() as u8);
    ctx_header.extend_from_slice(context);
    
    // Get OID for hash function
    let oid = get_hash_function_oid(hash_function);
    
    // Compute hash of message
    let message_hash = match hash_function {
        HashFunction::SHA3_256 => hash::sha3_256(message).to_vec(),
        HashFunction::SHA3_512 => hash::sha3_512(message).to_vec(),
        HashFunction::SHAKE128 => hash::shake128(message, 32),
        HashFunction::SHAKE256 => hash::shake256(message, 32),
    };
    
    // Create pre-hashed message
    let mut pre_hashed = Vec::with_capacity(ctx_header.len() + oid.len() + message_hash.len());
    pre_hashed.extend_from_slice(&ctx_header);
    pre_hashed.extend_from_slice(&oid);
    pre_hashed.extend_from_slice(&message_hash);
    
    // Call internal signing function
    ml_dsa_sign_internal(private_key_bytes, &pre_hashed, rnd, parameter_set)
}

/// Internal function for ML-DSA hash-then-verify
pub(crate) fn ml_dsa_hash_verify_internal(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
    context: &[u8],
    hash_function: HashFunction,
    parameter_set: ParameterSet
) -> Result<bool> {
    // Format with domain separator 1 (for pre-hash)
    let domain_separator = 1u8;
    
    // Create context header
    let mut ctx_header = Vec::with_capacity(2 + context.len());
    ctx_header.push(domain_separator);
    ctx_header.push(context.len() as u8);
    ctx_header.extend_from_slice(context);
    
    // Get OID for hash function
    let oid = get_hash_function_oid(hash_function);
    
    // Compute hash of message
    let message_hash = match hash_function {
        HashFunction::SHA3_256 => hash::sha3_256(message).to_vec(),
        HashFunction::SHA3_512 => hash::sha3_512(message).to_vec(),
        HashFunction::SHAKE128 => hash::shake128(message, 32),
        HashFunction::SHAKE256 => hash::shake256(message, 32),
    };
    
    // Create pre-hashed message
    let mut pre_hashed = Vec::with_capacity(ctx_header.len() + oid.len() + message_hash.len());
    pre_hashed.extend_from_slice(&ctx_header);
    pre_hashed.extend_from_slice(&oid);
    pre_hashed.extend_from_slice(&message_hash);
    
    // Call internal verification function
    ml_dsa_verify_internal(public_key_bytes, &pre_hashed, signature_bytes, parameter_set)
}

// Utility functions

/// Get OID for hash function in DER encoding
fn get_hash_function_oid(hash_function: HashFunction) -> Vec<u8> {
    match hash_function {
        HashFunction::SHA3_256 => vec![0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
        HashFunction::SHA3_512 => vec![0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
        HashFunction::SHAKE128 => vec![0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B],
        HashFunction::SHAKE256 => vec![0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C],
    }
}

/// Generate matrix A from seed
fn expand_a(rho: &[u8], k: usize, l: usize) -> Result<Vec<Vec<Polynomial>>> {
    let mut matrix_a = Vec::with_capacity(k);
    let ntt_ctx = NTTContext::new(NTTType::MLDSA);

    for i in 0..k {
        let mut row = Vec::with_capacity(l);
        for j in 0..l {
            let seed = [rho, &[j as u8, i as u8]].concat();
            let a_ij = reject_sample_ntt(&seed, &ntt_ctx)?;
            row.push(a_ij);
        }
        matrix_a.push(row);
    }

    Ok(matrix_a)
}

/// Rejection sampling in NTT domain
fn reject_sample_ntt(seed: &[u8], ntt_ctx: &NTTContext) -> Result<Polynomial> {
    let mut poly = Polynomial::new();
    let mut j = 0;
    
    let mut ctx = hash::SHAKE128Context::init();
    ctx.absorb(seed);
    
    while j < 256 {
        let bytes = ctx.squeeze(3);
        
        // Extract two values from 3 bytes
        let d1 = ((bytes[0] as u32) | ((bytes[1] as u32 & 0x0F) << 8)) as i32;
        let d2 = (((bytes[1] as u32 & 0xF0) >> 4) | ((bytes[2] as u32) << 4)) as i32;
        
        // Reject values that are not in [0, q-1]
        if d1 < ntt_ctx.modulus {
            poly.coeffs[j] = d1;
            j += 1;
        }
        
        if j < 256 && d2 < ntt_ctx.modulus {
            poly.coeffs[j] = d2;
            j += 1;
        }
    }
    
    // Already in NTT domain
    Ok(poly)
}

/// Sample secret vectors s1 and s2
fn expand_s(sigma: &[u8], l: usize, k: usize, eta: usize) -> Result<(Vec<Polynomial>, Vec<Polynomial>)> {
    let mut s1 = Vec::with_capacity(l);
    let mut s2 = Vec::with_capacity(k);
    let mut counter = 0u8;
    
    // Sample s1
    for i in 0..l {
        let seed = [sigma, &[counter]].concat();
        counter += 1;
        let s1_i = sample_bounded_poly(&seed, eta)?;
        s1.push(s1_i);
    }
    
    // Sample s2
    for i in 0..k {
        let seed = [sigma, &[counter]].concat();
        counter += 1;
        let s2_i = sample_bounded_poly(&seed, eta)?;
        s2.push(s2_i);
    }
    
    Ok((s1, s2))
}

/// Sample a polynomial with coefficients in [-eta, eta]
fn sample_bounded_poly(seed: &[u8], eta: usize) -> Result<Polynomial> {
    let mut poly = Polynomial::new();
    
    let mut ctx = hash::SHAKE256Context::init();
    ctx.absorb(seed);
    
    let mut j = 0;
    let mut iterations = 0;
    let max_iterations = 480; // Safety limit
    
    while j < 256 && iterations < max_iterations {
        iterations += 1;
        let byte = ctx.squeeze(1)[0];
        
        // Extract two values from each byte
        let b1 = byte & 0x0F;
        let b2 = byte >> 4;
        
        // Use rejection sampling
        if b1 < 15 - 5 + 2*eta + 1 {
            poly.coeffs[j] = (b1 as i32) - (eta as i32);
            j += 1;
        }
        
        if j < 256 && b2 < 15 - 5 + 2*eta + 1 {
            poly.coeffs[j] = (b2 as i32) - (eta as i32);
            j += 1;
        }
    }
    
    if j < 256 {
        return Err(Error::RandomnessError);
    }
    
    Ok(poly)
}

/// Compute t = As1 + s2
fn compute_public_t(
    matrix_a: &[Vec<Polynomial>],
    s1: &[Polynomial],
    s2: &[Polynomial],
    ntt_ctx: &NTTContext
) -> Result<Vec<Polynomial>> {
    let k = matrix_a.len();
    let l = s1.len();
    
    // NTT transform s1
    let mut s1_hat = Vec::with_capacity(l);
    for i in 0..l {
        let mut s1_i_hat = s1[i].clone();
        ntt_ctx.forward(&mut s1_i_hat)?;
        s1_hat.push(s1_i_hat);
    }
    
    // Compute t = As1 + s2
    let mut t = Vec::with_capacity(k);
    
    for i in 0..k {
        let mut t_i = Polynomial::new();
        
        // Compute A[i] * s1
        for j in 0..l {
            let mut prod = ntt_ctx.multiply_ntt(&matrix_a[i][j], &s1_hat[j])?;
            t_i.add_assign(&prod, ntt_ctx.modulus);
        }
        
        // Inverse NTT
        ntt_ctx.inverse(&mut t_i)?;
        
        // Add s2[i]
        t_i.add_assign(&s2[i], ntt_ctx.modulus);
        
        t.push(t_i);
    }
    
    Ok(t)
}

/// Split t into high and low bits (Power2Round)
fn power2round(t: &[Polynomial], d: usize) -> Result<(Vec<Polynomial>, Vec<Polynomial>)> {
    let k = t.len();
    
    let mut t1 = Vec::with_capacity(k);
    let mut t0 = Vec::with_capacity(k);
    
    for i in 0..k {
        let mut t1_i = Polynomial::new();
        let mut t0_i = Polynomial::new();
        
        for j in 0..256 {
            // Compute t1 = ⌊t/2^d⌋
            t1_i.coeffs[j] = t[i].coeffs[j] >> d;
            
            // Compute t0 = t - t1*2^d
            t0_i.coeffs[j] = t[i].coeffs[j] - (t1_i.coeffs[j] << d);
        }
        
        t1.push(t1_i);
        t0.push(t0_i);
    }
    
    Ok((t1, t0))
}

/// Sample a polynomial with exactly tau +/-1 coefficients
fn sample_in_ball(seed: &[u8], tau: usize) -> Result<Polynomial> {
    let mut poly = Polynomial::new();
    
    // Use SHAKE256 to generate randomness
    let mut ctx = hash::SHAKE256Context::init();
    ctx.absorb(seed);
    
    // Generate sign bits
    let sign_bytes = ctx.squeeze(32);
    let sign_bits = bytes_to_bits(&sign_bytes);
    
    // Use Fisher-Yates algorithm to select positions
    let mut indices = Vec::with_capacity(256);
    for i in 0..256 {
        indices.push(i);
    }
    
    for i in (256 - tau)..256 {
        // Get random index j in [0..i]
        let bytes = ctx.squeeze(2);
        let j = ((bytes[0] as u16) | ((bytes[1] as u16) << 8)) % (i as u16 + 1);
        
        // Swap positions i and j
        indices.swap(i, j as usize);
    }
    
    // Set the selected positions to +/-1
    for i in 0..tau {
        let idx = indices[256 - tau + i];
        let sign_bit = sign_bits[i % sign_bits.len()];
        poly.coeffs[idx] = if sign_bit == 0 { 1 } else { -1 };
    }
    
    Ok(poly)
}

/// Generate mask vector y
fn expand_mask(rho_prime: &[u8], kappa: u16, l: usize, gamma1: usize) -> Result<Vec<Polynomial>> {
    let mut y = Vec::with_capacity(l);
    
    for i in 0..l {
        let seed = [rho_prime, &kappa.to_le_bytes(), &(i as u16).to_le_bytes()].concat();
        let y_i = sample_uniform_poly(&seed, gamma1)?;
        y.push(y_i);
    }
    
    Ok(y)
}

/// Sample a polynomial with coefficients in [-gamma1+1, gamma1-1]
fn sample_uniform_poly(seed: &[u8], gamma1: usize) -> Result<Polynomial> {
    let mut poly = Polynomial::new();
    
    let mut ctx = hash::SHAKE256Context::init();
    ctx.absorb(seed);
    
    // Calculate how many bits needed per coefficient
    let bits_needed = bitlen((2 * gamma1 - 2) as u32);
    let bytes_per_coeff = (bits_needed + 7) / 8;
    
    for i in 0..256 {
        let mut valid_coeff = false;
        
        while !valid_coeff {
            let bytes = ctx.squeeze(bytes_per_coeff);
            
            // Convert bytes to an integer (little-endian)
            let mut val = 0i32;
            for j in 0..bytes_per_coeff {
                val |= (bytes[j] as i32) << (8 * j);
            }
            
            // Mask out unused bits
            let mask = (1 << bits_needed) - 1;
            let val_masked = val & mask;
            
            // Map to range [-gamma1+1, gamma1-1]
            let shifted = val_masked - (gamma1 as i32 - 1);
            
            // Accept if in range
            if shifted >= -(gamma1 as i32 - 1) && shifted <= (gamma1 as i32 - 1) {
                poly.coeffs[i] = shifted;
                valid_coeff = true;
            }
        }
    }
    
    Ok(poly)
}

/// Compute w = Az
fn compute_w(
    matrix_a: &[Vec<Polynomial>],
    z: &[Polynomial],
    ntt_ctx: &NTTContext
) -> Result<Vec<Polynomial>> {
    let k = matrix_a.len();
    let l = z.len();
    
    // NTT transform z
    let mut z_hat = Vec::with_capacity(l);
    for i in 0..l {
        let mut z_i_hat = z[i].clone();
        ntt_ctx.forward(&mut z_i_hat)?;
        z_hat.push(z_i_hat);
    }
    
    // Compute w = Az
    let mut w = Vec::with_capacity(k);
    
    for i in 0..k {
        let mut w_i = Polynomial::new();
        
        // Compute A[i] * z
        for j in 0..l {
            let mut prod = ntt_ctx.multiply_ntt(&matrix_a[i][j], &z_hat[j])?;
            w_i.add_assign(&prod, ntt_ctx.modulus);
        }
        
        // Inverse NTT
        ntt_ctx.inverse(&mut w_i)?;
        
        w.push(w_i);
    }
    
    Ok(w)
}

/// Decompose a polynomial into high and low bits
fn decompose(poly: &Polynomial, gamma2: usize) -> Result<(Polynomial, Polynomial)> {
    let mut high = Polynomial::new();
    let mut low = Polynomial::new();
    
    for i in 0..256 {
        let (h, l) = decompose_coefficient(poly.coeffs[i], gamma2);
        high.coeffs[i] = h;
        low.coeffs[i] = l;
    }
    
    Ok((high, low))
}

/// Decompose a single coefficient
fn decompose_coefficient(r: i32, alpha: usize) -> (i32, i32) {
    // Centered remainder modulo 2*alpha
    let mut r0 = r % (2 * alpha as i32);
    if r0 > alpha as i32 {
        r0 -= 2 * alpha as i32;
    } else if r0 < -(alpha as i32) {
        r0 += 2 * alpha as i32;
    }
    
    // Quotient
    let r1 = (r - r0) / (2 * alpha as i32);
    
    (r1, r0)
}

/// Make hint for high bits
fn make_hint(w_prime: &Polynomial, ct0: &Polynomial, gamma2: usize) -> Result<Polynomial> {
    let mut h = Polynomial::new();
    
    for i in 0..256 {
        // Decompose coefficients
        let (w1, _) = decompose_coefficient(w_prime.coeffs[i], gamma2);
        let (v1, _) = decompose_coefficient(w_prime.coeffs[i] - ct0.coeffs[i], gamma2);
        
        // If high bits differ, set hint to 1
        h.coeffs[i] = if w1 != v1 { 1 } else { 0 };
    }
    
    Ok(h)
}

/// Use hint to recover high bits
fn use_hint(h: &Polynomial, r: &Polynomial, gamma2: usize) -> Result<Polynomial> {
    let mut w1 = Polynomial::new();
    let q = 8380417; // ML-DSA modulus (q)
    
    for i in 0..256 {
        // Decompose coefficient
        let (r1, r0) = decompose_coefficient(r.coeffs[i], gamma2);
        
        // Use hint to adjust high bits
        if h.coeffs[i] == 1 {
            let d = if r0 > 0 { 1 } else { -1 };
            w1.coeffs[i] = (r1 + d) % ((q - 1) / (2 * gamma2 as i32));
        } else {
            w1.coeffs[i] = r1;
        }
    }
    
    Ok(w1)
}

/// Encode the w1 component for challenge hash
fn encode_w1(w1: &[Polynomial]) -> Result<Vec<u8>> {
    let k = w1.len();
    // For high bits, we typically use 4 bits per coefficient
    let bits_per_coeff = 4; 
    
    // Calculate number of bytes needed per polynomial
    let bytes_per_poly = (256 * bits_per_coeff + 7) / 8;
    let mut result = Vec::with_capacity(k * bytes_per_poly);
    
    for i in 0..k {
        // Convert polynomial coefficients to bits
        let mut bits = Vec::with_capacity(256 * bits_per_coeff);
        
        for j in 0..256 {
            let coeff = w1[i].coeffs[j] as u32;
            // We need to ensure the coefficient is within the expected range
            if coeff >= (1 << bits_per_coeff) {
                return Err(Error::EncodingError(format!(
                    "Coefficient out of range for w1 encoding: {}", coeff
                )));
            }
            
            // Store coefficient in bits_per_coeff bits
            for b in 0..bits_per_coeff {
                bits.push(((coeff >> b) & 1) as u8);
            }
        }
        
        // Pack bits into bytes
        for b in 0..(bits.len() + 7) / 8 {
            let mut byte = 0u8;
            for j in 0..8 {
                if b * 8 + j < bits.len() {
                    byte |= bits[b * 8 + j] << j;
                }
            }
            result.push(byte);
        }
    }
    
    Ok(result)
}

/// Encode hint for ML-DSA
fn encode_hint(h: &[Polynomial], omega: usize) -> Result<Vec<u8>> {
    let k = h.len();
    let mut result = Vec::with_capacity(omega + k);
    
    // First, gather all positions where coefficients are 1
    let mut positions = Vec::new();
    for i in 0..k {
        for j in 0..256 {
            if h[i].coeffs[j] == 1 {
                positions.push((i, j));
            }
        }
    }
    
    // Check if number of 1s is within limit
    if positions.len() > omega {
        return Err(Error::EncodingError(format!(
            "Too many ones in hint: {}, maximum allowed: {}", positions.len(), omega
        )));
    }
    
    // Sort positions to ensure canonical ordering
    positions.sort_by(|a, b| {
        if a.0 != b.0 {
            a.0.cmp(&b.0)
        } else {
            a.1.cmp(&b.1)
        }
    });
    
    // Store positions in the result
    let mut idx = 0;
    for (i, j) in positions {
        if idx >= omega {
            break;
        }
        result.push(j as u8);
        idx += 1;
    }
    
    // Fill remaining positions with zeros
    while idx < omega {
        result.push(0);
        idx += 1;
    }
    
    // Store number of ones per polynomial
    for i in 0..k {
        let mut count = 0;
        for (poly_idx, _) in &positions {
            if *poly_idx == i {
                count += 1;
            }
        }
        result.push(count);
    }
    
    Ok(result)
}

/// Convert a byte array to a bit array
fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for &byte in bytes {
        for j in 0..8 {
            bits.push((byte >> j) & 1);
        }
    }
    bits
}

/// Convert a bit array to a byte array
fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    let num_bytes = (bits.len() + 7) / 8;
    let mut bytes = vec![0u8; num_bytes];
    
    for (i, &bit) in bits.iter().enumerate() {
        if bit != 0 {
            bytes[i / 8] |= 1 << (i % 8);
        }
    }
    
    bytes
}

/// Count the number of 1's in a hint polynomial vector
fn count_ones(hint: &[Polynomial]) -> usize {
    let mut count = 0;
    for poly in hint {
        for &coeff in &poly.coeffs {
            if coeff == 1 {
                count += 1;
            }
        }
    }
    count
}

/// Encode the public key
fn encode_public_key(
    rho: &[u8; 32],
    t1: &[Polynomial],
    parameter_set: ParameterSet
) -> Result<Vec<u8>> {
    let k = parameter_set.dimensions().0;
    let d = parameter_set.d();
    
    // Calculate t1 size - coefficients are in [0, (q-1)/2^d]
    let max_value = (8380417 - 1) >> d;
    let bits_per_coeff = bitlen(max_value as u32);
    let t1_size = k * ((256 * bits_per_coeff + 7) / 8);
    
    let mut public_key = Vec::with_capacity(32 + t1_size);
    
    // Add rho
    public_key.extend_from_slice(rho);
    
    // Encode t1
    for i in 0..k {
        let encoded = encode_poly(&t1[i], bits_per_coeff, max_value as u32)?;
        public_key.extend_from_slice(&encoded);
    }
    
    Ok(public_key)
}

/// Encode the private key
fn encode_private_key(
    rho: &[u8; 32],
    key_seed: &[u8; 32],
    tr: &[u8],
    s1: &[Polynomial],
    s2: &[Polynomial],
    t0: &[Polynomial],
    parameter_set: ParameterSet
) -> Result<Vec<u8>> {
    let (k, l) = parameter_set.dimensions();
    let eta = parameter_set.eta();
    let d = parameter_set.d();
    
    // Calculate sizes
    let s_max_value = eta as u32;
    let s_bits_per_coeff = bitlen(2 * s_max_value);
    let s_size = (l + k) * ((256 * s_bits_per_coeff + 7) / 8);
    
    let t0_max_value = (1 << d) - 1;
    let t0_bits_per_coeff = bitlen(t0_max_value);
    let t0_size = k * ((256 * t0_bits_per_coeff + 7) / 8);
    
    let sk_size = 32 + 32 + 64 + s_size + t0_size;
    let mut private_key = Vec::with_capacity(sk_size);
    
    // Add rho, key, tr
    private_key.extend_from_slice(rho);
    private_key.extend_from_slice(key_seed);
    private_key.extend_from_slice(tr);
    
    // Encode s1
    for i in 0..l {
        let encoded = encode_poly_signed(&s1[i], eta, eta)?;
        private_key.extend_from_slice(&encoded);
    }
    
    // Encode s2
    for i in 0..k {
        let encoded = encode_poly_signed(&s2[i], eta, eta)?;
        private_key.extend_from_slice(&encoded);
    }
    
    // Encode t0
    for i in 0..k {
        let encoded = encode_poly(&t0[i], t0_bits_per_coeff, t0_max_value)?;
        private_key.extend_from_slice(&encoded);
    }
    
    Ok(private_key)
}

/// Decode the public key
fn decode_public_key(
    public_key_bytes: &[u8],
    parameter_set: ParameterSet
) -> Result<(Vec<u8>, Vec<Polynomial>)> {
    let (k, _) = parameter_set.dimensions();
    let d = parameter_set.d();
    
    // Extract rho
    if public_key_bytes.len() < 32 {
        return Err(Error::InvalidPublicKey);
    }
    let rho = public_key_bytes[0..32].to_vec();
    
    // Extract t1
    let max_value = (8380417 - 1) >> d;
    let bits_per_coeff = bitlen(max_value as u32);
    let bytes_per_poly = (256 * bits_per_coeff + 7) / 8;
    
    let mut t1 = Vec::with_capacity(k);
    
    for i in 0..k {
        let start = 32 + i * bytes_per_poly;
        let end = start + bytes_per_poly;
        
        if end > public_key_bytes.len() {
            return Err(Error::InvalidPublicKey);
        }
        
        let poly = decode_poly(&public_key_bytes[start..end], bits_per_coeff, max_value as u32)?;
        t1.push(poly);
    }
    
    Ok((rho, t1))
}

/// Decode the private key
fn decode_private_key(
    private_key_bytes: &[u8],
    parameter_set: ParameterSet
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<Polynomial>, Vec<Polynomial>, Vec<Polynomial>)> {
    let (k, l) = parameter_set.dimensions();
    let eta = parameter_set.eta();
    let d = parameter_set.d();
    
    // Extract rho, key, tr
    if private_key_bytes.len() < 32 + 32 + 64 {
        return Err(Error::InvalidPrivateKey);
    }
    
    let rho = private_key_bytes[0..32].to_vec();
    let key = private_key_bytes[32..64].to_vec();
    let tr = private_key_bytes[64..128].to_vec();
    
    // Calculate sizes
    let s_max_value = eta as u32;
    let s_bits_per_coeff = bitlen(2 * s_max_value);
    let s_bytes_per_poly = (256 * s_bits_per_coeff + 7) / 8;
    
    let t0_max_value = (1 << d) - 1;
    let t0_bits_per_coeff = bitlen(t0_max_value);
    let t0_bytes_per_poly = (256 * t0_bits_per_coeff + 7) / 8;
    
    let mut offset = 128;
    
    // Decode s1
    let mut s1 = Vec::with_capacity(l);
    for _ in 0..l {
        if offset + s_bytes_per_poly > private_key_bytes.len() {
            return Err(Error::InvalidPrivateKey);
        }
        
        let poly = decode_poly_signed(&private_key_bytes[offset..offset + s_bytes_per_poly], 
                                     eta, eta)?;
        s1.push(poly);
        offset += s_bytes_per_poly;
    }
    
    // Decode s2
    let mut s2 = Vec::with_capacity(k);
    for _ in 0..k {
        if offset + s_bytes_per_poly > private_key_bytes.len() {
            return Err(Error::InvalidPrivateKey);
        }
        
        let poly = decode_poly_signed(&private_key_bytes[offset..offset + s_bytes_per_poly], 
                                     eta, eta)?;
        s2.push(poly);
        offset += s_bytes_per_poly;
    }
    
    // Decode t0
    let mut t0 = Vec::with_capacity(k);
    for _ in 0..k {
        if offset + t0_bytes_per_poly > private_key_bytes.len() {
            return Err(Error::InvalidPrivateKey);
        }
        
        let poly = decode_poly(&private_key_bytes[offset..offset + t0_bytes_per_poly], 
                              t0_bits_per_coeff, t0_max_value)?;
        t0.push(poly);
        offset += t0_bytes_per_poly;
    }
    
    Ok((rho, key, tr, s1, s2, t0))
}

/// Decode signature
fn decode_signature(
    signature_bytes: &[u8],
    parameter_set: ParameterSet
) -> Result<(Vec<u8>, Vec<Polynomial>, Vec<Polynomial>)> {
    let (k, l) = parameter_set.dimensions();
    let gamma1 = parameter_set.gamma1();
    let lambda = parameter_set.lambda();
    let omega = parameter_set.omega();
    
    // Extract c_tilde
    if signature_bytes.len() < lambda / 4 {
        return Err(Error::InvalidSignature);
    }
    
    let c_tilde = signature_bytes[0..lambda/4].to_vec();
    
    // Extract z
    let z_max_value = gamma1 as u32 - 1;
    let z_bits_per_coeff = bitlen(2 * z_max_value);
    let z_bytes_per_poly = (256 * z_bits_per_coeff + 7) / 8;
    
    let mut offset = lambda / 4;
    let mut z = Vec::with_capacity(l);
    
    for _ in 0..l {
        if offset + z_bytes_per_poly > signature_bytes.len() {
            return Err(Error::InvalidSignature);
        }
        
        let poly = decode_poly_signed(&signature_bytes[offset..offset + z_bytes_per_poly], 
                                     gamma1 - 1, gamma1 - 1)?;
        z.push(poly);
        offset += z_bytes_per_poly;
    }
    
    // Extract hints
    if offset + omega + k > signature_bytes.len() {
        return Err(Error::InvalidSignature);
    }
    
    let hint_bytes = &signature_bytes[offset..offset + omega + k];
    let h = decode_hint(hint_bytes, k, omega)?;
    
    Ok((c_tilde, z, h))
}

/// Decode hint from bytes
fn decode_hint(bytes: &[u8], k: usize, omega: usize) -> Result<Vec<Polynomial>> {
    if bytes.len() < omega + k {
        return Err(Error::InvalidSignature);
    }
    
    // Initialize polynomials with zeros
    let mut h = Vec::with_capacity(k);
    for _ in 0..k {
        h.push(Polynomial::new());
    }
    
    // Extract position bytes and count bytes
    let positions = &bytes[0..omega];
    let counts = &bytes[omega..omega + k];
    
    // Validate that counts sum to at most omega
    let total_count: usize = counts.iter().map(|&c| c as usize).sum();
    if total_count > omega {
        return Err(Error::InvalidSignature);
    }
    
    // Parse hints using counts to determine which positions go with which polynomial
    let mut pos_idx = 0;
    for i in 0..k {
        let count = counts[i] as usize;
        for _ in 0..count {
            if pos_idx >= omega {
                return Err(Error::InvalidSignature);
            }
            
            let pos = positions[pos_idx] as usize;
            if pos >= 256 {
                return Err(Error::InvalidSignature);
            }
            
            h[i].coeffs[pos] = 1;
            pos_idx += 1;
        }
    }
    
    // Ensure remaining positions are 0
    for i in pos_idx..omega {
        if positions[i] != 0 {
            return Err(Error::InvalidSignature);
        }
    }
    
    Ok(h)
}

/// Encode a polynomial with coefficients in [0, bound]
fn encode_poly(poly: &Polynomial, bits: usize, bound: u32) -> Result<Vec<u8>> {
    let mut bits_array = Vec::with_capacity(256 * bits);
    
    for i in 0..256 {
        let coeff = poly.coeffs[i] as u32;
        if coeff > bound {
            return Err(Error::EncodingError(format!("Coefficient out of range: {}", coeff)));
        }
        
        for j in 0..bits {
            bits_array.push(((coeff >> j) & 1) as u8);
        }
    }
    
    let bytes_needed = (bits_array.len() + 7) / 8;
    let mut result = vec![0u8; bytes_needed];
    
    for i in 0..bytes_needed {
        let mut byte = 0u8;
        for j in 0..8 {
            if i * 8 + j < bits_array.len() {
                byte |= bits_array[i * 8 + j] << j;
            }
        }
        result[i] = byte;
    }
    
    Ok(result)
}

/// Decode a polynomial with coefficients in [0, bound]
fn decode_poly(bytes: &[u8], bits: usize, bound: u32) -> Result<Polynomial> {
    let bytes_needed = (256 * bits + 7) / 8;
    if bytes.len() < bytes_needed {
        return Err(Error::EncodingError(format!(
            "Not enough bytes for polynomial: have {}, need {}", bytes.len(), bytes_needed
        )));
    }
    
    let bit_array = bytes_to_bits(&bytes[0..bytes_needed]);
    
    let mut poly = Polynomial::new();
    for i in 0..256 {
        let start = i * bits;
        
        if start + bits > bit_array.len() {
            return Err(Error::EncodingError("Not enough bits for polynomial".to_string()));
        }
        
        let mut coeff = 0u32;
        for j in 0..bits {
            coeff |= (bit_array[start + j] as u32) << j;
        }
        
        if coeff > bound {
            return Err(Error::EncodingError(format!("Decoded coefficient out of range: {}", coeff)));
        }
        
        poly.coeffs[i] = coeff as i32;
    }
    
    Ok(poly)
}

/// Encode a polynomial with coefficients in [-a, b]
fn encode_poly_signed(poly: &Polynomial, a: usize, b: usize) -> Result<Vec<u8>> {
    let bits = bitlen((a + b) as u32);
    let mut bits_array = Vec::with_capacity(256 * bits);
    
    for i in 0..256 {
        let coeff = (poly.coeffs[i] + (a as i32)) as u32;
        if coeff > (a + b) as u32 {
            return Err(Error::EncodingError(format!("Coefficient out of range: {}", coeff)));
        }
        
        for j in 0..bits {
            bits_array.push(((coeff >> j) & 1) as u8);
        }
    }
    
    let bytes_needed = (bits_array.len() + 7) / 8;
    let mut result = vec![0u8; bytes_needed];
    
    for i in 0..bytes_needed {
        let mut byte = 0u8;
        for j in 0..8 {
            if i * 8 + j < bits_array.len() {
                byte |= bits_array[i * 8 + j] << j;
            }
        }
        result[i] = byte;
    }
    
    Ok(result)
}

/// Decode a polynomial with coefficients in [-a, b]
fn decode_poly_signed(bytes: &[u8], a: usize, b: usize) -> Result<Polynomial> {
    let bits = bitlen((a + b) as u32);
    let bytes_needed = (256 * bits + 7) / 8;
    
    if bytes.len() < bytes_needed {
        return Err(Error::EncodingError(format!(
            "Not enough bytes for polynomial: have {}, need {}", bytes.len(), bytes_needed
        )));
    }
    
    let bit_array = bytes_to_bits(&bytes[0..bytes_needed]);
    
    let mut poly = Polynomial::new();
    for i in 0..256 {
        let start = i * bits;
        
        if start + bits > bit_array.len() {
            return Err(Error::EncodingError("Not enough bits for polynomial".to_string()));
        }
        
        let mut coeff = 0u32;
        for j in 0..bits {
            coeff |= (bit_array[start + j] as u32) << j;
        }
        
        if coeff > (a + b) as u32 {
            return Err(Error::EncodingError(format!("Decoded coefficient out of range: {}", coeff)));
        }
        
        poly.coeffs[i] = (coeff as i32) - (a as i32);
    }
    
    Ok(poly)
}

/// Encode a signature
fn encode_signature(
    c_tilde: &[u8],
    z: &[Polynomial],
    h: &[Polynomial],
    parameter_set: ParameterSet
) -> Result<Vec<u8>> {
    let (k, l) = parameter_set.dimensions();
    let gamma1 = parameter_set.gamma1();
    let omega = parameter_set.omega();
    let lambda = parameter_set.lambda();
    
    // Calculate signature size
    let z_bits_per_coeff = bitlen((2 * gamma1 - 2) as u32);
    let z_bytes_per_poly = (256 * z_bits_per_coeff + 7) / 8;
    let z_size = l * z_bytes_per_poly;
    
    // Calculate hint size
    let h_size = omega + k;
    
    let sig_size = lambda / 4 + z_size + h_size;
    let mut signature = Vec::with_capacity(sig_size);
    
    // Add c_tilde
    signature.extend_from_slice(c_tilde);
    
    // Encode z
    for i in 0..l {
        let encoded = encode_poly_signed(&z[i], gamma1 - 1, gamma1 - 1)?;
        signature.extend_from_slice(&encoded);
    }
    
    // Encode hint h
    let encoded_hint = encode_hint(h, omega)?;
    signature.extend_from_slice(&encoded_hint);
    
    Ok(signature)
}

/// Calculate bit length of an integer
fn bitlen(n: u32) -> usize {
    if n == 0 { 
        return 0; 
    }
    
    (32 - n.leading_zeros()) as usize
}