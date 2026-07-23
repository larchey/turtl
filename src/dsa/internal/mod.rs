//! Internal implementation details for ML-DSA.
//!
//! This module contains the core algorithms used for ML-DSA key generation,
//! signing, and verification as specified in NIST FIPS 204.

use crate::common::ntt::NTTType;
use crate::common::{hash, ntt::NTTContext, poly::Polynomial};
use crate::dsa::{HashFunction, ParameterSet, PrivateKey, PublicKey};
use crate::error::{Error, Result};

/// Generate a keypair from a seed.
pub(crate) fn seed_to_keypair(
    seed: &[u8; 32],
    parameter_set: ParameterSet,
) -> Result<super::KeyPair> {
    // Call the internal key generation function
    let (public_key_bytes, private_key_bytes) = ml_dsa_keygen_internal(seed, parameter_set)?;

    // Create public and private key objects
    let public_key = PublicKey::new(public_key_bytes, parameter_set)?;
    let private_key = PrivateKey::new(private_key_bytes, parameter_set)?;

    // Return the key pair
    super::KeyPair::from_keys(public_key, private_key)
}

/// Implement ML-DSA key generation from seed
pub(crate) fn ml_dsa_keygen_internal(
    seed: &[u8; 32],
    parameter_set: ParameterSet,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Implementation of ML-DSA.KeyGen_internal from FIPS 204

    // Get parameter values
    let (k, l) = parameter_set.dimensions();
    let eta = parameter_set.eta();
    let d = parameter_set.d();

    // 1. Expand the seed to get rho, sigma, and K
    let domain_bytes = [k as u8, l as u8];
    let mut data = Vec::with_capacity(seed.len() + domain_bytes.len());
    data.extend_from_slice(seed);
    data.extend_from_slice(&domain_bytes);
    let expanded = hash::h_function(&data, 128);

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
    parameter_set: ParameterSet,
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
    let mut rho_data = Vec::new();
    rho_data.extend_from_slice(&key);
    rho_data.extend_from_slice(rnd);
    rho_data.extend_from_slice(&mu);
    let rho_prime = hash::h_function(&rho_data, 64);

    // Initialize counter
    let mut kappa = 0u16;

    // Set a maximum number of attempts to prevent infinite loops
    const MAX_ATTEMPTS: u16 = 1000;

    // Loop until a valid signature is found or max attempts reached
    while kappa < MAX_ATTEMPTS {
        // Generate y (in centered representation [-gamma1+1, gamma1-1])
        let y = expand_mask(&rho_prime, kappa, l, gamma1)?;

        // For w = Ay, we need y in [0, q-1] representation for NTT
        let mut y_reduced = y.clone();
        for i in 0..l {
            y_reduced[i].reduce_modulo(ntt_ctx.modulus);
        }

        // Compute w = Ay using reduced y
        let w = compute_w(&matrix_a, &y_reduced, &ntt_ctx)?;

        // Decompose w and compute w1
        let mut w1 = Vec::with_capacity(k);
        let mut w0 = Vec::with_capacity(k);

        for i in 0..k {
            let (w1_i, w0_i) = decompose(&w[i], gamma2)?;
            w1.push(w1_i);
            w0.push(w0_i);
        }

        // Compute c = H(mu || w1)
        let w1_encoded = encode_w1(&w1, gamma2)?;

        let mut c_data = Vec::new();
        c_data.extend_from_slice(&mu);
        c_data.extend_from_slice(&w1_encoded);
        let c_tilde = hash::h_function(&c_data, parameter_set.lambda() / 4);

        // Sample c from challenge space
        let c = sample_in_ball(&c_tilde, tau)?;

        // Convert c to NTT domain
        let mut c_hat = c.clone();
        ntt_ctx.forward(&mut c_hat)?;

        // Compute z = y + c*s1 using centered arithmetic
        let mut z = Vec::with_capacity(l);
        for i in 0..l {
            // Compute c*s1 in NTT domain
            let mut cs1_i = ntt_ctx.multiply_ntt(&c_hat, &s1_hat[i])?;
            ntt_ctx.inverse(&mut cs1_i)?;

            // Convert to centered representation
            cs1_i.to_centered_representation(ntt_ctx.modulus);

            // Add y (already centered) + cs1 (now centered) using regular addition
            let mut z_i = Polynomial::new();
            for j in 0..256 {
                z_i.coeffs[j] = y[i].coeffs[j] + cs1_i.coeffs[j];
            }
            // Reduce to [0, q-1] for subsequent operations
            z_i.reduce_modulo(ntt_ctx.modulus);
            z.push(z_i);
        }

        // Check if z is small enough (using centered norm)
        let mut z_ok = true;
        let mut max_z_norm = 0;
        for i in 0..l {
            let norm = z[i].infinity_norm_centered(ntt_ctx.modulus);
            if norm > max_z_norm {
                max_z_norm = norm;
            }
            if norm >= (gamma1 - beta) as i32 {
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

        // Check if r0 is small enough (using centered norm)
        let mut r0_ok = true;
        for i in 0..k {
            if r0[i].infinity_norm_centered(ntt_ctx.modulus) >= (gamma2 - beta) as i32 {
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

        // Convert z to centered representation for encoding
        let mut z_centered = z.clone();
        for i in 0..l {
            z_centered[i].to_centered_representation(ntt_ctx.modulus);
        }

        // Encode the signature
        return encode_signature(&c_tilde, &z_centered, &h, parameter_set);
    }

    // Exhausted the attempt budget without producing a valid signature.
    Err(Error::RandomnessError)
}

/// Internal function for ML-DSA verification
pub(crate) fn ml_dsa_verify_internal(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
    parameter_set: ParameterSet,
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
    let omega = parameter_set.omega();

    // Verify c_tilde length
    if c_tilde.len() != parameter_set.lambda() / 4 {
        return Err(Error::InvalidSignature);
    }

    // Check if z is small enough using explicit bounds checking
    use crate::security::fault_detection;
    for i in 0..l {
        let norm = z[i].infinity_norm();

        // Verify bounds for z values
        fault_detection::verify_bounds(norm as usize, 0, gamma1 - beta - 1)
            .map_err(|_| Error::InvalidSignature)?;

        if norm >= (gamma1 - beta) as i32 {
            return Ok(false);
        }
    }

    // Validate that the hint vector has at most omega ones
    let hint_ones = count_ones(&h);

    // Additional bounds checking for hint
    fault_detection::verify_bounds(hint_ones, 0, omega).map_err(|_| Error::InvalidSignature)?;

    if hint_ones > omega {
        return Err(Error::InvalidSignature);
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

    // Compute Az (z must be in [0, q-1] representation for NTT)
    let mut z_reduced = z.clone();
    for i in 0..l {
        z_reduced[i].reduce_modulo(ntt_ctx.modulus);
    }
    let az = compute_w(&matrix_a, &z_reduced, &ntt_ctx)?;

    // Compute c*t1*2^d
    // FIPS 204 Algorithm 2, Line 7: w' ← NTT^{-1}(A ◦ NTT(z) - c_hat ◦ NTT(t1·2^d))
    // Must compute t1*2^d FIRST, then multiply by c in NTT domain
    let mut ct1 = Vec::with_capacity(k);
    let d = parameter_set.d();

    for i in 0..k {
        // Step 1: Compute t1*2^d in coefficient domain
        let mut t1_2d = Polynomial::new();
        for j in 0..256 {
            // Multiply by 2^d (left shift)
            t1_2d.coeffs[j] = t1[i].coeffs[j] << d;
        }

        // Step 2: Reduce modulo q (coefficients should be in [0, q-1])
        t1_2d.reduce_modulo(ntt_ctx.modulus);

        // Step 3: Transform to NTT domain
        ntt_ctx.forward(&mut t1_2d)?;

        // Step 4: Multiply by c in NTT domain (c_hat ◦ NTT(t1·2^d))
        let mut ct1_i = ntt_ctx.multiply_ntt(&c_hat, &t1_2d)?;

        // Step 5: Transform back to coefficient domain
        ntt_ctx.inverse(&mut ct1_i)?;

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
    let w1_encoded = encode_w1(&w1, gamma2)?;

    // Compute c' = H(mu || w1)
    let mut c_prime_data = Vec::new();
    c_prime_data.extend_from_slice(&mu);
    c_prime_data.extend_from_slice(&w1_encoded);
    let c_prime = hash::h_function(&c_prime_data, parameter_set.lambda() / 4);

    // Compare c_tilde and c_prime
    Ok(c_tilde == c_prime)
}

/// Internal function for ML-DSA hash-then-sign
pub(crate) fn ml_dsa_hash_sign_internal(
    private_key_bytes: &[u8],
    message: &[u8],
    context: &[u8],
    hash_function: HashFunction,
    rnd: &[u8; 32],
    parameter_set: ParameterSet,
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
    parameter_set: ParameterSet,
) -> Result<bool> {
    // Validate input parameters
    if context.len() > 255 {
        return Err(Error::ContextTooLong);
    }

    if public_key_bytes.len() != parameter_set.public_key_size() {
        return Err(Error::InvalidPublicKey);
    }

    if signature_bytes.len() < parameter_set.lambda() / 4 {
        return Err(Error::InvalidSignature);
    }

    // Format with domain separator 1 (for pre-hash)
    let domain_separator = 1u8;

    // Create context header
    let mut ctx_header = Vec::with_capacity(2 + context.len());
    ctx_header.push(domain_separator);
    ctx_header.push(context.len() as u8);
    ctx_header.extend_from_slice(context);

    // Get OID for hash function
    let oid = get_hash_function_oid(hash_function);

    // Compute hash of message using the specified hash function
    let message_hash = match hash_function {
        HashFunction::SHA3_256 => hash::sha3_256(message).to_vec(),
        HashFunction::SHA3_512 => hash::sha3_512(message).to_vec(),
        HashFunction::SHAKE128 => hash::shake128(message, 32),
        HashFunction::SHAKE256 => hash::shake256(message, 32),
    };

    // Verify the hash output is of the expected length
    let expected_hash_length = match hash_function {
        HashFunction::SHA3_256 => 32,
        HashFunction::SHA3_512 => 64,
        HashFunction::SHAKE128 => 32,
        HashFunction::SHAKE256 => 32,
    };

    if message_hash.len() != expected_hash_length {
        return Err(Error::RandomnessError);
    }

    // Create pre-hashed message
    let mut pre_hashed = Vec::with_capacity(ctx_header.len() + oid.len() + message_hash.len());
    pre_hashed.extend_from_slice(&ctx_header);
    pre_hashed.extend_from_slice(&oid);
    pre_hashed.extend_from_slice(&message_hash);

    // Call internal verification function
    ml_dsa_verify_internal(
        public_key_bytes,
        &pre_hashed,
        signature_bytes,
        parameter_set,
    )
}

// Utility functions

/// Get OID for hash function in DER encoding
fn get_hash_function_oid(hash_function: HashFunction) -> Vec<u8> {
    match hash_function {
        HashFunction::SHA3_256 => vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ],
        HashFunction::SHA3_512 => vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        ],
        HashFunction::SHAKE128 => vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B,
        ],
        HashFunction::SHAKE256 => vec![
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C,
        ],
    }
}

/// Generate matrix A from seed
fn expand_a(rho: &[u8], k: usize, l: usize) -> Result<Vec<Vec<Polynomial>>> {
    let mut matrix_a = Vec::with_capacity(k);
    let ntt_ctx = NTTContext::new(NTTType::MLDSA);

    for i in 0..k {
        let mut row = Vec::with_capacity(l);
        for j in 0..l {
            let mut seed = Vec::with_capacity(rho.len() + 2);
            seed.extend_from_slice(rho);
            seed.push(j as u8);
            seed.push(i as u8);
            let a_ij = reject_sample_ntt(&seed, &ntt_ctx)?;
            row.push(a_ij);
        }
        matrix_a.push(row);
    }

    Ok(matrix_a)
}

/// Rejection sampling of a uniform NTT-domain polynomial (FIPS 204 RejNTTPoly).
///
/// ML-DSA coefficients are ~23 bits (q = 8380417), so each candidate is built
/// from 3 bytes via CoeffFromThreeBytes (mask the top bit, reject if >= q).
fn reject_sample_ntt(seed: &[u8], ntt_ctx: &NTTContext) -> Result<Polynomial> {
    let mut poly = Polynomial::new();
    let mut j = 0;

    let mut ctx = hash::SHAKE128Context::init();
    ctx.absorb(seed);

    // Generous cap so an adversarial/degenerate seed cannot hang the process.
    let mut iterations = 0;
    while j < 256 {
        if iterations >= 10_000 {
            return Err(Error::RandomnessError);
        }
        iterations += 1;

        let bytes = ctx.squeeze(3);

        // CoeffFromThreeBytes: 23-bit little-endian value (top bit of b2 cleared)
        let coeff =
            (bytes[0] as u32) | ((bytes[1] as u32) << 8) | (((bytes[2] as u32) & 0x7F) << 16);

        // Reject values that are not in [0, q-1]
        if (coeff as i32) < ntt_ctx.modulus {
            poly.coeffs[j] = coeff as i32;
            j += 1;
        }
    }

    // Already in NTT domain
    Ok(poly)
}

/// Sample secret vectors s1 and s2
fn expand_s(
    sigma: &[u8],
    l: usize,
    k: usize,
    eta: usize,
) -> Result<(Vec<Polynomial>, Vec<Polynomial>)> {
    let mut s1 = Vec::with_capacity(l);
    let mut s2 = Vec::with_capacity(k);

    // FIPS 204 ExpandS: nonce is a 2-byte little-endian integer; s1 uses
    // nonces 0..l and s2 uses nonces l..l+k.
    for i in 0..l {
        let seed = [sigma, &(i as u16).to_le_bytes()].concat();
        s1.push(sample_bounded_poly(&seed, eta)?);
    }
    for i in 0..k {
        let seed = [sigma, &((l + i) as u16).to_le_bytes()].concat();
        s2.push(sample_bounded_poly(&seed, eta)?);
    }

    Ok((s1, s2))
}

/// Map a half-byte to a coefficient in [-eta, eta] (FIPS 204 CoeffFromHalfByte).
///
/// Returns None when the value must be rejected.
fn coeff_from_half_byte(b: u8, eta: usize) -> Option<i32> {
    match eta {
        2 if b < 15 => Some(2 - (b as i32 % 5)),
        4 if b < 9 => Some(4 - b as i32),
        _ => None,
    }
}

/// Sample a polynomial with coefficients in [-eta, eta] (FIPS 204 RejBoundedPoly).
fn sample_bounded_poly(seed: &[u8], eta: usize) -> Result<Polynomial> {
    let mut poly = Polynomial::new();

    let mut ctx = hash::SHAKE256Context::init();
    ctx.absorb(seed);

    let mut j = 0;
    let mut iterations = 0;
    while j < 256 {
        if iterations >= 10_000 {
            return Err(Error::RandomnessError);
        }
        iterations += 1;

        let byte = ctx.squeeze(1)[0];

        // Low nibble first, then high nibble.
        if let Some(c) = coeff_from_half_byte(byte & 0x0F, eta) {
            poly.coeffs[j] = c;
            j += 1;
        }
        if j < 256 {
            if let Some(c) = coeff_from_half_byte(byte >> 4, eta) {
                poly.coeffs[j] = c;
                j += 1;
            }
        }
    }

    Ok(poly)
}

/// Compute t = As1 + s2
fn compute_public_t(
    matrix_a: &[Vec<Polynomial>],
    s1: &[Polynomial],
    s2: &[Polynomial],
    ntt_ctx: &NTTContext,
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
            let prod = ntt_ctx.multiply_ntt(&matrix_a[i][j], &s1_hat[j])?;
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

    let q: i32 = 8380417;
    let two_d = 1i32 << d;
    for i in 0..k {
        let mut t1_i = Polynomial::new();
        let mut t0_i = Polynomial::new();

        for j in 0..256 {
            // FIPS 204 Power2Round: r0 is the centered remainder mod 2^d, so
            // t1 = round(r / 2^d) rather than floor.
            let r = t[i].coeffs[j].rem_euclid(q);
            let mut r0 = r & (two_d - 1);
            if r0 > two_d / 2 {
                r0 -= two_d;
            }
            t1_i.coeffs[j] = (r - r0) >> d;
            t0_i.coeffs[j] = r0;
        }

        t1.push(t1_i);
        t0.push(t0_i);
    }

    Ok((t1, t0))
}

/// Sample a polynomial with exactly tau +/-1 coefficients (FIPS 204 Algorithm 29).
///
/// The first 8 squeezed bytes provide 64 sign bits; positions are then chosen by
/// rejection sampling one byte at a time (j <= i), giving a byte-exact, unbiased
/// mapping from c_tilde to the challenge polynomial.
fn sample_in_ball(seed: &[u8], tau: usize) -> Result<Polynomial> {
    use crate::security::fault_detection;
    let mut poly = Polynomial::new();

    // FIPS 204 uses tau <= 64 (fits within the 64 sign bits).
    fault_detection::verify_bounds(tau, 1, 64).map_err(|_| Error::RandomnessError)?;

    let mut ctx = hash::SHAKE256Context::init();
    ctx.absorb(seed);

    // First 8 bytes = 64 sign bits, consumed LSB-first as they are used.
    let sign_bytes = ctx.squeeze(8);
    let signs = u64::from_le_bytes(sign_bytes.as_slice().try_into().unwrap());

    for (sign_idx, i) in ((256 - tau)..256).enumerate() {
        // Rejection-sample j in [0, i] one byte at a time.
        let j = loop {
            let b = ctx.squeeze(1)[0] as usize;
            if b <= i {
                break b;
            }
        };

        poly.coeffs[i] = poly.coeffs[j];
        poly.coeffs[j] = if (signs >> sign_idx) & 1 == 1 { -1 } else { 1 };
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
    let bytes_per_coeff = bits_needed.div_ceil(8);

    for i in 0..256 {
        let mut valid_coeff = false;
        let mut iterations = 0;

        while !valid_coeff {
            if iterations >= 10_000 {
                return Err(Error::RandomnessError);
            }
            iterations += 1;

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
    ntt_ctx: &NTTContext,
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
            let prod = ntt_ctx.multiply_ntt(&matrix_a[i][j], &z_hat[j])?;
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

/// Decompose a single coefficient per FIPS 204 Algorithm 37.
///
/// Decomposes r into (r1, r0) such that r ≡ r1 * (2*alpha) + r0 (mod q),
/// where r0 is in the centered range (-alpha, alpha].
///
/// Includes the FIPS 204 special case: when r - r0 = q - 1, sets r1 = 0
/// and r0 = r0 - 1 to keep r1 in the valid range [0, (q-1)/(2*alpha) - 1].
fn decompose_coefficient(r: i32, alpha: usize) -> (i32, i32) {
    let q: i64 = 8380417;
    let two_alpha = (alpha as i64) * 2;

    // Ensure r is in [0, q-1]
    let r_plus = ((r as i64 % q) + q) % q;

    // Compute centered remainder: r0 = r mod± (2*alpha)
    // Result in (-alpha, alpha] per FIPS 204 Section 2.4
    let mut r0 = r_plus % two_alpha;
    if r0 > alpha as i64 {
        r0 -= two_alpha;
    }

    // FIPS 204 special case: when r - r0 = q - 1, wrap r1 to 0
    if r_plus - r0 == q - 1 {
        return (0, (r0 - 1) as i32);
    }

    let r1 = ((r_plus - r0) / two_alpha) as i32;
    (r1, r0 as i32)
}

/// Make hint for high bits
/// Implements MakeHint from FIPS 204 Algorithm 39
/// Called as MakeHint(z=-ct₀, r=w-cs₂+ct₀, α=2γ₂)
/// Returns 1 if HighBits(r, α) ≠ HighBits(r + z, α)
fn make_hint(w_prime: &Polynomial, ct0: &Polynomial, gamma2: usize) -> Result<Polynomial> {
    let mut h = Polynomial::new();
    let q = 8380417; // ML-DSA modulus

    for i in 0..256 {
        // FIPS 204: MakeHint(z, r, α) checks if HighBits(r) ≠ HighBits(r + z)
        // where: z = -ct₀, r = w - cs₂ + ct₀
        // So: r + z = (w - cs₂ + ct₀) + (-ct₀) = w - cs₂
        //
        // Since we're passed ct₀ (not -ct₀), we compute:
        // r + z = w_prime + (-ct0) = w_prime - ct0
        let diff = w_prime.coeffs[i] as i64 - ct0.coeffs[i] as i64;
        let r_plus_z = ((diff % q as i64) + q as i64) as i32 % q;

        // Decompose r and r + z to get high bits
        let (r1, _) = decompose_coefficient(w_prime.coeffs[i], gamma2);
        let (v1, _) = decompose_coefficient(r_plus_z, gamma2);

        // Set hint to 1 if high bits differ
        h.coeffs[i] = if r1 != v1 { 1 } else { 0 };
    }

    Ok(h)
}

/// Use hint to recover high bits
fn use_hint(h: &Polynomial, r: &Polynomial, gamma2: usize) -> Result<Polynomial> {
    let mut w1 = Polynomial::new();
    let q = 8380417; // ML-DSA modulus (q)
    let mod_value = (q - 1) / (2 * gamma2 as i32);

    for i in 0..256 {
        // Decompose coefficient
        let (r1, r0) = decompose_coefficient(r.coeffs[i], gamma2);

        // Use hint to adjust high bits
        if h.coeffs[i] == 1 {
            // Safe computation of d
            let d = if r0 > 0 { 1 } else { -1 };

            // Safe computation of r1 + d with overflow checking
            let adjusted = match r1.checked_add(d) {
                Some(val) => val,
                None => {
                    // If we'd overflow, saturate to max/min value
                    if d > 0 {
                        i32::MAX
                    } else {
                        i32::MIN
                    }
                }
            };

            // Safe modulo with overflow checking
            w1.coeffs[i] = ((adjusted % mod_value) + mod_value) % mod_value;
        } else {
            // FIPS 204 Algorithm 40 line 6: return r1 mod m (not just r1!)
            // This ensures w1 is always in the correct range [0, m-1]
            w1.coeffs[i] = ((r1 % mod_value) + mod_value) % mod_value;
        }
    }

    Ok(w1)
}

/// Encode the w1 component for challenge hash
fn encode_w1(w1: &[Polynomial], gamma2: usize) -> Result<Vec<u8>> {
    let k = w1.len();
    let q = 8380417; // ML-DSA modulus

    // FIPS 204 Algorithm 23: w1Encode
    // Compute m = (q-1)/(2*gamma2) and use bitlen(m-1) bits per coefficient
    let m = (q - 1) / (2 * gamma2 as i32);
    let bits_per_coeff = bitlen((m - 1) as u32);

    // Calculate number of bytes needed per polynomial
    let bytes_per_poly = (256_usize * bits_per_coeff).div_ceil(8);
    let mut result = Vec::with_capacity(k * bytes_per_poly);

    for i in 0..k {
        // Convert polynomial coefficients to bits
        let mut bits = Vec::with_capacity(256 * bits_per_coeff);

        for j in 0..256 {
            // Get the coefficient as a non-negative value
            let coeff_raw = w1[i].coeffs[j];

            // According to FIPS 204, w1 coefficients should always be non-negative
            // They are in the range [0, m-1] where m = (q-1)/(2*gamma2)
            if coeff_raw < 0 {
                return Err(Error::EncodingError(format!(
                    "w1 coefficient must be non-negative, got: {}",
                    coeff_raw
                )));
            }

            let coeff = coeff_raw as u32;
            let max_coeff = (1 << bits_per_coeff) - 1;

            // Check if coefficient is too large
            if coeff > max_coeff {
                return Err(Error::EncodingError(format!(
                    "Coefficient out of range for w1 encoding: {} (max {})",
                    coeff, max_coeff
                )));
            }

            // Store coefficient in bits_per_coeff bits
            for b in 0..bits_per_coeff {
                bits.push(((coeff >> b) & 1) as u8);
            }
        }

        // Pack bits into bytes
        for b in 0..bits.len().div_ceil(8) {
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

/// Encode hint for ML-DSA (FIPS 204 Algorithm 20, HintBitPack).
///
/// Layout: omega position bytes (hint positions, per-polynomial in ascending
/// order) followed by k bytes holding the *cumulative* count of ones through
/// each polynomial.
fn encode_hint(h: &[Polynomial], omega: usize) -> Result<Vec<u8>> {
    let k = h.len();
    let mut result = vec![0u8; omega + k];

    let mut index = 0usize;
    for i in 0..k {
        for j in 0..256 {
            if h[i].coeffs[j] == 1 {
                if index >= omega {
                    return Err(Error::EncodingError(format!(
                        "Too many ones in hint, maximum allowed: {}",
                        omega
                    )));
                }
                result[index] = j as u8;
                index += 1;
            }
        }
        // Cumulative count of ones through polynomial i
        result[omega + i] = index as u8;
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
    parameter_set: ParameterSet,
) -> Result<Vec<u8>> {
    let k = parameter_set.dimensions().0;
    let d = parameter_set.d();

    // Calculate t1 size - coefficients are in [0, (q-1)/2^d]
    let max_value = (8380417 - 1) >> d;
    let bits_per_coeff = bitlen(max_value as u32);

    let mut public_key = Vec::with_capacity(parameter_set.public_key_size());

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
    parameter_set: ParameterSet,
) -> Result<Vec<u8>> {
    let (k, l) = parameter_set.dimensions();
    let eta = parameter_set.eta();
    let d = parameter_set.d();

    // FIPS 204 packs t0 as a signed value in [-(2^(d-1)-1), 2^(d-1)].
    let t0_a = (1usize << (d - 1)) - 1;
    let t0_b = 1usize << (d - 1);

    let mut private_key = Vec::with_capacity(parameter_set.private_key_size());

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
        let encoded = encode_poly_signed(&t0[i], t0_a, t0_b)?;
        private_key.extend_from_slice(&encoded);
    }

    Ok(private_key)
}

/// Decode the public key
fn decode_public_key(
    public_key_bytes: &[u8],
    parameter_set: ParameterSet,
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
    let bytes_per_poly = (256_usize * bits_per_coeff).div_ceil(8);

    // Check if we have enough bytes for the t1 polynomials
    if public_key_bytes.len() < 32 + k * bytes_per_poly {
        return Err(Error::InvalidPublicKey);
    }

    let mut t1 = Vec::with_capacity(k);

    for i in 0..k {
        let start = 32 + i * bytes_per_poly;
        let end = start + bytes_per_poly;

        if end > public_key_bytes.len() {
            return Err(Error::InvalidPublicKey);
        }

        let poly = decode_poly(
            &public_key_bytes[start..end],
            bits_per_coeff,
            max_value as u32,
        )?;
        t1.push(poly);
    }

    Ok((rho, t1))
}

/// Decode the private key
fn decode_private_key(
    private_key_bytes: &[u8],
    parameter_set: ParameterSet,
) -> Result<(
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<Polynomial>,
    Vec<Polynomial>,
    Vec<Polynomial>,
)> {
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
    let _s_bits_per_coeff = bitlen(2 * s_max_value);
    let s_bytes_per_poly = (256 * _s_bits_per_coeff).div_ceil(8);

    // t0 is packed as a signed value in [-(2^(d-1)-1), 2^(d-1)] using d bits.
    let t0_a = (1usize << (d - 1)) - 1;
    let t0_b = 1usize << (d - 1);
    let t0_bytes_per_poly = (256 * d).div_ceil(8);

    // Check if private key has enough bytes
    let required_size = 128 + // rho + key + tr
                       (l * s_bytes_per_poly) + // s1
                       (k * s_bytes_per_poly) + // s2
                       (k * t0_bytes_per_poly); // t0

    if private_key_bytes.len() < required_size {
        return Err(Error::InvalidPrivateKey);
    }

    let mut offset = 128;

    // Decode s1
    let mut s1 = Vec::with_capacity(l);
    for _ in 0..l {
        if offset + s_bytes_per_poly > private_key_bytes.len() {
            return Err(Error::InvalidPrivateKey);
        }

        let poly = decode_poly_signed(
            &private_key_bytes[offset..offset + s_bytes_per_poly],
            eta,
            eta,
        )?;
        s1.push(poly);
        offset += s_bytes_per_poly;
    }

    // Decode s2
    let mut s2 = Vec::with_capacity(k);
    for _ in 0..k {
        if offset + s_bytes_per_poly > private_key_bytes.len() {
            return Err(Error::InvalidPrivateKey);
        }

        let poly = decode_poly_signed(
            &private_key_bytes[offset..offset + s_bytes_per_poly],
            eta,
            eta,
        )?;
        s2.push(poly);
        offset += s_bytes_per_poly;
    }

    // Decode t0
    let mut t0 = Vec::with_capacity(k);
    for _ in 0..k {
        if offset + t0_bytes_per_poly > private_key_bytes.len() {
            return Err(Error::InvalidPrivateKey);
        }

        let poly = decode_poly_signed(
            &private_key_bytes[offset..offset + t0_bytes_per_poly],
            t0_a,
            t0_b,
        )?;
        t0.push(poly);
        offset += t0_bytes_per_poly;
    }

    Ok((rho, key, tr, s1, s2, t0))
}

/// Decode signature
fn decode_signature(
    signature_bytes: &[u8],
    parameter_set: ParameterSet,
) -> Result<(Vec<u8>, Vec<Polynomial>, Vec<Polynomial>)> {
    let (k, l) = parameter_set.dimensions();
    let gamma1 = parameter_set.gamma1();
    let lambda = parameter_set.lambda();
    let omega = parameter_set.omega();

    // Extract c_tilde
    if signature_bytes.len() < lambda / 4 {
        return Err(Error::InvalidSignature);
    }

    let c_tilde = signature_bytes[0..lambda / 4].to_vec();

    // Extract z
    let z_max_value = gamma1 as u32 - 1;
    let z_bits_per_coeff = bitlen(2 * z_max_value);
    let z_bytes_per_poly = (256 * z_bits_per_coeff).div_ceil(8);

    // Calculate the required signature size
    let required_size = lambda / 4 + (l * z_bytes_per_poly) + omega + k;

    if signature_bytes.len() < required_size {
        return Err(Error::InvalidSignature);
    }

    let mut offset = lambda / 4;
    let mut z = Vec::with_capacity(l);

    for _ in 0..l {
        if offset + z_bytes_per_poly > signature_bytes.len() {
            return Err(Error::InvalidSignature);
        }

        let poly = decode_poly_signed(
            &signature_bytes[offset..offset + z_bytes_per_poly],
            gamma1 - 1,
            gamma1,
        )?;
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

    // Position bytes, then k cumulative-count bytes (FIPS 204 HintBitUnpack)
    let positions = &bytes[0..omega];
    let counts = &bytes[omega..omega + k];

    let mut index = 0usize;
    for i in 0..k {
        let end = counts[i] as usize;
        // Cumulative counts must be non-decreasing and bounded by omega
        if end < index || end > omega {
            return Err(Error::InvalidSignature);
        }

        let first = index;
        while index < end {
            // Positions within a polynomial must be strictly increasing
            if index > first && positions[index - 1] >= positions[index] {
                return Err(Error::InvalidSignature);
            }
            h[i].coeffs[positions[index] as usize] = 1;
            index += 1;
        }
    }

    // All remaining (unused) position bytes must be zero
    for &p in &positions[index..omega] {
        if p != 0 {
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
            return Err(Error::EncodingError(format!(
                "Coefficient out of range: {}",
                coeff
            )));
        }

        for j in 0..bits {
            bits_array.push(((coeff >> j) & 1) as u8);
        }
    }

    let bytes_needed = bits_array.len().div_ceil(8);
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
    let bytes_needed = (256 * bits).div_ceil(8);
    if bytes.len() < bytes_needed {
        return Err(Error::EncodingError(format!(
            "Not enough bytes for polynomial: have {}, need {}",
            bytes.len(),
            bytes_needed
        )));
    }

    let bit_array = bytes_to_bits(&bytes[0..bytes_needed]);

    let mut poly = Polynomial::new();
    for i in 0..256 {
        let start = i * bits;

        if start + bits > bit_array.len() {
            return Err(Error::EncodingError(
                "Not enough bits for polynomial".to_string(),
            ));
        }

        let mut coeff = 0u32;
        for j in 0..bits {
            coeff |= (bit_array[start + j] as u32) << j;
        }

        if coeff > bound {
            return Err(Error::EncodingError(format!(
                "Decoded coefficient out of range: {}",
                coeff
            )));
        }

        poly.coeffs[i] = coeff as i32;
    }

    Ok(poly)
}

/// Encode a polynomial with coefficients in [-a, b] using FIPS 204 BitPack.
///
/// BitPack(w, a, b) stores (b - w_i) in bitlen(a+b) bits per coefficient.
fn encode_poly_signed(poly: &Polynomial, a: usize, b: usize) -> Result<Vec<u8>> {
    let bits = bitlen((a + b) as u32);
    let mut bits_array = Vec::with_capacity(256 * bits);

    for i in 0..256 {
        // FIPS 204 BitPack stores b - w_i, which lies in [0, a+b] for w in [-a, b].
        let coeff = (b as i32) - poly.coeffs[i];

        if coeff < 0 || coeff > (a + b) as i32 {
            return Err(Error::EncodingError(format!(
                "Coefficient out of range for BitPack: {}",
                poly.coeffs[i]
            )));
        }

        let coeff_u32 = coeff as u32;

        // Encode each bit of the coefficient (LSB first)
        for j in 0..bits {
            bits_array.push(((coeff_u32 >> j) & 1) as u8);
        }
    }

    let bytes_needed = bits_array.len().div_ceil(8);
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
    let bytes_needed = (256 * bits).div_ceil(8);

    if bytes.len() < bytes_needed {
        return Err(Error::EncodingError(format!(
            "Not enough bytes for polynomial: have {}, need {}",
            bytes.len(),
            bytes_needed
        )));
    }

    let bit_array = bytes_to_bits(&bytes[0..bytes_needed]);

    let mut poly = Polynomial::new();
    for i in 0..256 {
        let start = i * bits;

        if start + bits > bit_array.len() {
            return Err(Error::EncodingError(
                "Not enough bits for polynomial".to_string(),
            ));
        }

        let mut coeff = 0u32;
        for j in 0..bits {
            coeff |= (bit_array[start + j] as u32) << j;
        }

        if coeff > (a + b) as u32 {
            return Err(Error::EncodingError(format!(
                "Decoded coefficient out of range: {}",
                coeff
            )));
        }

        // FIPS 204 BitUnpack: w_i = b - (stored value)
        poly.coeffs[i] = (b as i32) - (coeff as i32);
    }

    Ok(poly)
}

/// Encode a signature
fn encode_signature(
    c_tilde: &[u8],
    z: &[Polynomial],
    h: &[Polynomial],
    parameter_set: ParameterSet,
) -> Result<Vec<u8>> {
    let (_k, l) = parameter_set.dimensions();
    let gamma1 = parameter_set.gamma1();
    let omega = parameter_set.omega();

    let mut signature = Vec::with_capacity(parameter_set.signature_size());

    // Add c_tilde
    signature.extend_from_slice(c_tilde);

    // Encode z
    for i in 0..l {
        let encoded = encode_poly_signed(&z[i], gamma1 - 1, gamma1)?;
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

#[cfg(test)]
mod sib_tests {
    use super::*;
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    // Inline FIPS 204 Algorithm 29 reference for cross-checking.
    fn ref_sample_in_ball(seed: &[u8], tau: usize) -> [i32; 256] {
        let mut c = [0i32; 256];
        let mut x = sha3::Shake256::default();
        x.update(seed);
        let mut r = x.finalize_xof();
        let mut s8 = [0u8; 8];
        r.read(&mut s8);
        let signs = u64::from_le_bytes(s8);
        for (si, i) in ((256 - tau)..256).enumerate() {
            let j = loop {
                let mut b = [0u8; 1];
                r.read(&mut b);
                if (b[0] as usize) <= i {
                    break b[0] as usize;
                }
            };
            c[i] = c[j];
            c[j] = if (signs >> si) & 1 == 1 { -1 } else { 1 };
        }
        c
    }

    #[test]
    fn sample_in_ball_matches_fips() {
        for (seed_byte, tau) in [(1u8, 39usize), (2, 49), (3, 60), (200, 39)] {
            let seed = [seed_byte; 32];
            let got = sample_in_ball(&seed, tau).unwrap();
            let expected = ref_sample_in_ball(&seed, tau);
            assert_eq!(got.coeffs, expected, "mismatch for tau={tau}");
        }
    }
}
