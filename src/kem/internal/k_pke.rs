//! K-PKE component for ML-KEM.
//! 
//! This module implements the K-PKE public-key encryption scheme
//! used as a component within ML-KEM.

use crate::error::{Error, Result};
use crate::kem::ParameterSet;
use crate::common::{ntt::NTTContext, poly::Polynomial, hash, sample::SampleInBall};
use zeroize::Zeroize;

/// Generate the key components for K-PKE
pub(crate) fn generate_key_components(
    rho: &[u8; 32],
    rhoprime: &[u8; 64],
    parameter_set: ParameterSet
) -> Result<(Vec<Vec<Polynomial>>, Vec<Polynomial>, Vec<Polynomial>)> {
    let k = parameter_set.k();
    let eta1 = parameter_set.eta1();
    
    // Create NTT context
    let ntt_ctx = NTTContext::new();
    
    // Generate matrix A
    let mut matrix_a = Vec::with_capacity(k);
    for i in 0..k {
        let mut row = Vec::with_capacity(k);
        for j in 0..k {
            let seed = [rho, &[j as u8, i as u8]].concat();
            let a_ij = reject_sample_ntt(&seed, &ntt_ctx)?;
            row.push(a_ij);
        }
        matrix_a.push(row);
    }
    
    // Generate vectors s1 and s2
    let mut s1 = Vec::with_capacity(k);
    let mut s2 = Vec::with_capacity(k);
    
    let mut counter = 0u8;
    
    // Sample s1
    for i in 0..k {
        let seed = [rhoprime, &[counter]].concat();
        counter += 1;
        let s1_i = sample_cbd(seed.as_slice(), eta1)?;
        s1.push(s1_i);
    }
    
    // Sample s2
    for i in 0..k {
        let seed = [rhoprime, &[counter]].concat();
        counter += 1;
        let s2_i = sample_cbd(seed.as_slice(), eta1)?;
        s2.push(s2_i);
    }
    
    Ok((matrix_a, s1, s2))
}

/// Compute the public value t = As1 + s2
pub(crate) fn compute_public_t(
    matrix_a: &[Vec<Polynomial>],
    s1: &[Polynomial],
    s2: &[Polynomial]
) -> Result<Vec<Polynomial>> {
    let k = matrix_a.len();
    let ntt_ctx = NTTContext::new();
    
    // NTT transform s1
    let mut s1_ntt = Vec::with_capacity(k);
    for i in 0..k {
        let mut s1_i = s1[i].clone();
        ntt_ctx.forward(&mut s1_i)?;
        s1_ntt.push(s1_i);
    }
    
    // Compute t = As1 + s2
    let mut t = Vec::with_capacity(k);
    for i in 0..k {
        let mut t_i = Polynomial::new();
        
        // Compute the i-th row of A times s1
        for j in 0..k {
            let mut prod = ntt_ctx.multiply_ntt(&matrix_a[i][j], &s1_ntt[j])?;
            t_i.add_assign(&prod, ntt_ctx.modulus);
        }
        
        // Transform back
        ntt_ctx.inverse(&mut t_i)?;
        
        // Add s2[i]
        t_i.add_assign(&s2[i], ntt_ctx.modulus);
        
        t.push(t_i);
    }
    
    Ok(t)
}

/// Power2Round: Split a polynomial vector into high and low bits
pub(crate) fn power2round(
    t: &[Polynomial],
    parameter_set: ParameterSet
) -> Result<(Vec<Polynomial>, Vec<Polynomial>)> {
    let k = t.len();
    let d = 13; // The d parameter from FIPS 203
    
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

/// Encode the public key
pub(crate) fn encode_public_key(
    rho: &[u8; 32],
    t1: &[Polynomial],
    parameter_set: ParameterSet
) -> Result<Vec<u8>> {
    let k = parameter_set.k();
    let d = 13; // The d parameter from FIPS 203
    
    // Calculate public key size
    let t1_size = k * 32 * (bitlen(8380417 - 1) - d);
    let pk_size = 32 + t1_size;
    
    let mut public_key = Vec::with_capacity(pk_size);
    
    // Add rho
    public_key.extend_from_slice(rho);
    
    // Add t1
    for i in 0..k {
        let encoded = byte_encode(&t1[i], 2_u32.pow(bitlen(8380417 - 1) as u32 - d as u32) - 1)?;
        public_key.extend(encoded);
    }
    
    Ok(public_key)
}

/// Encode the private key
pub(crate) fn encode_private_key(
    rho: &[u8; 32],
    key_seed: &[u8; 32],
    tr: &[u8],
    s1: &[Polynomial],
    s2: &[Polynomial],
    t0: &[Polynomial],
    parameter_set: ParameterSet
) -> Result<Vec<u8>> {
    let k = parameter_set.k();
    let eta1 = parameter_set.eta1();
    let d = 13; // The d parameter from FIPS 203
    
    // Calculate private key size
    let s1_s2_size = k * 32 * bitlen(2 * eta1);
    let t0_size = k * 32 * d;
    let sk_size = 32 + 32 + 64 + s1_s2_size + t0_size;
    
    let mut private_key = Vec::with_capacity(sk_size);
    
    // Add rho, key_seed, tr
    private_key.extend_from_slice(rho);
    private_key.extend_from_slice(key_seed);
    private_key.extend_from_slice(tr);
    
    // Add s1
    for i in 0..k {
        let encoded = bit_pack(&s1[i], eta1 as i32, eta1 as i32)?;
        private_key.extend(encoded);
    }
    
    // Add s2
    for i in 0..k {
        let encoded = bit_pack(&s2[i], eta1 as i32, eta1 as i32)?;
        private_key.extend(encoded);
    }
    
    // Add t0
    for i in 0..k {
        let encoded = bit_pack(&t0[i], (1 << (d - 1)) - 1, 1 << (d - 1))?;
        private_key.extend(encoded);
    }
    
    Ok(private_key)
}

/// Decode the private key
pub(crate) fn decode_private_key(
    private_key: &[u8],
    parameter_set: ParameterSet
) -> Result<(Vec<u8>, Vec<u8>, [u8; 32], [u8; 32])> {
    let pk_size = 32 + 32 * parameter_set.k() * (bitlen(8380417 - 1) - 13);
    
    // Extract components
    let dk_pke = private_key[0..384 * parameter_set.k()].to_vec();
    let ek_pke = private_key[384 * parameter_set.k()..384 * parameter_set.k() + pk_size].to_vec();
    
    let mut h = [0u8; 32];
    h.copy_from_slice(&private_key[384 * parameter_set.k() + pk_size..384 * parameter_set.k() + pk_size + 32]);
    
    let mut z = [0u8; 32];
    z.copy_from_slice(&private_key[384 * parameter_set.k() + pk_size + 32..384 * parameter_set.k() + pk_size + 64]);
    
    Ok((dk_pke, ek_pke, h, z))
}

/// K-PKE Encrypt
pub(crate) fn encrypt(
    public_key: &[u8],
    message: &[u8; 32],
    randomness: &[u8; 32],
    parameter_set: ParameterSet
) -> Result<Vec<u8>> {
    let k = parameter_set.k();
    let eta1 = parameter_set.eta1();
    let eta2 = parameter_set.eta2();
    let du = parameter_set.du();
    let dv = parameter_set.dv();
    
    // 1. Initialize counter
    let mut counter = 0u8;
    
    // 2-3. Decode the public key
    let (t, rho) = decode_public_key(public_key, parameter_set)?;
    
    // 4-8. Generate matrix A
    let ntt_ctx = NTTContext::new();
    let matrix_a = expand_a(&rho, k)?;
    
    // 9-12. Generate vector y
    let mut y = Vec::with_capacity(k);
    for i in 0..k {
        let seed = [randomness, &[counter]].concat();
        counter += 1;
        let y_i = sample_cbd(seed.as_slice(), eta1)?;
        y.push(y_i);
    }
    
    // 13-16. Generate vector e1
    let mut e1 = Vec::with_capacity(k);
    for i in 0..k {
        let seed = [randomness, &[counter]].concat();
        counter += 1;
        let e1_i = sample_cbd(seed.as_slice(), eta2)?;
        e1.push(e1_i);
    }
    
    // 17. Generate e2
    let seed = [randomness, &[counter]].concat();
    let e2 = sample_cbd(seed.as_slice(), eta2)?;
    
    // 18. NTT transform y
    let mut y_ntt = Vec::with_capacity(k);
    for i in 0..k {
        let mut y_i = y[i].clone();
        ntt_ctx.forward(&mut y_i)?;
        y_ntt.push(y_i);
    }
    
    // 19. Compute u = A^T * y + e1
    let mut u = Vec::with_capacity(k);
    for j in 0..k {
        let mut u_j = Polynomial::new();
        
        // Compute the j-th column of A times y
        for i in 0..k {
            let mut prod = ntt_ctx.multiply_ntt(&matrix_a[i][j], &y_ntt[i])?;
            u_j.add_assign(&prod, ntt_ctx.modulus);
        }
        
        // Transform back
        ntt_ctx.inverse(&mut u_j)?;
        
        // Add e1[j]
        u_j.add_assign(&e1[j], ntt_ctx.modulus);
        
        u.push(u_j);
    }
    
    // 20. Decode message
    let mu = decompress1(byte_decode1(message)?)?;
    
    // 21. Compute v = t^T * y + e2 + mu
    let mut v = e2.clone();
    for i in 0..k {
        let mut prod = ntt_ctx.multiply_ntt(&t[i], &y_ntt[i])?;
        ntt_ctx.inverse(&mut prod)?;
        v.add_assign(&prod, ntt_ctx.modulus);
    }
    v.add_assign(&mu, ntt_ctx.modulus);
    
    // 22-23. Compress u and v
    let u_compressed = compress_vector(&u, du)?;
    let v_compressed = compress(&v, dv)?;
    
    // 24. Encode and return ciphertext
    let c1 = byte_encode_vector(&u_compressed, du)?;
    let c2 = byte_encode(&v_compressed, dv)?;
    
    let mut ciphertext = Vec::new();
    ciphertext.extend(c1);
    ciphertext.extend(c2);
    
    Ok(ciphertext)
}

/// K-PKE Decrypt
pub(crate) fn decrypt(
    private_key: &[u8],
    ciphertext: &[u8],
    parameter_set: ParameterSet
) -> Result<[u8; 32]> {
    let k = parameter_set.k();
    let du = parameter_set.du();
    let dv = parameter_set.dv();
    
    // 1-4. Decode ciphertext
    let c1_len = 32 * du * k;
    let c1 = &ciphertext[0..c1_len];
    let c2 = &ciphertext[c1_len..];
    
    let u_prime = decompress_vector(&byte_decode_vector(c1, du)?, du)?;
    let v_prime = decompress(&byte_decode(c2, dv)?, dv)?;
    
    // 5. Decode private key
    let s = decode_s_from_private_key(private_key, parameter_set)?;
    
    // 6. Compute w = v' - s^T * u'
    let ntt_ctx = NTTContext::new();
    let mut w = v_prime.clone();
    
    // Transform u' to NTT domain
    let mut u_prime_ntt = Vec::with_capacity(k);
    for i in 0..k {
        let mut u_i = u_prime[i].clone();
        ntt_ctx.forward(&mut u_i)?;
        u_prime_ntt.push(u_i);
    }
    
    // Transform s to NTT domain
    let mut s_ntt = Vec::with_capacity(k);
    for i in 0..k {
        let mut s_i = s[i].clone();
        ntt_ctx.forward(&mut s_i)?;
        s_ntt.push(s_i);
    }
    
    // Compute s^T * u'
    for i in 0..k {
        let mut prod = ntt_ctx.multiply_ntt(&s_ntt[i], &u_prime_ntt[i])?;
        ntt_ctx.inverse(&mut prod)?;
        w.sub_assign(&prod, ntt_ctx.modulus);
    }
    
    // 7. Compress and encode message
    let m = byte_encode1(compress1(w)?)?;
    
    let mut result = [0u8; 32];
    result.copy_from_slice(&m);
    
    Ok(result)
}

// Helper functions

/// Calculate the bit length of a positive integer
fn bitlen(n: u32) -> usize {
    32 - n.leading_zeros() as usize
}

/// Rejection sampling in NTT domain
fn reject_sample_ntt(seed: &[u8], ntt_ctx: &NTTContext) -> Result<Polynomial> {
    // Implementation of RejNTTPoly from FIPS 203
    let mut poly = Polynomial::new();
    let mut j = 0;
    
    let mut ctx = hash::SHAKE128Context::init();
    ctx.absorb(seed);
    
    while j < 256 {
        let out = ctx.squeeze(3);
        let d1 = (out[0] as u32) | ((out[1] as u32 & 0x0F) << 8);
        let d2 = ((out[1] as u32 & 0xF0) >> 4) | ((out[2] as u32) << 4);
        
        if d1 < 8380417 {
            poly.coeffs[j] = d1 as i32;
            j += 1;
        }
        
        if j < 256 && d2 < 8380417 {
            poly.coeffs[j] = d2 as i32;
            j += 1;
        }
    }
    
    // Already in NTT domain
    Ok(poly)
}

/// Sample from the centered binomial distribution
fn sample_cbd(seed: &[u8], eta: usize) -> Result<Polynomial> {
    let mut poly = Polynomial::new();
    
    // Convert seed to bit array
    let bits = byte_to_bits(seed)?;
    
    for i in 0..256 {
        let mut a = 0;
        let mut b = 0;
        
        for j in 0..eta {
            a += bits[2*i*eta + j] as i32;
            b += bits[2*i*eta + eta + j] as i32;
        }
        
        poly.coeffs[i] = a - b;
    }
    
    Ok(poly)
}

/// Expand matrix A
fn expand_a(rho: &[u8], k: usize) -> Result<Vec<Vec<Polynomial>>> {
    let ntt_ctx = NTTContext::new();
    
    let mut matrix_a = Vec::with_capacity(k);
    for i in 0..k {
        let mut row = Vec::with_capacity(k);
        for j in 0..k {
            let seed = [rho, &[j as u8, i as u8]].concat();
            let a_ij = reject_sample_ntt(&seed, &ntt_ctx)?;
            row.push(a_ij);
        }
        matrix_a.push(row);
    }
    
    Ok(matrix_a)
}

/// Decode the public key
fn decode_public_key(
    public_key: &[u8],
    parameter_set: ParameterSet
) -> Result<(Vec<Polynomial>, [u8; 32])> {
    let k = parameter_set.k();
    let d = 13; // The d parameter from FIPS 203
    
    // Extract rho
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&public_key[0..32]);
    
    // Extract t1
    let t1_size = 32 * (bitlen(8380417 - 1) - d);
    let mut t = Vec::with_capacity(k);
    
    for i in 0..k {
        let start = 32 + i * t1_size;
        let end = start + t1_size;
        let t1_i = byte_decode(&public_key[start..end], 2_u32.pow(bitlen(8380417 - 1) as u32 - d as u32) - 1)?;
        t.push(t1_i);
    }
    
    Ok((t, rho))
}

/// Decode s from private key
fn decode_s_from_private_key(
    private_key: &[u8],
    parameter_set: ParameterSet
) -> Result<Vec<Polynomial>> {
    let k = parameter_set.k();
    let eta1 = parameter_set.eta1();
    
    // s is stored after rho, key_seed, and tr
    let s_start = 32 + 32 + 64;
    let s_size = 32 * bitlen(2 * eta1);
    
    let mut s = Vec::with_capacity(k);
    
    for i in 0..k {
        let start = s_start + i * s_size;
        let end = start + s_size;
        let s_i = bit_unpack(&private_key[start..end], eta1 as i32, eta1 as i32)?;
        s.push(s_i);
    }
    
    Ok(s)
}

// Auxiliary encoding and decoding functions
// These would need to be properly implemented based on FIPS 203

fn byte_encode(poly: &Polynomial, bound: u32) -> Result<Vec<u8>> {
    // Simplified implementation
    let mut result = Vec::new();
    // Implementation would encode polynomial coefficients as bytes
    Ok(result)
}

fn byte_encode_vector(polys: &[Polynomial], bound: usize) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    for poly in polys {
        result.extend(byte_encode(poly, bound as u32)?);
    }
    Ok(result)
}

fn byte_decode(bytes: &[u8], bound: u32) -> Result<Polynomial> {
    // Simplified implementation
    let mut poly = Polynomial::new();
    // Implementation would decode bytes into polynomial coefficients
    Ok(poly)
}

fn byte_decode_vector(bytes: &[u8], bound: usize) -> Result<Vec<Polynomial>> {
    // Simplified implementation
    let mut result = Vec::new();
    // Implementation would decode bytes into polynomial vector
    Ok(result)
}

fn byte_encode1(poly: Polynomial) -> Result<Vec<u8>> {
    // Simplified implementation
    let mut result = Vec::new();
    // Implementation would encode polynomial coefficients as bytes for d=1
    Ok(result)
}

fn byte_decode1(bytes: &[u8]) -> Result<Polynomial> {
    // Simplified implementation
    let mut poly = Polynomial::new();
    // Implementation would decode bytes into polynomial for d=1
    Ok(poly)
}

fn byte_to_bits(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for j in 0..8 {
            bits.push((byte >> j) & 1);
        }
    }
    Ok(bits)
}

fn bit_pack(poly: &Polynomial, a: i32, b: i32) -> Result<Vec<u8>> {
    // Simplified implementation
    let mut result = Vec::new();
    // Implementation would encode polynomial coefficients as bits
    Ok(result)
}

fn bit_unpack(bytes: &[u8], a: i32, b: i32) -> Result<Polynomial> {
    // Simplified implementation
    let mut poly = Polynomial::new();
    // Implementation would decode bits into polynomial
    Ok(poly)
}

fn compress(poly: &Polynomial, d: usize) -> Result<Polynomial> {
    let mut result = Polynomial::new();
    for i in 0..256 {
        let value = poly.coeffs[i];
        // FIPS 203 formula: Compress_d(x) = ⌈(2^d/q) · x⌋ mod 2^d
        let compressed = ((((1 << d) as i64 * value as i64) + (8380417 / 2) as i64) / 8380417) % (1 << d) as i64;
        result.coeffs[i] = compressed as i32;
    }
    Ok(result)
}

fn compress_vector(polys: &[Polynomial], d: usize) -> Result<Vec<Polynomial>> {
    let mut result = Vec::with_capacity(polys.len());
    for poly in polys {
        result.push(compress(poly, d)?);
    }
    Ok(result)
}

fn decompress(poly: &Polynomial, d: usize) -> Result<Polynomial> {
    let mut result = Polynomial::new();
    for i in 0..256 {
        let value = poly.coeffs[i];
        // FIPS 203 formula: Decompress_d(y) = ⌈(q/2^d) · y⌋
        let decompressed = ((8380417 as i64 * value as i64) + (1 << (d - 1)) as i64) >> d;
        result.coeffs[i] = decompressed as i32;
    }
    Ok(result)
}

fn decompress_vector(polys: &[Polynomial], d: usize) -> Result<Vec<Polynomial>> {
    let mut result = Vec::with_capacity(polys.len());
    for poly in polys {
        result.push(decompress(poly, d)?);
    }
    Ok(result)
}

fn compress1(poly: Polynomial) -> Result<Polynomial> {
    compress(&poly, 1)
}

fn decompress1(poly: Polynomial) -> Result<Polynomial> {
    decompress(&poly, 1)
}