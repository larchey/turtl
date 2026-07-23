//! K-PKE component for ML-KEM (FIPS 203).
//!
//! This module implements the K-PKE public-key encryption scheme
//! used as a component within ML-KEM, following FIPS 203 Algorithms 12-14.

use crate::common::ntt::NTTType;
use crate::common::{ntt::NTTContext, poly::Polynomial};
use crate::error::{Error, Result};
use crate::kem::ParameterSet;

use super::aux;

/// Generate the key components for K-PKE (FIPS 203 Algorithm 12)
///
/// Generates matrix A, secret vector s, and error vector e.
/// Returns (A, s, e) where all are in normal (non-NTT) domain.
pub(crate) fn generate_key_components(
    rho: &[u8; 32],
    sigma: &[u8; 32],
    parameter_set: ParameterSet,
) -> Result<(Vec<Vec<Polynomial>>, Vec<Polynomial>, Vec<Polynomial>)> {
    let k = parameter_set.k();
    let eta1 = parameter_set.eta1();

    // Create NTT context
    let ntt_ctx = NTTContext::new(NTTType::MLKEM);

    // Generate matrix A (already in NTT domain per FIPS 203 Section 4.2)
    let mut matrix_a = Vec::with_capacity(k);
    for i in 0..k {
        let mut row = Vec::with_capacity(k);
        for j in 0..k {
            let mut seed = Vec::with_capacity(rho.len() + 2);
            seed.extend_from_slice(rho);
            seed.push(j as u8);
            seed.push(i as u8);
            let a_ij = reject_sample_ntt(&seed, &ntt_ctx)?;
            row.push(a_ij);
        }
        matrix_a.push(row);
    }

    // Generate secret vector s (FIPS 203 calls this s)
    let mut s = Vec::with_capacity(k);
    let mut counter = 0u8;

    for _i in 0..k {
        let mut seed = Vec::with_capacity(sigma.len() + 1);
        seed.extend_from_slice(sigma);
        seed.push(counter);
        counter += 1;
        let s_i = sample_cbd(seed.as_slice(), eta1)?;
        s.push(s_i);
    }

    // Generate error vector e (FIPS 203 calls this e)
    let mut e = Vec::with_capacity(k);
    for _i in 0..k {
        let mut seed = Vec::with_capacity(sigma.len() + 1);
        seed.extend_from_slice(sigma);
        seed.push(counter);
        counter += 1;
        let e_i = sample_cbd(seed.as_slice(), eta1)?;
        e.push(e_i);
    }

    Ok((matrix_a, s, e))
}

/// Compute the public value t-hat = A-hat·s-hat + e-hat (FIPS 203 Algorithm 13).
///
/// Per FIPS 203, the public key stores t-hat in the NTT domain, so this returns
/// t-hat (NTT domain) alongside s-hat (NTT domain), which the private key stores.
/// Matrix A is already in the NTT domain.
pub(crate) fn compute_public_t(
    matrix_a: &[Vec<Polynomial>],
    s: &[Polynomial],
    e: &[Polynomial],
) -> Result<(Vec<Polynomial>, Vec<Polynomial>)> {
    let k = matrix_a.len();
    let ntt_ctx = NTTContext::new(NTTType::MLKEM);

    // NTT transform s and e (FIPS 203 keeps both in the NTT domain)
    let mut s_hat = Vec::with_capacity(k);
    let mut e_hat = Vec::with_capacity(k);
    for i in 0..k {
        let mut s_i = s[i].clone();
        ntt_ctx.forward(&mut s_i)?;
        s_hat.push(s_i);

        let mut e_i = e[i].clone();
        ntt_ctx.forward(&mut e_i)?;
        e_hat.push(e_i);
    }

    // Compute t-hat = A-hat·s-hat + e-hat, staying in the NTT domain
    let mut t_hat = Vec::with_capacity(k);
    for i in 0..k {
        let mut t_i = Polynomial::new();

        // Compute the i-th row of A-hat times s-hat
        for j in 0..k {
            let prod = ntt_ctx.multiply_ntt(&matrix_a[i][j], &s_hat[j])?;
            t_i.add_assign(&prod, ntt_ctx.modulus);
        }

        // Add e-hat[i] (no inverse NTT: t-hat stays in NTT domain)
        t_i.add_assign(&e_hat[i], ntt_ctx.modulus);

        t_hat.push(t_i);
    }

    Ok((t_hat, s_hat))
}

/// Encode the public key (FIPS 203 Algorithm 13, step 8)
///
/// Public key format: ek_pke = ByteEncode_12(t-hat[0]) || ... || ByteEncode_12(t-hat[k-1]) || ρ
/// Note FIPS 203 places ρ *after* the encoded t-hat.
pub(crate) fn encode_public_key(
    rho: &[u8; 32],
    t: &[Polynomial],
    _parameter_set: ParameterSet,
) -> Result<Vec<u8>> {
    let k = t.len();

    // Public key size: k * 32 * 12 bits / 8 + 32 bytes (ρ) = k * 384 + 32 bytes
    let pk_size = k * 384 + 32;
    let mut public_key = Vec::with_capacity(pk_size);

    // Add ByteEncode_12(t-hat) for each polynomial
    // FIPS 203: ByteEncode_d encodes coefficients with d bits each
    for i in 0..k {
        let encoded = byte_encode_12(&t[i])?;
        public_key.extend(encoded);
    }

    // Add ρ (appended last, per FIPS 203)
    public_key.extend_from_slice(rho);

    Ok(public_key)
}

/// Encode the K-PKE private key (FIPS 203 uses s only, not t0)
///
/// Private key format: dk_pke = ByteEncode_12(s[0]) || ... || ByteEncode_12(s[k-1])
pub(crate) fn encode_private_key_pke(s: &[Polynomial]) -> Result<Vec<u8>> {
    let k = s.len();

    // Private key size: k * 32 * 12 bits / 8 = k * 384 bytes
    let sk_size = k * 384;
    let mut private_key = Vec::with_capacity(sk_size);

    // Add ByteEncode_12(s) for each polynomial
    for i in 0..k {
        let encoded = byte_encode_12(&s[i])?;
        private_key.extend(encoded);
    }

    Ok(private_key)
}

/// Decode the public key
pub(crate) fn decode_public_key(
    public_key: &[u8],
    parameter_set: ParameterSet,
) -> Result<(Vec<Polynomial>, [u8; 32])> {
    let k = parameter_set.k();

    if public_key.len() != k * 384 + 32 {
        return Err(Error::EncodingError(format!(
            "Invalid public key length: expected {}, got {}",
            k * 384 + 32,
            public_key.len()
        )));
    }

    // Extract t-hat (decode each polynomial), then ρ which is appended last
    let mut t = Vec::with_capacity(k);
    for i in 0..k {
        let start = i * 384;
        let end = start + 384;
        let t_i = byte_decode_12(&public_key[start..end])?;
        t.push(t_i);
    }

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&public_key[k * 384..k * 384 + 32]);

    Ok((t, rho))
}

/// Decode the private key
/// Returns (dk_pke, ek_pke, h, z)
pub(crate) fn decode_private_key(
    private_key: &[u8],
    parameter_set: ParameterSet,
) -> Result<(Vec<u8>, Vec<u8>, [u8; 32], [u8; 32])> {
    let k = parameter_set.k();
    let dk_pke_size = k * 384;
    let ek_pke_size = parameter_set.public_key_size();

    if private_key.len() < dk_pke_size + ek_pke_size + 64 {
        return Err(Error::EncodingError(format!(
            "Private key too short: expected at least {}, got {}",
            dk_pke_size + ek_pke_size + 64,
            private_key.len()
        )));
    }

    // Extract components
    let dk_pke = private_key[0..dk_pke_size].to_vec();
    let ek_pke = private_key[dk_pke_size..dk_pke_size + ek_pke_size].to_vec();

    let mut h = [0u8; 32];
    h.copy_from_slice(&private_key[dk_pke_size + ek_pke_size..dk_pke_size + ek_pke_size + 32]);

    let mut z = [0u8; 32];
    z.copy_from_slice(&private_key[dk_pke_size + ek_pke_size + 32..dk_pke_size + ek_pke_size + 64]);

    Ok((dk_pke, ek_pke, h, z))
}

/// Decode s from dk_pke bytes
fn decode_s_from_dk_pke(dk_pke: &[u8], k: usize) -> Result<Vec<Polynomial>> {
    if dk_pke.len() != k * 384 {
        return Err(Error::EncodingError(format!(
            "Invalid dk_pke length: expected {}, got {}",
            k * 384,
            dk_pke.len()
        )));
    }

    let mut s = Vec::with_capacity(k);
    for i in 0..k {
        let start = i * 384;
        let end = start + 384;
        let s_i = byte_decode_12(&dk_pke[start..end])?;
        s.push(s_i);
    }

    Ok(s)
}

/// K-PKE Encrypt (FIPS 203 Algorithm 13)
pub(crate) fn encrypt(
    public_key: &[u8],
    message: &[u8; 32],
    randomness: &[u8; 32],
    parameter_set: ParameterSet,
) -> Result<Vec<u8>> {
    let k = parameter_set.k();
    let eta1 = parameter_set.eta1();
    let eta2 = parameter_set.eta2();
    let du = parameter_set.du();
    let dv = parameter_set.dv();

    // Initialize counter
    let mut counter = 0u8;

    // Decode the public key: t-hat is already in the NTT domain (FIPS 203)
    let (t_ntt, rho) = decode_public_key(public_key, parameter_set)?;

    // Generate matrix A (in NTT domain)
    let ntt_ctx = NTTContext::new(NTTType::MLKEM);
    let matrix_a = expand_a(&rho, k)?;

    // Sample vector r from CBD_η1
    let mut r = Vec::with_capacity(k);
    for _i in 0..k {
        let mut seed = Vec::with_capacity(randomness.len() + 1);
        seed.extend_from_slice(randomness);
        seed.push(counter);
        counter += 1;
        let r_i = sample_cbd(seed.as_slice(), eta1)?;
        r.push(r_i);
    }

    // Sample vector e1 from CBD_η2
    let mut e1 = Vec::with_capacity(k);
    for _i in 0..k {
        let mut seed = Vec::with_capacity(randomness.len() + 1);
        seed.extend_from_slice(randomness);
        seed.push(counter);
        counter += 1;
        let e1_i = sample_cbd(seed.as_slice(), eta2)?;
        e1.push(e1_i);
    }

    // Sample e2 from CBD_η2
    let mut seed = Vec::with_capacity(randomness.len() + 1);
    seed.extend_from_slice(randomness);
    seed.push(counter);
    let e2 = sample_cbd(seed.as_slice(), eta2)?;

    // NTT transform r
    let mut r_ntt = Vec::with_capacity(k);
    for i in 0..k {
        let mut r_i = r[i].clone();
        ntt_ctx.forward(&mut r_i)?;
        r_ntt.push(r_i);
    }

    // Compute u = A^T·r + e1
    let mut u = Vec::with_capacity(k);
    for j in 0..k {
        let mut u_j = Polynomial::new();

        // Compute the j-th column of A times r (A^T)
        for i in 0..k {
            let prod = ntt_ctx.multiply_ntt(&matrix_a[i][j], &r_ntt[i])?;
            u_j.add_assign(&prod, ntt_ctx.modulus);
        }

        // Transform back to normal domain
        ntt_ctx.inverse(&mut u_j)?;

        // Add e1[j]
        u_j.add_assign(&e1[j], ntt_ctx.modulus);

        u.push(u_j);
    }

    // Decode message
    let mu = decompress1(byte_decode1(message)?)?;

    // Compute v = t^T·r + e2 + μ
    let mut v = e2.clone();
    for i in 0..k {
        let mut prod = ntt_ctx.multiply_ntt(&t_ntt[i], &r_ntt[i])?;
        ntt_ctx.inverse(&mut prod)?;
        v.add_assign(&prod, ntt_ctx.modulus);
    }
    v.add_assign(&mu, ntt_ctx.modulus);

    // Compress u and v
    let u_compressed = compress_vector(&u, du)?;
    let v_compressed = compress(&v, dv)?;

    // Encode ciphertext
    let c1 = byte_encode_vector(&u_compressed, (1 << du) - 1)?;
    let c2 = byte_encode(&v_compressed, (1 << dv) - 1)?;

    let mut ciphertext = Vec::new();
    ciphertext.extend(c1);
    ciphertext.extend(c2);

    Ok(ciphertext)
}

/// K-PKE Decrypt (FIPS 203 Algorithm 14)
pub(crate) fn decrypt(
    private_key: &[u8],
    ciphertext: &[u8],
    parameter_set: ParameterSet,
) -> Result<[u8; 32]> {
    let k = parameter_set.k();
    let du = parameter_set.du();
    let dv = parameter_set.dv();

    // Decode ciphertext
    let c1_len = 32 * du * k;
    if ciphertext.len() < c1_len {
        return Err(Error::EncodingError(format!(
            "Ciphertext too short: expected at least {}, got {}",
            c1_len,
            ciphertext.len()
        )));
    }

    let c1 = &ciphertext[0..c1_len];
    let c2 = &ciphertext[c1_len..];

    let u = decompress_vector(&byte_decode_vector(c1, (1 << du) - 1)?, du)?;
    let v = decompress(&byte_decode(c2, (1 << dv) - 1)?, dv)?;

    // Decode private key to get s-hat (already in the NTT domain, FIPS 203)
    let s_ntt = decode_s_from_dk_pke(private_key, k)?;

    // Compute w = v - s^T·u
    let ntt_ctx = NTTContext::new(NTTType::MLKEM);
    let mut w = v.clone();

    // Transform u to NTT domain
    let mut u_ntt = Vec::with_capacity(k);
    for i in 0..k {
        let mut u_i = u[i].clone();
        ntt_ctx.forward(&mut u_i)?;
        u_ntt.push(u_i);
    }

    // Compute s-hat^T·u-hat
    for i in 0..k {
        let mut prod = ntt_ctx.multiply_ntt(&s_ntt[i], &u_ntt[i])?;
        ntt_ctx.inverse(&mut prod)?;
        w.sub_assign(&prod, ntt_ctx.modulus);
    }

    // Compress and encode message
    let m = byte_encode1(compress1(w)?)?;

    let mut result = [0u8; 32];
    result.copy_from_slice(&m);

    Ok(result)
}

// Helper functions

/// Rejection sampling in NTT domain (FIPS 203 Algorithm 16)
fn reject_sample_ntt(seed: &[u8], _ntt_ctx: &NTTContext) -> Result<Polynomial> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let mut poly = Polynomial::new();
    let mut j = 0;

    // Create SHAKE128 XOF
    let mut hasher = sha3::Shake128::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    // Generous cap so an adversarial/degenerate seed cannot hang the process.
    // ~128 accepting iterations are expected; exhausting this bound is
    // cryptographically implausible for a well-formed XOF.
    let mut iterations = 0;
    while j < 256 {
        if iterations >= 10_000 {
            return Err(Error::RandomnessError);
        }
        iterations += 1;

        let mut buf = [0u8; 3];
        reader.read(&mut buf);

        let d1 = (buf[0] as u32) | ((buf[1] as u32 & 0x0F) << 8);
        let d2 = ((buf[1] as u32 & 0xF0) >> 4) | ((buf[2] as u32) << 4);

        if d1 < 3329 {
            poly.coeffs[j] = d1 as i32;
            j += 1;
        }

        if j < 256 && d2 < 3329 {
            poly.coeffs[j] = d2 as i32;
            j += 1;
        }
    }

    Ok(poly)
}

/// Sample from the centered binomial distribution (FIPS 203 Algorithm 17)
fn sample_cbd(seed: &[u8], eta: usize) -> Result<Polynomial> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let mut poly = Polynomial::new();

    // Use SHAKE256 to expand the seed (FIPS 203 uses SHAKE256 for CBD sampling)
    let mut hasher = sha3::Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    // We need 256 coefficients, each requiring 2*eta bits
    let required_bytes = (256 * 2 * eta).div_ceil(8);
    let mut expanded_seed = vec![0u8; required_bytes];
    reader.read(&mut expanded_seed);

    // Convert to bits
    let bits = aux::bytes_to_bits(&expanded_seed);

    // Sample each coefficient
    for i in 0..256 {
        let mut a = 0;
        let mut b = 0;

        for j in 0..eta {
            let idx_a = 2 * i * eta + j;
            let idx_b = 2 * i * eta + eta + j;

            if idx_a < bits.len() {
                a += bits[idx_a] as i32;
            }

            if idx_b < bits.len() {
                b += bits[idx_b] as i32;
            }
        }

        poly.coeffs[i] = a - b;
    }

    Ok(poly)
}

/// Expand matrix A (FIPS 203 Algorithm 15)
fn expand_a(rho: &[u8], k: usize) -> Result<Vec<Vec<Polynomial>>> {
    let ntt_ctx = NTTContext::new(NTTType::MLKEM);

    let mut matrix_a = Vec::with_capacity(k);
    for i in 0..k {
        let mut row = Vec::with_capacity(k);
        for j in 0..k {
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

// Encoding/Decoding functions

/// ByteEncode_12 for ML-KEM (FIPS 203 Algorithm 4)
/// Encodes a polynomial with coefficients in [0, q-1] using 12 bits per coefficient
fn byte_encode_12(poly: &Polynomial) -> Result<Vec<u8>> {
    let mut result = vec![0u8; 384]; // 256 coefficients * 12 bits / 8 = 384 bytes

    let bits_per_coeff = 12;
    let mut bits = Vec::with_capacity(256 * bits_per_coeff);

    for i in 0..256 {
        let mut coeff = poly.coeffs[i];

        // Ensure coefficient is in [0, q-1]
        if coeff < 0 {
            coeff += 3329;
        }
        coeff = coeff.rem_euclid(3329);

        if !(0..3329).contains(&coeff) {
            return Err(Error::EncodingError(format!(
                "Coefficient out of range: {}",
                coeff
            )));
        }

        // Store coefficient in 12 bits (little-endian)
        for j in 0..bits_per_coeff {
            bits.push(((coeff >> j) & 1) as u8);
        }
    }

    // Pack bits into bytes
    for i in 0..384 {
        let mut byte = 0u8;
        for j in 0..8 {
            if i * 8 + j < bits.len() {
                byte |= bits[i * 8 + j] << j;
            }
        }
        result[i] = byte;
    }

    Ok(result)
}

/// ByteDecode_12 for ML-KEM (FIPS 203 Algorithm 5)
/// Decodes a byte array into a polynomial with coefficients in [0, q-1]
fn byte_decode_12(bytes: &[u8]) -> Result<Polynomial> {
    if bytes.len() < 384 {
        return Err(Error::EncodingError(format!(
            "Input too short: expected 384 bytes, got {}",
            bytes.len()
        )));
    }

    // Convert bytes to bits
    let bits = aux::bytes_to_bits(&bytes[0..384]);

    let mut poly = Polynomial::new();
    let bits_per_coeff = 12;

    for i in 0..256 {
        let start = i * bits_per_coeff;

        if start + bits_per_coeff > bits.len() {
            return Err(Error::EncodingError(
                "Not enough bits for polynomial".to_string(),
            ));
        }

        let mut coeff = 0i32;
        for j in 0..bits_per_coeff {
            coeff |= (bits[start + j] as i32) << j;
        }

        if coeff >= 3329 {
            return Err(Error::EncodingError(format!(
                "Decoded coefficient out of range: {}",
                coeff
            )));
        }

        poly.coeffs[i] = coeff;
    }

    Ok(poly)
}

/// Generic byte encoding (FIPS 203 Algorithm 4)
fn byte_encode(poly: &Polynomial, bound: u32) -> Result<Vec<u8>> {
    let bits_per_coeff = aux::ceil_log2(bound + 1);
    let bytes_needed = (256 * bits_per_coeff as usize).div_ceil(8);
    let mut result = vec![0u8; bytes_needed];

    let mut bits = Vec::with_capacity(256 * bits_per_coeff as usize);

    for i in 0..256 {
        let coeff = poly.coeffs[i] as u32;
        if coeff > bound {
            return Err(Error::EncodingError(format!(
                "Coefficient out of range: {}",
                coeff
            )));
        }

        for j in 0..bits_per_coeff {
            bits.push(((coeff >> j) & 1) as u8);
        }
    }

    for i in 0..bytes_needed {
        let mut byte = 0u8;
        for j in 0..8 {
            if i * 8 + j < bits.len() {
                byte |= bits[i * 8 + j] << j;
            }
        }
        result[i] = byte;
    }

    Ok(result)
}

/// Generic byte decoding (FIPS 203 Algorithm 5)
fn byte_decode(bytes: &[u8], bound: u32) -> Result<Polynomial> {
    let bits_per_coeff = aux::ceil_log2(bound + 1);
    let bytes_needed = (256 * bits_per_coeff as usize).div_ceil(8);

    if bytes.len() < bytes_needed {
        return Err(Error::EncodingError(format!(
            "Input too short: expected at least {} bytes, got {}",
            bytes_needed,
            bytes.len()
        )));
    }

    let bits = aux::bytes_to_bits(&bytes[0..bytes_needed]);
    let mut poly = Polynomial::new();

    for i in 0..256 {
        let start = i * bits_per_coeff as usize;

        if start + bits_per_coeff as usize > bits.len() {
            return Err(Error::EncodingError(
                "Not enough bits for polynomial".to_string(),
            ));
        }

        let mut coeff = 0u32;
        for j in 0..bits_per_coeff as usize {
            coeff |= (bits[start + j] as u32) << j;
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

/// Encode a vector of polynomials
fn byte_encode_vector(polys: &[Polynomial], bound: usize) -> Result<Vec<u8>> {
    let mut result = Vec::new();

    for poly in polys {
        let encoded = byte_encode(poly, bound as u32)?;
        result.extend_from_slice(&encoded);
    }

    Ok(result)
}

/// Decode a vector of polynomials
fn byte_decode_vector(bytes: &[u8], bound: usize) -> Result<Vec<Polynomial>> {
    let bits_per_coeff = aux::ceil_log2(bound as u32 + 1);
    let bytes_per_poly = (256 * bits_per_coeff as usize).div_ceil(8);

    if !bytes.len().is_multiple_of(bytes_per_poly) {
        return Err(Error::EncodingError("Invalid input length".to_string()));
    }

    let num_polys = bytes.len() / bytes_per_poly;
    let mut result = Vec::with_capacity(num_polys);

    for i in 0..num_polys {
        let start = i * bytes_per_poly;
        let end = start + bytes_per_poly;

        let poly = byte_decode(&bytes[start..end], bound as u32)?;
        result.push(poly);
    }

    Ok(result)
}

/// Encode message (d = 1)
fn byte_encode1(poly: Polynomial) -> Result<Vec<u8>> {
    let mut result = vec![0u8; 32]; // 256 bits = 32 bytes

    for i in 0..256 {
        let coeff = poly.coeffs[i];
        if coeff != 0 && coeff != 1 {
            return Err(Error::EncodingError(format!(
                "Coefficient out of range for d=1: {}",
                coeff
            )));
        }

        if coeff == 1 {
            result[i / 8] |= 1 << (i % 8);
        }
    }

    Ok(result)
}

/// Decode message (d = 1)
fn byte_decode1(bytes: &[u8]) -> Result<Polynomial> {
    if bytes.len() < 32 {
        return Err(Error::EncodingError(format!(
            "Input too short: expected at least 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut poly = Polynomial::new();

    for i in 0..256 {
        if (bytes[i / 8] >> (i % 8)) & 1 == 1 {
            poly.coeffs[i] = 1;
        } else {
            poly.coeffs[i] = 0;
        }
    }

    Ok(poly)
}

// Compression functions (FIPS 203 Algorithm 8 and 9)

/// Compress a polynomial (FIPS 203 Algorithm 8)
fn compress(poly: &Polynomial, d: usize) -> Result<Polynomial> {
    let mut result = Polynomial::new();
    let q = 3329;

    for i in 0..256 {
        let value = poly.coeffs[i];
        // Ensure value is in [0, q)
        let normalized = value.rem_euclid(q);

        // Compress_d(x) = ⌈(2^d/q) · x⌋ mod 2^d
        let compressed =
            ((((1 << d) as i64 * normalized as i64) + (q / 2) as i64) / q as i64) % (1 << d) as i64;
        result.coeffs[i] = compressed as i32;
    }

    Ok(result)
}

/// Decompress a polynomial (FIPS 203 Algorithm 9)
fn decompress(poly: &Polynomial, d: usize) -> Result<Polynomial> {
    let mut result = Polynomial::new();
    let q = 3329;

    for i in 0..256 {
        let value = poly.coeffs[i];
        if value < 0 || value >= (1 << d) {
            return Err(Error::EncodingError(format!(
                "Value out of range for Decompress_{}: {}",
                d, value
            )));
        }

        // Decompress_d(y) = ⌈(q/2^d) · y⌋
        let decompressed = ((q as i64 * value as i64) + (1 << (d - 1)) as i64) >> d;
        result.coeffs[i] = decompressed as i32;
    }

    Ok(result)
}

/// Compress a vector of polynomials
fn compress_vector(polys: &[Polynomial], d: usize) -> Result<Vec<Polynomial>> {
    let mut result = Vec::with_capacity(polys.len());
    for poly in polys {
        result.push(compress(poly, d)?);
    }
    Ok(result)
}

/// Decompress a vector of polynomials
fn decompress_vector(polys: &[Polynomial], d: usize) -> Result<Vec<Polynomial>> {
    let mut result = Vec::with_capacity(polys.len());
    for poly in polys {
        result.push(decompress(poly, d)?);
    }
    Ok(result)
}

/// Compress with d=1 for message encoding
fn compress1(poly: Polynomial) -> Result<Polynomial> {
    compress(&poly, 1)
}

/// Decompress with d=1 for message decoding
fn decompress1(poly: Polynomial) -> Result<Polynomial> {
    decompress(&poly, 1)
}
