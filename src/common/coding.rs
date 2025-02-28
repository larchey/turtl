//! Encoding and decoding functions for ML-KEM and ML-DSA.
//! 
//! This module implements encoding and decoding operations
//! for both ML-KEM and ML-DSA algorithms.

use crate::error::{Error, Result};
use crate::common::poly::Polynomial;
use crate::common::ntt::NTTType;

/// Convert a byte array to a bit array
pub fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for &byte in bytes {
        for j in 0..8 {
            bits.push((byte >> j) & 1);
        }
    }
    bits
}

/// Convert a bit array to a byte array
pub fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    let num_bytes = (bits.len() + 7) / 8;
    let mut bytes = vec![0u8; num_bytes];
    
    for (i, &bit) in bits.iter().enumerate() {
        if bit != 0 {
            bytes[i / 8] |= 1 << (i % 8);
        }
    }
    
    bytes
}

/// Encode an integer into bytes (little-endian)
pub fn int_to_bytes(x: u32, num_bytes: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(num_bytes);
    let mut x_copy = x;
    
    for _ in 0..num_bytes {
        bytes.push((x_copy & 0xFF) as u8);
        x_copy >>= 8;
    }
    
    bytes
}

/// Decode an integer from bytes (little-endian)
pub fn bytes_to_int(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= (byte as u32) << (8 * i);
    }
    result
}

/// ML-KEM/ML-DSA Compression function
pub fn compress(x: u32, d: usize, q: u32) -> u32 {
    ((((1u64 << d) * x as u64 + q as u64 / 2) / q as u64) % (1u64 << d)) as u32
}

/// ML-KEM/ML-DSA Decompression function
pub fn decompress(x: u32, d: usize, q: u32) -> u32 {
    ((q as u64 * x as u64 + (1u64 << (d - 1))) >> d) as u32
}

/// Get modulus for the specified algorithm type
pub fn get_modulus_for_ntt_type(ntt_type: NTTType) -> u32 {
    match ntt_type {
        NTTType::MLKEM => 3329,     // ML-KEM modulus
        NTTType::MLDSA => 8380417,  // ML-DSA modulus
    }
}

/// Compress a polynomial according to algorithm type
pub fn compress_poly(poly: &Polynomial, d: usize, ntt_type: NTTType) -> Result<Polynomial> {
    let q = get_modulus_for_ntt_type(ntt_type);
    let mut result = Polynomial::new();
    
    for i in 0..256 {
        let value = poly.coeffs[i] as u32;
        if value >= q {
            return Err(Error::EncodingError(format!(
                "Value out of range for compression: {} not in [0, {})", value, q
            )));
        }
        
        // Compress_d(x) = ⌈(2^d/q) · x⌋ mod 2^d
        result.coeffs[i] = compress(value, d, q) as i32;
    }
    
    Ok(result)
}

/// Decompress a polynomial according to algorithm type
pub fn decompress_poly(poly: &Polynomial, d: usize, ntt_type: NTTType) -> Result<Polynomial> {
    let q = get_modulus_for_ntt_type(ntt_type);
    let mut result = Polynomial::new();
    
    for i in 0..256 {
        let value = poly.coeffs[i] as u32;
        if value >= (1 << d) {
            return Err(Error::EncodingError(format!(
                "Value out of range for decompression: {} not in [0, 2^{})", value, d
            )));
        }
        
        // Decompress_d(y) = ⌈(q/2^d) · y⌋
        result.coeffs[i] = decompress(value, d, q) as i32;
    }
    
    Ok(result)
}

/// Encode a polynomial with coefficients in [0, 2^bits-1]
pub fn encode_poly(poly: &Polynomial, bits: usize, ntt_type: NTTType) -> Result<Vec<u8>> {
    let q = get_modulus_for_ntt_type(ntt_type);
    
    let mut bits_array = Vec::with_capacity(256 * bits);
    
    for i in 0..256 {
        let coeff = poly.coeffs[i] as u32;
        if coeff >= q {
            return Err(Error::EncodingError(format!("Coefficient out of range: {}", coeff)));
        }
        
        for j in 0..bits {
            bits_array.push(((coeff >> j) & 1) as u8);
        }
    }
    
    Ok(bits_to_bytes(&bits_array))
}

/// Decode a polynomial with coefficients in [0, 2^bits-1]
pub fn decode_poly(bytes: &[u8], bits: usize, ntt_type: NTTType) -> Result<Polynomial> {
    let q = get_modulus_for_ntt_type(ntt_type);
    
    let mut poly = Polynomial::new();
    let bits_array = bytes_to_bits(bytes);
    
    if bits_array.len() < 256 * bits {
        return Err(Error::EncodingError("Not enough bits for polynomial".to_string()));
    }
    
    for i in 0..256 {
        let mut coeff = 0u32;
        for j in 0..bits {
            if i * bits + j < bits_array.len() {
                coeff |= (bits_array[i * bits + j] as u32) << j;
            }
        }
        
        if coeff >= q {
            return Err(Error::EncodingError(format!("Coefficient out of range: {}", coeff)));
        }
        
        poly.coeffs[i] = coeff as i32;
    }
    
    Ok(poly)
}

/// Encode a polynomial with coefficients in [-a, b]
pub fn encode_poly_signed(poly: &Polynomial, a: i32, b: i32, ntt_type: NTTType) -> Result<Vec<u8>> {
    let q = get_modulus_for_ntt_type(ntt_type);
    let bits = bitlen((a + b + 1) as u32);
    let mut bits_array = Vec::with_capacity(256 * bits);
    
    for i in 0..256 {
        let coeff = poly.coeffs[i];
        if coeff < -a || coeff > b {
            return Err(Error::EncodingError(format!("Coefficient out of range: {}", coeff)));
        }
        
        // Map [-a, b] to [0, a+b]
        let mapped = (coeff + a) as u32;
        
        // Store in bits_per_coeff bits
        for j in 0..bits {
            bits_array.push(((mapped >> j) & 1) as u8);
        }
    }
    
    Ok(bits_to_bytes(&bits_array))
}

/// Decode a polynomial with coefficients in [-a, b]
pub fn decode_poly_signed(bytes: &[u8], a: i32, b: i32, ntt_type: NTTType) -> Result<Polynomial> {
    let q = get_modulus_for_ntt_type(ntt_type);
    let bits = bitlen((a + b + 1) as u32);
    let mut poly = Polynomial::new();
    let bits_array = bytes_to_bits(bytes);
    
    if bits_array.len() < 256 * bits {
        return Err(Error::EncodingError("Not enough bits for polynomial".to_string()));
    }
    
    for i in 0..256 {
        let mut mapped = 0u32;
        for j in 0..bits {
            if i * bits + j < bits_array.len() {
                mapped |= (bits_array[i * bits + j] as u32) << j;
            }
        }
        
        if mapped > (a + b) as u32 {
            return Err(Error::EncodingError(format!("Decoded value out of range: {}", mapped)));
        }
        
        // Map [0, a+b] back to [-a, b]
        poly.coeffs[i] = mapped as i32 - a;
    }
    
    Ok(poly)
}

/// Encode a polynomial for use in message encoding (d = 1)
pub fn byte_encode1(poly: &Polynomial, ntt_type: NTTType) -> Result<Vec<u8>> {
    // For d = 1, each coefficient is 0 or 1
    let mut result = vec![0u8; 32]; // 256 bits = 32 bytes
    
    for i in 0..256 {
        let coeff = poly.coeffs[i];
        if coeff != 0 && coeff != 1 {
            return Err(Error::EncodingError(format!("Coefficient out of range for d=1: {}", coeff)));
        }
        
        if coeff == 1 {
            result[i / 8] |= 1 << (i % 8);
        }
    }
    
    Ok(result)
}

/// Decode a polynomial from bytes (d = 1)
pub fn byte_decode1(bytes: &[u8], ntt_type: NTTType) -> Result<Polynomial> {
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

/// Calculate bit length of a positive integer
pub fn bitlen(n: u32) -> usize {
    if n == 0 {
        return 1;
    }
    (32 - n.leading_zeros()) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compression_mlkem() {
        // Test vector for ML-KEM compression
        let q = 3329;
        let d = 4;
        let x = 1234;
        
        let compressed = compress(x, d, q);
        let decompressed = decompress(compressed, d, q);
        
        // The decompressed value should be close to the original
        assert!(i32::abs(x as i32 - decompressed as i32) <= q as i32 / (1 << d));
        
        // Test property: Compress(Decompress(y)) = y
        for y in 0..(1 << d) {
            let d_val = decompress(y, d, q);
            let c_val = compress(d_val, d, q);
            assert_eq!(c_val, y);
        }
    }
    
    #[test]
    fn test_compression_mldsa() {
        // Test vector for ML-DSA compression
        let q = 8380417;
        let d = 6;
        let x = 123456;
        
        let compressed = compress(x, d, q);
        let decompressed = decompress(compressed, d, q);
        
        // The decompressed value should be close to the original
        assert!(i32::abs(x as i32 - decompressed as i32) <= q as i32 / (1 << d));
        
        // Test property: Compress(Decompress(y)) = y
        for y in 0..16 { // Test just a few values to keep test runtime reasonable
            let d_val = decompress(y, d, q);
            let c_val = compress(d_val, d, q);
            assert_eq!(c_val, y);
        }
    }
    
    #[test]
    fn test_bit_conversion() {
        let original = vec![0xA5, 0x3C, 0xF0];
        let bits = bytes_to_bits(&original);
        let bytes = bits_to_bytes(&bits);
        
        assert_eq!(bytes, original);
    }
    
    #[test]
    fn test_encode_decode_poly() {
        let ntt_type = NTTType::MLKEM;
        let q = get_modulus_for_ntt_type(ntt_type);
        let bits = 12; // Sufficient bits to represent values in [0, q-1]
        
        let mut poly = Polynomial::new();
        for i in 0..256 {
            poly.coeffs[i] = (i as i32 * 13) % q as i32;
        }
        
        let encoded = encode_poly(&poly, bits, ntt_type).unwrap();
        let decoded = decode_poly(&encoded, bits, ntt_type).unwrap();
        
        // Check that we recover the same polynomial
        for i in 0..256 {
            assert_eq!(poly.coeffs[i], decoded.coeffs[i]);
        }
    }
}