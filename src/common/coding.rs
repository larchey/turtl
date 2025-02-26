//! Encoding and decoding functions for ML-KEM and ML-DSA.
//! 
//! This module implements shared encoding and decoding operations
//! used by both ML-KEM and ML-DSA.

use crate::error::{Error, Result};
use crate::common::poly::Polynomial;

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

/// Encode a polynomial with coefficients in [0, 2^bits-1]
pub fn encode_poly(poly: &Polynomial, bits: usize) -> Result<Vec<u8>> {
    let mut bits_array = Vec::with_capacity(256 * bits);
    
    for i in 0..256 {
        let coeff = poly.coeffs[i] as u32;
        for j in 0..bits {
            bits_array.push(((coeff >> j) & 1) as u8);
        }
    }
    
    Ok(bits_to_bytes(&bits_array))
}

/// Decode a polynomial with coefficients in [0, 2^bits-1]
pub fn decode_poly(bytes: &[u8], bits: usize) -> Result<Polynomial> {
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
        poly.coeffs[i] = coeff as i32;
    }
    
    Ok(poly)
}

/// Encode a polynomial with coefficients in [-a, b]
pub fn encode_poly_signed(poly: &Polynomial, a: usize, b: usize) -> Result<Vec<u8>> {
    let bits = bitlen(a + b);
    let mut bits_array = Vec::with_capacity(256 * bits);
    
    for i in 0..256 {
        let coeff = (poly.coeffs[i] + (a as i32)) as u32;
        for j in 0..bits {
            bits_array.push(((coeff >> j) & 1) as u8);
        }
    }
    
    Ok(bits_to_bytes(&bits_array))
}

/// Decode a polynomial with coefficients in [-a, b]
pub fn decode_poly_signed(bytes: &[u8], a: usize, b: usize) -> Result<Polynomial> {
    let bits = bitlen(a + b);
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
        poly.coeffs[i] = (coeff as i32) - (a as i32);
    }
    
    Ok(poly)
}

/// Encode a sparse polynomial (with hints)
pub fn encode_sparse_poly(poly: &Polynomial) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    
    // Count non-zero positions
    let mut positions = Vec::new();
    for i in 0..256 {
        if poly.coeffs[i] != 0 {
            positions.push(i);
        }
    }
    
    // Store the number of non-zero positions
    result.push(positions.len() as u8);
    
    // Store the positions
    for pos in positions {
        result.push(pos as u8);
        // If pos > 255, we'd need to handle this differently
    }
    
    Ok(result)
}

/// Decode a sparse polynomial (with hints)
pub fn decode_sparse_poly(bytes: &[u8]) -> Result<Polynomial> {
    let mut poly = Polynomial::new();
    
    if bytes.is_empty() {
        return Err(Error::EncodingError("Empty byte array".to_string()));
    }
    
    let num_positions = bytes[0] as usize;
    
    if bytes.len() < 1 + num_positions {
        return Err(Error::EncodingError("Byte array too short".to_string()));
    }
    
    for i in 0..num_positions {
        let pos = bytes[i + 1] as usize;
        poly.coeffs[pos] = 1;
    }
    
    Ok(poly)
}

/// Calculate bit length of a positive integer
pub fn bitlen(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    (n as f64).log2().ceil() as usize
}

/// ML-KEM/ML-DSA Compression function
pub fn compress(x: u32, d: usize, q: u32) -> u32 {
    ((((1u64 << d) * x as u64 + q as u64 / 2) / q as u64) % (1u64 << d)) as u32
}

/// ML-KEM/ML-DSA Decompression function
pub fn decompress(x: u32, d: usize, q: u32) -> u32 {
    ((q as u64 * x as u64 + (1u64 << (d - 1))) >> d) as u32
}