//! Constant-Time Operations
//! 
//! This module provides utilities for performing operations in constant time,
//! which is essential for preventing timing side-channel attacks.
//! 
//! Timing attacks extract secret information by measuring the time taken by
//! cryptographic operations. These utilities ensure that the time taken is
//! independent of the secret data being processed.

/// Performs a constant-time conditional move.
/// 
/// Sets `r := x` if `cond` is true, otherwise leaves `r` unchanged.
/// This operation is performed in constant time regardless of the value of `cond`.
/// 
/// # Arguments
/// 
/// * `r` - The destination value (modified in-place)
/// * `x` - The source value
/// * `cond` - The condition (true or false)
#[inline]
pub fn ct_cmov(r: &mut u32, x: u32, cond: bool) {
    // Convert bool to a mask (0x00000000 or 0xffffffff)
    let mask = if cond { 0xffffffff } else { 0 };
    
    // Use bitwise operations to perform conditional move in constant time
    *r = (*r & !mask) | (x & mask);
}

/// Performs a constant-time conditional move for 64-bit integers.
/// 
/// Sets `r := x` if `cond` is true, otherwise leaves `r` unchanged.
/// This operation is performed in constant time regardless of the value of `cond`.
/// 
/// # Arguments
/// 
/// * `r` - The destination value (modified in-place)
/// * `x` - The source value
/// * `cond` - The condition (true or false)
#[inline]
pub fn ct_cmov_u64(r: &mut u64, x: u64, cond: bool) {
    // Convert bool to a mask (0x0000000000000000 or 0xffffffffffffffff)
    let mask = if cond { 0xffffffffffffffff } else { 0 };
    
    // Use bitwise operations to perform conditional move in constant time
    *r = (*r & !mask) | (x & mask);
}

/// Performs a constant-time conditional move for 128-bit integers.
/// 
/// Sets `r := x` if `cond` is true, otherwise leaves `r` unchanged.
/// This operation is performed in constant time regardless of the value of `cond`.
/// 
/// # Arguments
/// 
/// * `r` - The destination value (modified in-place)
/// * `x` - The source value
/// * `cond` - The condition (true or false)
#[inline]
pub fn ct_cmov_u128(r: &mut u128, x: u128, cond: bool) {
    // Convert bool to a mask
    let mask = if cond { u128::MAX } else { 0 };
    
    // Use bitwise operations to perform conditional move in constant time
    *r = (*r & !mask) | (x & mask);
}

/// Performs a constant-time conditional move for bytes.
/// 
/// Sets `r := x` if `cond` is true, otherwise leaves `r` unchanged.
/// This operation is performed in constant time regardless of the value of `cond`.
/// 
/// # Arguments
/// 
/// * `r` - The destination value (modified in-place)
/// * `x` - The source value
/// * `cond` - The condition (true or false)
#[inline]
pub fn ct_cmov_byte(r: &mut u8, x: u8, cond: bool) {
    // Convert bool to a mask (0x00 or 0xff)
    let mask = if cond { 0xff } else { 0 };
    
    // Use bitwise operations to perform conditional move in constant time
    *r = (*r & !mask) | (x & mask);
}

/// Performs a constant-time conditional swap.
/// 
/// Swaps `a` and `b` if `cond` is true, otherwise leaves them unchanged.
/// This operation is performed in constant time regardless of the value of `cond`.
/// 
/// # Arguments
/// 
/// * `a` - First value (may be modified)
/// * `b` - Second value (may be modified)
/// * `cond` - The condition (true or false)
#[inline]
pub fn ct_cswap(a: &mut u32, b: &mut u32, cond: bool) {
    // Convert bool to a mask (0x00000000 or 0xffffffff)
    let mask = if cond { 0xffffffff } else { 0 };
    
    // Use bitwise operations to perform conditional swap in constant time
    let t = mask & (*a ^ *b);
    *a ^= t;
    *b ^= t;
}

/// Performs a constant-time conditional swap for 64-bit integers.
/// 
/// Swaps `a` and `b` if `cond` is true, otherwise leaves them unchanged.
/// This operation is performed in constant time regardless of the value of `cond`.
/// 
/// # Arguments
/// 
/// * `a` - First value (may be modified)
/// * `b` - Second value (may be modified)
/// * `cond` - The condition (true or false)
#[inline]
pub fn ct_cswap_u64(a: &mut u64, b: &mut u64, cond: bool) {
    // Convert bool to a mask (0x0000000000000000 or 0xffffffffffffffff)
    let mask = if cond { 0xffffffffffffffff } else { 0 };
    
    // Use bitwise operations to perform conditional swap in constant time
    let t = mask & (*a ^ *b);
    *a ^= t;
    *b ^= t;
}

/// Performs a constant-time conditional swap for 128-bit integers.
/// 
/// Swaps `a` and `b` if `cond` is true, otherwise leaves them unchanged.
/// This operation is performed in constant time regardless of the value of `cond`.
/// 
/// # Arguments
/// 
/// * `a` - First value (may be modified)
/// * `b` - Second value (may be modified)
/// * `cond` - The condition (true or false)
#[inline]
pub fn ct_cswap_u128(a: &mut u128, b: &mut u128, cond: bool) {
    // Convert bool to a mask
    let mask = if cond { u128::MAX } else { 0 };
    
    // Use bitwise operations to perform conditional swap in constant time
    let t = mask & (*a ^ *b);
    *a ^= t;
    *b ^= t;
}

/// Performs a constant-time conditional swap for bytes.
/// 
/// Swaps `a` and `b` if `cond` is true, otherwise leaves them unchanged.
/// This operation is performed in constant time regardless of the value of `cond`.
/// 
/// # Arguments
/// 
/// * `a` - First value (may be modified)
/// * `b` - Second value (may be modified)
/// * `cond` - The condition (true or false)
#[inline]
pub fn ct_cswap_byte(a: &mut u8, b: &mut u8, cond: bool) {
    // Convert bool to a mask (0x00 or 0xff)
    let mask = if cond { 0xff } else { 0 };
    
    // Use bitwise operations to perform conditional swap in constant time
    let t = mask & (*a ^ *b);
    *a ^= t;
    *b ^= t;
}

/// Performs a constant-time conditional swap for byte slices.
/// 
/// Swaps the contents of `a` and `b` if `cond` is true, otherwise leaves them unchanged.
/// This operation is performed in constant time regardless of the value of `cond`.
/// 
/// # Arguments
/// 
/// * `a` - First byte slice (may be modified)
/// * `b` - Second byte slice (may be modified)
/// * `cond` - The condition (true or false)
/// 
/// # Panics
/// 
/// Panics if `a` and `b` have different lengths.
#[inline]
pub fn ct_cswap_slice(a: &mut [u8], b: &mut [u8], cond: bool) {
    assert_eq!(a.len(), b.len(), "Slices must have the same length");
    
    // Convert bool to a mask (0x00 or 0xff)
    let mask = if cond { 0xff } else { 0 };
    
    // Perform conditional swap on each byte
    for (x, y) in a.iter_mut().zip(b.iter_mut()) {
        let t = mask & (*x ^ *y);
        *x ^= t;
        *y ^= t;
    }
}

/// Performs a constant-time selection between two values.
/// 
/// Returns `x` if `cond` is true, otherwise returns `y`.
/// This operation is performed in constant time regardless of the value of `cond`.
/// 
/// # Arguments
/// 
/// * `x` - First value
/// * `y` - Second value
/// * `cond` - The condition (true or false)
/// 
/// # Returns
/// 
/// `x` if `cond` is true, `y` otherwise
#[inline]
pub fn ct_select(x: u32, y: u32, cond: bool) -> u32 {
    // Convert bool to a mask (0x00000000 or 0xffffffff)
    let mask = if cond { 0xffffffff } else { 0 };
    
    // Use bitwise operations to perform selection in constant time
    (x & mask) | (y & !mask)
}

/// Performs a constant-time selection between two 64-bit integer values.
/// 
/// Returns `x` if `cond` is true, otherwise returns `y`.
/// This operation is performed in constant time regardless of the value of `cond`.
/// 
/// # Arguments
/// 
/// * `x` - First value
/// * `y` - Second value
/// * `cond` - The condition (true or false)
/// 
/// # Returns
/// 
/// `x` if `cond` is true, `y` otherwise
#[inline]
pub fn ct_select_u64(x: u64, y: u64, cond: bool) -> u64 {
    // Convert bool to a mask (0x0000000000000000 or 0xffffffffffffffff)
    let mask = if cond { 0xffffffffffffffff } else { 0 };
    
    // Use bitwise operations to perform selection in constant time
    (x & mask) | (y & !mask)
}

/// Performs a constant-time selection between two 128-bit integer values.
/// 
/// Returns `x` if `cond` is true, otherwise returns `y`.
/// This operation is performed in constant time regardless of the value of `cond`.
/// 
/// # Arguments
/// 
/// * `x` - First value
/// * `y` - Second value
/// * `cond` - The condition (true or false)
/// 
/// # Returns
/// 
/// `x` if `cond` is true, `y` otherwise
#[inline]
pub fn ct_select_u128(x: u128, y: u128, cond: bool) -> u128 {
    // Convert bool to a mask
    let mask = if cond { u128::MAX } else { 0 };
    
    // Use bitwise operations to perform selection in constant time
    (x & mask) | (y & !mask)
}

/// Performs a constant-time selection between two byte values.
/// 
/// Returns `x` if `cond` is true, otherwise returns `y`.
/// This operation is performed in constant time regardless of the value of `cond`.
/// 
/// # Arguments
/// 
/// * `x` - First value
/// * `y` - Second value
/// * `cond` - The condition (true or false)
/// 
/// # Returns
/// 
/// `x` if `cond` is true, `y` otherwise
#[inline]
pub fn ct_select_byte(x: u8, y: u8, cond: bool) -> u8 {
    // Convert bool to a mask (0x00 or 0xff)
    let mask = if cond { 0xff } else { 0 };
    
    // Use bitwise operations to perform selection in constant time
    (x & mask) | (y & !mask)
}

/// Tests if two values are equal in constant time.
/// 
/// # Arguments
/// 
/// * `x` - First value
/// * `y` - Second value
/// 
/// # Returns
/// 
/// `true` if `x == y`, `false` otherwise
#[inline]
pub fn ct_eq_u32(x: u32, y: u32) -> bool {
    // XOR the values - will be 0 if equal
    let diff = x ^ y;
    
    // If diff is 0, then x and y are equal
    diff == 0
}

/// Tests if two 64-bit values are equal in constant time.
/// 
/// # Arguments
/// 
/// * `x` - First value
/// * `y` - Second value
/// 
/// # Returns
/// 
/// `true` if `x == y`, `false` otherwise
#[inline]
pub fn ct_eq_u64(x: u64, y: u64) -> bool {
    // XOR the values - will be 0 if equal
    let diff = x ^ y;
    
    // If diff is 0, then x and y are equal
    diff == 0
}

/// Tests if two 128-bit values are equal in constant time.
/// 
/// # Arguments
/// 
/// * `x` - First value
/// * `y` - Second value
/// 
/// # Returns
/// 
/// `true` if `x == y`, `false` otherwise
#[inline]
pub fn ct_eq_u128(x: u128, y: u128) -> bool {
    // XOR the values - will be 0 if equal
    let diff = x ^ y;
    
    // If diff is 0, then x and y are equal
    diff == 0
}

/// Tests if a value is zero in constant time.
/// 
/// # Arguments
/// 
/// * `x` - The value to test
/// 
/// # Returns
/// 
/// `true` if `x == 0`, `false` otherwise
#[inline]
pub fn ct_is_zero_u32(x: u32) -> bool {
    // Compute (x - 1) & ~x
    // If x is 0, this will be 0xffffffff, otherwise it will be < 0xffffffff
    let y = x.wrapping_sub(1);
    let z = !x & y;
    
    // Extract the high bit
    (z >> 31) == 1
}

/// Tests if a 64-bit value is zero in constant time.
/// 
/// # Arguments
/// 
/// * `x` - The value to test
/// 
/// # Returns
/// 
/// `true` if `x == 0`, `false` otherwise
#[inline]
pub fn ct_is_zero_u64(x: u64) -> bool {
    // Compute (x - 1) & ~x
    // If x is 0, this will be 0xffffffffffffffff, otherwise it will be < 0xffffffffffffffff
    let y = x.wrapping_sub(1);
    let z = !x & y;
    
    // Extract the high bit
    (z >> 63) == 1
}

/// Tests if a 128-bit value is zero in constant time.
/// 
/// # Arguments
/// 
/// * `x` - The value to test
/// 
/// # Returns
/// 
/// `true` if `x == 0`, `false` otherwise
#[inline]
pub fn ct_is_zero_u128(x: u128) -> bool {
    // Compute (x - 1) & ~x
    // If x is 0, this will be u128::MAX, otherwise it will be < u128::MAX
    let y = x.wrapping_sub(1);
    let z = !x & y;
    
    // Extract the high bit
    (z >> 127) == 1
}

/// Tests if a value is zero in constant time for bytes.
/// 
/// # Arguments
/// 
/// * `x` - The value to test
/// 
/// # Returns
/// 
/// `true` if `x == 0`, `false` otherwise
#[inline]
pub fn ct_is_zero_u8(x: u8) -> bool {
    // Compute (x - 1) & ~x
    // If x is 0, this will be 0xff, otherwise it will be < 0xff
    let y = x.wrapping_sub(1);
    let z = !x & y;
    
    // Extract the high bit
    (z >> 7) == 1
}