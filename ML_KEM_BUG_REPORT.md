# CRITICAL BUG: ML-KEM Using Wrong Modulus

**Priority:** P0 - Blocks all ML-KEM functionality
**Discovered:** 2026-01-25
**Status:** Blocking Task #5 (ML-KEM example)

## Summary
The ML-KEM implementation in `src/kem/internal/k_pke.rs` is using the ML-DSA modulus (q=8380417) instead of the ML-KEM modulus (q=3329), causing key generation to fail.

## Evidence

### 1. Key Generation Failure
```
Running: cargo run --example kem_basic
Error: InvalidPublicKey
```

### 2. Wrong Modulus in k_pke.rs
File: `src/kem/internal/k_pke.rs`

Lines using incorrect modulus (8380417):
- Line 149: `let t1_size = k * 32 * (bitlen(8380417 - 1) - d);`
- Line 159: `let encoded = byte_encode(&t1[i], 2_u32.pow(bitlen(8380417 - 1) as u32 - d as u32) - 1)?;`
- Line 218: `let pk_size = 32 + 32 * parameter_set.k() * (bitlen(8380417 - 1) - 13);`
- Line 422: `if d1 < 8380417 {`
- Line 427: `if j < 256 && d2 < 8380417 {`

### 3. Size Calculation Mismatch

**ML-KEM-512 Expected:**
- Public key: 800 bytes
- Formula: `32 (rho) + 2 * 256 * 12 / 8 = 32 + 768 = 800`

**Current (using DSA formula):**
- Calculated: ~736 bytes
- Formula: `32 + k * 32 * (bitlen(8380417-1) - 13)`
- `bitlen(8380417-1) = 23`
- `32 + 2 * 32 * (23 - 13) = 32 + 640 = 672` (approximately)

## Root Cause

The `k_pke.rs` module appears to be adapted from ML-DSA code but was not properly updated for ML-KEM's different parameters:

| Parameter | ML-KEM | ML-DSA | Current Code |
|-----------|--------|--------|--------------|
| Modulus (q) | 3329 | 8380417 | **8380417** ❌ |
| Public key encoding | 12 bits/coeff | Variable | **Variable (DSA)** ❌ |
| Polynomial ring | Z_q[X]/(X^256+1) | Z_q[X]/(X^256+1) | ✓ |

## Required Fixes

### 1. Update k_pke.rs to use ML-KEM modulus
- Replace all instances of `8380417` with `3329`
- Update `bitlen()` calculations for ML-KEM encoding
- Fix public key encoding: ML-KEM uses 12 bits per coefficient

### 2. Correct Public Key Encoding
ML-KEM public key format (FIPS 203):
```rust
// Public key = rho || encode(t, 12)
// Size = 32 + k * 256 * 12 / 8
// ML-KEM-512: 32 + 2 * 384 = 800 bytes
// ML-KEM-768: 32 + 3 * 384 = 1184 bytes
// ML-KEM-1024: 32 + 4 * 384 = 1568 bytes
```

### 3. Fix Rejection Sampling
Update rejection sampling in NTT domain to use q=3329 bounds.

## Impact

**Blocked:**
- ✅ Task #5: ML-KEM Basic Usage Example
- Any ML-KEM functionality (key generation, encapsulation, decapsulation)
- ML-KEM interoperability testing

**Not Affected:**
- ML-DSA implementation (uses separate code path)
- Documentation tasks
- Security documentation
- API documentation

## Verification

After fixes, verify with:
```bash
cargo test --test kem_test_vectors
cargo run --example kem_basic
```

Expected output:
- All KEM tests pass
- Example runs successfully showing all 3 parameter sets
- Shared secrets match on both sides

## Related Files

**Need Modification:**
- `src/kem/internal/k_pke.rs` (primary fix)
- Possibly `src/kem/internal/aux.rs` (if helper functions affected)

**Already Correct:**
- `src/kem/params.rs` (correctly defines q=3329 via `q()` method)
- `src/kem/mod.rs` (API layer is fine)
- `examples/kem_basic.rs` (example code is correct, just needs working implementation)

## References

- FIPS 203: ML-KEM Standard
  - Section 4.1: Parameter sets (q = 3329)
  - Section 7.2: Public key encoding (12 bits per coefficient)
- Current implementation uses ML-DSA (FIPS 204) parameters instead
