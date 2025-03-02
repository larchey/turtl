# TURTL Implementation Details

This document describes the implementation details of the TURTL (Trusted Uniform Rust Toolkit for Lattice-cryptography) library, specifically focusing on the implementation of ML-KEM (NIST FIPS 203) and ML-DSA (NIST FIPS 204).

## ML-KEM Implementation

### Overview

The ML-KEM implementation follows NIST FIPS 203 and includes all parameter sets:

- ML-KEM-512 (security category 1)
- ML-KEM-768 (security category 3)
- ML-KEM-1024 (security category 5)

### Key Components

1. **Number-Theoretic Transform (NTT)**:
   - Implemented in `src/common/ntt.rs`
   - Uses the modulus q = 3329 as specified in FIPS 203
   - Includes optimized Montgomery arithmetic for fast modular operations
   - Implements the NTT algorithm exactly as described in FIPS 203

2. **Polynomial Operations**:
   - Implemented in `src/common/poly.rs`
   - Supports polynomial addition, subtraction, and multiplication
   - Includes coefficient-wise operations needed for ML-KEM

3. **Key Generation**:
   - Implemented in `src/kem/keypair.rs` and `src/kem/internal/mod.rs`
   - Follows the ML-KEM.KeyGen algorithm from FIPS 203
   - Includes optimized matrix-vector operations

4. **Encapsulation**:
   - Implemented in `src/kem/encapsulate.rs` and `src/kem/internal/mod.rs`
   - Follows the ML-KEM.Encaps algorithm from FIPS 203
   - Includes proper randomness handling

5. **Decapsulation**:
   - Implemented in `src/kem/decapsulate.rs` and `src/kem/internal/mod.rs`
   - Follows the ML-KEM.Decaps algorithm from FIPS 203
   - Includes side-channel resistant re-encryption verification

6. **Security Enhancements**:
   - Fault detection in decapsulation (src/security/fault_detection.rs)
   - Constant-time operations (src/security/constant_time.rs)
   - Memory zeroization for sensitive data

### Deviations from FIPS 203

1. **Additional Security Features**:
   - Enhanced fault attack resistance beyond the FIPS 203 requirements
   - Additional constant-time utilities for implementing secure operations

2. **Performance Optimizations**:
   - Specialized NTT implementation for improved performance
   - Optimized polynomial operations
   - Efficient Montgomery reduction with proper fault detection

## ML-DSA Implementation

### Overview

The ML-DSA implementation follows NIST FIPS 204 and includes all parameter sets:

- ML-DSA-44 (security category 2)
- ML-DSA-65 (security category 3)
- ML-DSA-87 (security category 5)

### Key Components

1. **Number-Theoretic Transform (NTT)**:
   - Shared implementation in `src/common/ntt.rs`
   - Uses the modulus q = 8380417 as specified in FIPS 204
   - Adapted for ML-DSA's specific needs
   - Uses correct primitive roots of unity for NTT operations

2. **Key Generation**:
   - Implemented in `src/dsa/keypair.rs` and `src/dsa/internal/mod.rs`
   - Follows the ML-DSA.KeyGen algorithm from FIPS 204

3. **Signing**:
   - Implemented in `src/dsa/sign.rs` and `src/dsa/internal/mod.rs`
   - Follows the ML-DSA.Sign algorithm from FIPS 204
   - Supports both deterministic and hedged signing modes

4. **Verification**:
   - Implemented in `src/dsa/verify.rs` and `src/dsa/internal/mod.rs`
   - Follows the ML-DSA.Verify algorithm from FIPS 204

5. **High-Level API**:
   - Stamp API in `src/dsa/stamp.rs` for simplified signing operations

### Deviations from FIPS 204

1. **Additional Security Features**:
   - Enhanced fault attack resistance
   - Additional constant-time utilities for implementing secure operations

2. **Performance Optimizations**:
   - Specialized implementations for improved performance

## Common Infrastructure

1. **Ring Arithmetic**:
   - Implemented in `src/common/ring.rs`
   - Provides modular arithmetic operations for both ML-KEM and ML-DSA

2. **Random Sampling**:
   - Implemented in `src/common/sample.rs`
   - Implements the CBD (centered binomial distribution) sampler
   - Provides uniform sampling utilities

3. **Hashing**:
   - Implemented in `src/common/hash.rs`
   - Uses the SHA3 family (SHAKE128/SHAKE256) as specified in FIPS 203/204

4. **Coding/Encoding**:
   - Implemented in `src/common/coding.rs`
   - Handles compression and decompression operations

5. **Error Handling**:
   - Implemented in `src/error.rs`
   - Provides comprehensive error types for all operations

## Security Considerations

See the [SECURITY.md](SECURITY.md) file for detailed information on security features and considerations.

## Future Improvements

1. **SIMD Optimizations**:
   - Use of SIMD instructions for NTT and polynomial operations
   - Platform-specific optimizations

2. **Hardware Acceleration**:
   - Support for hardware acceleration where available

3. **Memory Usage Optimizations**:
   - Reduced stack and heap usage for constrained environments