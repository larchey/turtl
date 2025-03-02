# TURTL Implementation TODO List

## Security Improvements
- [x] Enhance constant-time operations:
  - [x] Add support for larger integer types (u64, u128)
  - [ ] Implement vectorized constant-time operations for SIMD optimization
  - [ ] Fully integrate constant-time operations across all DSA components

- [ ] Strengthen fault detection:
  - [ ] Implement hardware-level fault detection mechanisms
  - [ ] Add comprehensive fault detection for DSA key generation
  - [ ] Implement double verification for all critical DSA operations
  - [x] Enhance bounds checking implementation

- [ ] Memory protection:
  - [ ] Implement advanced memory hardening beyond basic zeroize
  - [ ] Add protection for shared secrets in memory
  - [ ] Implement secure temporary value management

## Implementation Gaps
- [ ] NTT optimizations:
  - [ ] Add SIMD/vectorized optimizations for NTT transformations
  - [ ] Implement protections against cache timing attacks
  - [x] Add fault detection checks to Montgomery multiplication

## Additional Tasks
- [x] Fix index out of bounds bug in CBD sampler (k_pke.rs:450-451)
- [x] Fix KEM test vectors compatibility in unit tests

- [ ] Polynomial operations:
  - [ ] Implement polynomial multiplication outside NTT domain
  - [ ] Add constant-time polynomial comparison functions
  - [ ] Create specialized functions for small polynomial arithmetic

- [ ] Ring arithmetic:
  - [ ] Complete Montgomery implementation to support multiple moduli
  - [ ] Add field inversion operations
  - [ ] Implement optimized reduction for specific moduli

## Testing Improvements
- [ ] Add comprehensive security testing:
  - [ ] Create timing-invariance tests for constant-time operations
  - [ ] Implement fault injection simulation tests
  - [ ] Add zeroization verification tests
  - [ ] Develop side-channel resistance validation tests

- [ ] Expand operation testing:
  - [ ] Add negative test cases with corrupted inputs
  - [ ] Test randomized signing mode for ML-DSA
  - [ ] Implement full test vectors for ML-DSA-87
  - [ ] Create interoperability tests with reference implementations

- [ ] Enhance error handling tests:
  - [ ] Test proper cleanup after errors
  - [ ] Verify resistance against fault-injection during error handling
  - [ ] Add comprehensive input validation tests

- [ ] Add specialized test categories:
  - [ ] Implement fuzzing tests for input validation
  - [ ] Create memory safety tests
  - [ ] Add performance benchmarks for security features

## Feature Implementation
- [ ] Complete SIMD optimizations using the nightly feature
- [ ] Implement formal verification for critical components
- [ ] Add serialization/deserialization format compatibility checks
- [ ] Implement runtime test vector verification