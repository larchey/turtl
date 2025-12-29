# TURTL Implementation TODO List

## Recent Improvements (Code Audit - December 2025)

### Benchmarks
- [x] Implement complete ML-KEM benchmarks (key_gen, encapsulate, decapsulate) for all 3 parameter sets
- [x] Implement complete ML-DSA benchmarks (key_gen, sign, verify) for all 3 parameter sets
- [x] Add hedged and deterministic signing mode benchmarks
- [x] Fix RNG/RandomnessError issues in benchmark implementations

### Security Testing
- [x] Add 11 timing-invariance tests for constant-time operations (marked #[ignore] due to system noise)
- [x] Add 16 fault injection simulation tests covering bit flips, corruption detection, and bounds checking
- [x] Add 14 zeroization verification tests for memory safety
- [x] Test constant-time equality, conditional operations, and swaps across u32/u64/u128/u8

### Test Infrastructure
- [x] Create comprehensive test documentation with usage instructions
- [x] Add warmup and statistical analysis for timing tests
- [x] Test zeroization of arrays, vectors, strings, structs, and nested types
- [x] Test automatic cleanup in panic scenarios

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
- [x] NTT optimizations:
  - [ ] Add SIMD/vectorized optimizations for NTT transformations
  - [ ] Implement protections against cache timing attacks
  - [x] Add fault detection checks to Montgomery multiplication
  - [x] Fix ML-KEM NTT implementation to match FIPS 203 specification
  - [x] Fix ML-DSA zetas table with correct primitive roots of unity

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
- [x] Add comprehensive security testing:
  - [x] Create timing-invariance tests for constant-time operations (11 tests, #[ignore] by default)
  - [x] Implement fault injection simulation tests (16 tests covering corruption scenarios)
  - [x] Add zeroization verification tests (14 tests for memory safety)
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
  - [x] Create memory safety tests (14 zeroization tests)
  - [x] Add performance benchmarks for security features (KEM and DSA benchmarks)

## Feature Implementation
- [ ] Complete SIMD optimizations using the nightly feature
- [ ] Implement formal verification for critical components
- [ ] Add serialization/deserialization format compatibility checks
- [ ] Implement runtime test vector verification