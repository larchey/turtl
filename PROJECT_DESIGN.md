# TURTL - Technical Design Document

## 1. Project Overview

### Vision
TURTL (Trusted Uniform Rust Toolkit for Lattice-cryptography) provides production-ready, pure Rust implementations of NIST's post-quantum cryptographic standards (ML-KEM and ML-DSA). The library ensures quantum-resistant security for key exchange and digital signatures while maintaining safety, performance, and side-channel resistance.

### Core Goals
1. **FIPS Compliance**: Fully conformant implementations of FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA)
2. **Security First**: Constant-time operations, fault detection, memory zeroization, no unsafe code
3. **Production Ready**: Comprehensive testing, interoperability validation, performance optimization
4. **Developer Friendly**: Clear APIs, extensive documentation, practical examples

### Non-Goals
- Classic cryptography (RSA, ECC) - focus only on post-quantum algorithms
- Hardware acceleration (SIMD/AVX512) - nice-to-have but not MVP
- Support for other PQC candidates (Kyber, Dilithium pre-NIST versions)
- GUI applications - library-only

## 2. Architecture

### High-Level Architecture
```
┌─────────────────────────────────────────────────────────┐
│                   Public API Layer                       │
│  ┌──────────────────┐        ┌──────────────────┐       │
│  │   ML-KEM API     │        │   ML-DSA API     │       │
│  │  (FIPS 203)      │        │  (FIPS 204)      │       │
│  └────────┬─────────┘        └────────┬─────────┘       │
└───────────┼──────────────────────────┼─────────────────┘
            │                          │
┌───────────┼──────────────────────────┼─────────────────┐
│           │    Internal Algorithms   │                 │
│  ┌────────▼─────────┐       ┌────────▼─────────┐       │
│  │  K-PKE (KEM)     │       │  Signing/Verify  │       │
│  │  - KeyGen        │       │  - KeyGen        │       │
│  │  - Encrypt       │       │  - Sign          │       │
│  │  - Decrypt       │       │  - Verify        │       │
│  └────────┬─────────┘       └────────┬─────────┘       │
└───────────┼──────────────────────────┼─────────────────┘
            │                          │
┌───────────┼──────────────────────────┼─────────────────┐
│           │   Common Primitives      │                 │
│  ┌────────▼──────────────────────────▼─────────┐       │
│  │  NTT (Number-Theoretic Transform)          │       │
│  │  Polynomial Arithmetic (Zq[X]/(X^256+1))   │       │
│  │  Sampling (CBD, InBall)                    │       │
│  │  Coding (Encode/Decode)                    │       │
│  │  Hash (SHAKE256, SHAKE128, SHA3-256)       │       │
│  │  Ring Arithmetic (Field ops, Montgomery)   │       │
│  └────────────────────────────────────────────┘       │
└───────────────────────────────┬─────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────┐
│              Security Layer                             │
│  - Constant-Time Operations (ct_cmov, ct_eq, etc)      │
│  - Fault Detection (bounds checks, re-verification)    │
│  - Memory Zeroization (automatic cleanup)              │
└─────────────────────────────────────────────────────────┘
```

### Components

#### Component 1: ML-KEM (Key Encapsulation Mechanism)
- **Purpose:** Quantum-resistant key exchange following FIPS 203
- **Location:** src/kem/
- **Dependencies:** common primitives, security layer
- **Key Responsibilities:**
  - Generate public/private key pairs (3 parameter sets: 512, 768, 1024)
  - Encapsulate shared secret into ciphertext
  - Decapsulate ciphertext to recover shared secret
  - Implicit rejection for IND-CCA2 security

#### Component 2: ML-DSA (Digital Signature Algorithm)
- **Purpose:** Quantum-resistant signatures following FIPS 204
- **Location:** src/dsa/
- **Dependencies:** common primitives, security layer
- **Key Responsibilities:**
  - Generate signing/verification key pairs (3 parameter sets: 44, 65, 87)
  - Sign messages with deterministic or hedged randomness
  - Verify signatures
  - Stamp API for high-level message signing

#### Component 3: Common Cryptographic Primitives
- **Purpose:** Shared algorithms used by both ML-KEM and ML-DSA
- **Location:** src/common/
- **Dependencies:** None (foundational)
- **Key Responsibilities:**
  - NTT transforms for polynomial multiplication
  - Polynomial arithmetic in quotient rings
  - Random sampling (CBD for noise, InBall for challenges)
  - Encoding/decoding with compression
  - Hash function wrappers (SHAKE, SHA3)

#### Component 4: Security Hardening
- **Purpose:** Side-channel resistance and fault protection
- **Location:** src/security/
- **Dependencies:** None (used by all components)
- **Key Responsibilities:**
  - Constant-time conditional operations
  - Timing-safe equality checks
  - Fault injection detection
  - Automatic memory zeroization

## 3. Technical Stack

### Language & Framework
- **Primary Language:** Rust
- **Version:** 1.93+ (2024 edition)
- **Compiler:** Rust stable (no nightly required for core functionality)

### Key Dependencies
```toml
# Cryptographic Primitives
sha3 = "0.10"              # SHAKE256, SHAKE128, SHA3-256
rand_core = "0.6"           # Randomness abstraction (no_std compatible)
zeroize = { version = "1", features = ["derive"] }  # Memory safety

# Development Dependencies
criterion = "0.5"           # Benchmarking
rand = "0.8"                # Test randomness
```

### Development Tools
- **Build:** cargo (Rust's build system)
- **Test:** cargo test (built-in test framework)
- **Lint:** cargo clippy (Rust linter)
- **Format:** cargo fmt / rustfmt (Rust formatter)
- **Audit:** cargo audit (dependency vulnerability scanner)

## 4. Data Model

### Key Data Structures

```rust
// ML-KEM Types
pub struct KemPublicKey {
    pub param: KemParam,       // Parameter set (512/768/1024)
    pub key: Vec<u8>,          // Raw public key bytes
}

pub struct KemPrivateKey {
    pub param: KemParam,       // Parameter set
    pub key: Vec<u8>,          // Raw private key bytes (auto-zeroized)
}

pub struct KemCiphertext {
    pub param: KemParam,       // Parameter set
    pub data: Vec<u8>,         // Ciphertext bytes
}

pub struct SharedSecret([u8; 32]);  // Shared secret (auto-zeroized)

// ML-DSA Types
pub struct DsaPublicKey {
    pub param: DsaParam,       // Parameter set (44/65/87)
    pub key: Vec<u8>,          // Raw public key bytes
}

pub struct DsaPrivateKey {
    pub param: DsaParam,       // Parameter set
    pub key: Vec<u8>,          // Raw private key bytes (auto-zeroized)
}

pub struct Signature {
    pub param: DsaParam,       // Parameter set
    pub data: Vec<u8>,         // Signature bytes
}

// Internal Polynomial Representation
pub struct Polynomial {
    pub coeffs: Vec<i32>,      // 256 coefficients in Zq
}

// Parameter Sets
pub enum KemParam {
    Kem512,   // Security category 1 (128-bit)
    Kem768,   // Security category 3 (192-bit)
    Kem1024,  // Security category 5 (256-bit)
}

pub enum DsaParam {
    Dsa44,    // Security category 2 (128-bit)
    Dsa65,    // Security category 3 (192-bit)
    Dsa87,    // Security category 5 (256-bit)
}
```

## 5. API Design

### Public API - ML-KEM

```rust
// Key Generation
pub fn kem_keygen(param: KemParam) -> Result<(KemPublicKey, KemPrivateKey)>;

// Encapsulation
pub fn kem_encapsulate(pk: &KemPublicKey) -> Result<(KemCiphertext, SharedSecret)>;

// Decapsulation
pub fn kem_decapsulate(sk: &KemPrivateKey, ct: &KemCiphertext) -> Result<SharedSecret>;

// Parameter set utilities
impl KemParam {
    pub fn public_key_size(&self) -> usize;
    pub fn private_key_size(&self) -> usize;
    pub fn ciphertext_size(&self) -> usize;
    pub fn security_level(&self) -> u8;  // 1, 3, or 5
}
```

### Public API - ML-DSA

```rust
// Key Generation
pub fn dsa_keygen(param: DsaParam) -> Result<(DsaPublicKey, DsaPrivateKey)>;

// Signing (deterministic)
pub fn dsa_sign(sk: &DsaPrivateKey, message: &[u8], context: &[u8]) -> Result<Signature>;

// Signing (hedged - includes fresh randomness)
pub fn dsa_sign_hedged(
    sk: &DsaPrivateKey,
    message: &[u8],
    context: &[u8],
    rng: &mut impl CryptoRng
) -> Result<Signature>;

// Verification
pub fn dsa_verify(
    pk: &DsaPublicKey,
    message: &[u8],
    context: &[u8],
    signature: &Signature
) -> Result<bool>;

// High-level Stamp API
pub struct Stamp {
    private_key: DsaPrivateKey,
}

impl Stamp {
    pub fn new(param: DsaParam) -> Result<Self>;
    pub fn sign(&self, message: &[u8]) -> Result<Signature>;
    pub fn public_key(&self) -> DsaPublicKey;
}
```

### Internal APIs (src/common/)

```rust
// NTT Operations
pub fn ntt_forward(poly: &Polynomial, param: NttParam) -> Polynomial;
pub fn ntt_inverse(poly: &Polynomial, param: NttParam) -> Polynomial;

// Polynomial Operations
impl Polynomial {
    pub fn add(&self, other: &Polynomial, q: i32) -> Polynomial;
    pub fn sub(&self, other: &Polynomial, q: i32) -> Polynomial;
    pub fn mul_scalar(&self, scalar: i32, q: i32) -> Polynomial;
    pub fn inf_norm(&self, q: i32) -> i32;
}

// Sampling
pub fn cbd_sample(bytes: &[u8], eta: u8) -> Polynomial;
pub fn sample_in_ball(seed: &[u8], tau: u16) -> Polynomial;

// Coding
pub fn encode(poly: &Polynomial, bits: u8) -> Vec<u8>;
pub fn decode(bytes: &[u8], bits: u8) -> Polynomial;
```

## 6. Security Model

### Threat Model
We protect against:
- **Quantum attacks:** Shor's algorithm, Grover's algorithm
- **Side-channel attacks:** Timing attacks, cache-timing, power analysis
- **Fault injection attacks:** Glitching, laser fault injection
- **Memory disclosure:** RAM dumps, process memory scanning
- **Invalid inputs:** Malformed keys, tampered ciphertexts/signatures

### Security Measures

1. **Constant-Time Operations**
   - All secret-dependent branches replaced with bitwise masking
   - Functions: `ct_cmov()`, `ct_cswap()`, `ct_select()`, `ct_eq()`
   - Applied in: key derivation, decryption, signature verification

2. **Memory Zeroization**
   - All `Polynomial`, `PrivateKey`, `SharedSecret` types implement `Zeroize`
   - Automatic cleanup via `ZeroizeOnDrop` trait
   - Prevents secrets lingering in memory

3. **Fault Detection**
   - Double verification in signature checks
   - Re-encryption validation in KEM decapsulation
   - Bounds checking on polynomial coefficients

4. **Input Validation**
   - Validate all public key/ciphertext/signature sizes
   - Check parameter set consistency
   - Context length limits (max 255 bytes per FIPS 204)

5. **No Unsafe Code**
   - `#![forbid(unsafe_code)]` at crate root
   - All operations rely on safe Rust guarantees

### Secrets Management
- Private keys stored in heap-allocated `Vec<u8>` with `Zeroize`
- Shared secrets stored in fixed-size arrays with `Zeroize`
- No secrets in function return positions (moved ownership)
- Random number generation via `rand_core::CryptoRng` trait

## 7. Configuration

### Compile-Time Feature Flags
```toml
[features]
default = ["std"]
std = []                    # Standard library support
nightly = []                # Nightly-only optimizations (future)
```

### No Runtime Configuration
TURTL is a library with no configuration files. All parameters are specified via API:
- Parameter sets chosen at key generation time
- Context strings provided per-operation
- Hedged vs deterministic signing chosen by function call

## 8. Error Handling

### Error Types
```rust
pub enum TurtlError {
    InvalidParameter,              // Wrong parameter set
    InvalidPublicKeySize,          // Public key size mismatch
    InvalidPrivateKeySize,         // Private key size mismatch
    InvalidCiphertextSize,         // Ciphertext size mismatch
    InvalidSignatureSize,          // Signature size mismatch
    InvalidMessageSize,            // Message too long
    InvalidContextSize,            // Context string >255 bytes
    PolynomialCoeffOutOfRange,     // Coefficient outside valid range
    SamplingFailure,               // Sampling rejection limit hit
    RandomnessError,               // RNG failure or signing retry limit
    VerificationFailure,           // Signature verification failed
    HashError,                     // Hash function failure
    EncodingError,                 // Encode/decode failure
    InternalError,                 // Unexpected internal state
}
```

### Error Response Format
All errors are returned via `Result<T, TurtlError>`. No panics in production code (except arithmetic overflow bugs, which are developer errors).

## 9. Testing Strategy

### Unit Tests
- Inline `#[cfg(test)]` modules in each source file
- Test individual functions: NTT, polynomial ops, sampling, encoding
- **Target:** 90%+ line coverage per module

### Integration Tests
- Located in `tests/` directory
- Test complete workflows: keygen → sign → verify, keygen → encaps → decaps
- NIST test vectors from FIPS 203/204
- **Files:**
  - `kem_test_vectors.rs` - ML-KEM NIST vectors
  - `dsa_test_vectors.rs` - ML-DSA NIST vectors
  - `negative_test_cases.rs` - Invalid input handling
  - `security_test.rs` - Security properties

### Security Tests
- `constant_time_test.rs` - Verify constant-time operations
- `timing_invariance_test.rs` - Statistical timing tests (marked #[ignore])
- `fault_injection_test.rs` - Fault detection mechanisms
- `zeroization_test.rs` - Memory cleanup verification

### Test Coverage Goals
- **common/**: 90%+ coverage
- **kem/**: 85%+ coverage (critical path)
- **dsa/**: 85%+ coverage (critical path)
- **security/**: 95%+ coverage (security-critical)
- **Overall:** 85%+ minimum

## 10. Performance Requirements

### Latency (Target on modern x86_64 CPU)
- ML-KEM-768 KeyGen: < 100μs
- ML-KEM-768 Encapsulate: < 120μs
- ML-KEM-768 Decapsulate: < 140μs
- ML-DSA-65 KeyGen: < 200μs
- ML-DSA-65 Sign: < 1ms (with rejection sampling)
- ML-DSA-65 Verify: < 250μs

### Memory Usage
- ML-KEM-768: < 10KB stack per operation
- ML-DSA-65: < 15KB stack per operation
- No heap allocations in hot paths (except key storage)

### Throughput
- Sign 1000+ messages/second (ML-DSA-65)
- Encapsulate 5000+ shared secrets/second (ML-KEM-768)

## 11. Deployment

### Build Process
```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# no_std build (embedded)
cargo build --no-default-features
```

### Integration
TURTL is a library crate. Users add it to their `Cargo.toml`:
```toml
[dependencies]
turtl = "0.1"
```

### Runtime Dependencies
- None (pure Rust, statically linked)
- Requires system RNG for randomness (`getrandom` crate)

## 12. Observability

### Logging
- No built-in logging (library design choice)
- Users can wrap API calls with their own logging
- Errors are returned, not logged

### Metrics
Users should measure:
- Operation latency (keygen, sign, verify, encaps, decaps)
- Success/failure rates
- Memory usage

### Monitoring
For production deployments:
- Monitor signature verification failure rates (detect attack attempts)
- Track operation latencies (detect performance degradation)
- Audit RNG failures (critical security issue)

## 13. File Structure

```
turtl/
├── src/
│   ├── lib.rs                          # Crate root, module exports
│   ├── error.rs                        # Error type definitions
│   ├── common/                         # Shared primitives
│   │   ├── mod.rs                      # Module exports
│   │   ├── ntt.rs                      # NTT forward/inverse
│   │   ├── poly.rs                     # Polynomial arithmetic
│   │   ├── sample.rs                   # CBD, InBall sampling
│   │   ├── coding.rs                   # Encode/decode
│   │   ├── hash.rs                     # SHAKE/SHA3 wrappers
│   │   └── ring.rs                     # Field arithmetic
│   ├── kem/                            # ML-KEM (FIPS 203)
│   │   ├── mod.rs                      # Public API
│   │   ├── params.rs                   # Parameter sets
│   │   ├── keypair.rs                  # Key generation
│   │   ├── encapsulate.rs              # Encapsulation
│   │   ├── decapsulate.rs              # Decapsulation
│   │   ├── shell.rs                    # Key derivation
│   │   └── internal/                   # Internal algorithms
│   │       ├── mod.rs                  # K-PKE algorithms
│   │       ├── k_pke.rs                # PKE component
│   │       └── aux.rs                  # Helper functions
│   ├── dsa/                            # ML-DSA (FIPS 204)
│   │   ├── mod.rs                      # Public API
│   │   ├── params.rs                   # Parameter sets
│   │   ├── keypair.rs                  # Key generation
│   │   ├── sign.rs                     # Signing algorithm
│   │   ├── verify.rs                   # Verification algorithm
│   │   ├── stamp.rs                    # High-level Stamp API
│   │   └── internal/                   # Internal algorithms
│   │       └── mod.rs                  # Signing/verification internals
│   └── security/                       # Security hardening
│       ├── mod.rs                      # Module exports
│       ├── constant_time.rs            # CT operations
│       └── fault_detection.rs          # Fault resistance
├── tests/                              # Integration tests
│   ├── kem_test_vectors.rs             # ML-KEM NIST vectors
│   ├── dsa_test_vectors.rs             # ML-DSA NIST vectors
│   ├── constant_time_test.rs           # CT operation tests
│   ├── timing_invariance_test.rs       # Statistical timing tests
│   ├── fault_injection_test.rs         # Fault detection tests
│   ├── zeroization_test.rs             # Memory safety tests
│   ├── negative_test_cases.rs          # Error handling tests
│   ├── security_test.rs                # General security tests
│   ├── ntt_roundtrip_test.rs           # NTT diagnostics
│   └── error_handling_test.rs          # Error path coverage
├── benches/                            # Performance benchmarks
│   ├── kem_benchmark.rs                # ML-KEM benchmarks
│   ├── dsa_benchmark.rs                # ML-DSA benchmarks
│   └── ntt_benchmark.rs                # NTT performance
├── examples/                           # Usage examples (TO CREATE)
│   ├── kem_basic.rs                    # Simple KEM usage
│   ├── dsa_basic.rs                    # Simple DSA usage
│   └── hedged_signing.rs               # Hedged vs deterministic
├── docs/                               # Additional documentation (TO CREATE)
│   ├── SECURITY.md                     # Security considerations
│   ├── INTEROP.md                      # Interoperability testing
│   └── PERFORMANCE.md                  # Performance guide
├── Cargo.toml                          # Package manifest
├── README.md                           # User documentation
├── CLAUDE.md                           # Developer guidelines
├── AUDIT_SUMMARY.md                    # Security audit findings
└── TODO.md                             # Work tracking
```

## 14. Development Phases

### Phase 1: Core Fixes (CRITICAL - Week 1)
**Goal:** Make ML-DSA functional

- Task #1: Fix ML-DSA NTT implementation (compare with FIPS 204 Section 8.4)
- Task #2: Verify ML-DSA signing works with all 3 parameter sets
- Task #3: Fix failing negative test cases
- Task #4: Add NTT correctness tests (roundtrip, known vector validation)

### Phase 2: Documentation & Examples (Week 2)
**Goal:** Make library usable by developers

- Task #5: Create ML-KEM basic usage example (examples/kem_basic.rs)
- Task #6: Create ML-DSA basic usage example (examples/dsa_basic.rs)
- Task #7: Write SECURITY.md documentation
- Task #8: Create hedged signing example (examples/hedged_signing.rs)
- Task #9: Improve README with quickstart guide
- Task #10: Add API documentation (rustdoc comments)

### Phase 3: Validation & Testing (Week 3)
**Goal:** Ensure production readiness

- Task #11: ML-KEM interoperability tests (test against reference implementation)
- Task #12: ML-DSA interoperability tests (test against reference implementation)
- Task #13: Security audit documentation (expand SECURITY.md)
- Task #14: Benchmark optimization baseline (document current performance)
- Task #15: Add fuzzing infrastructure (AFL/libFuzzer/cargo-fuzz)

### Phase 4: Optimization (Week 4+)
**Goal:** Improve performance while maintaining security

- Task #16: Profile NTT performance bottlenecks
- Task #17: Optimize polynomial multiplication (consider Karatsuba)
- Task #18: Add SIMD/AVX2 NTT implementation (behind feature flag)
- Task #19: Optimize memory allocations (reduce heap usage)
- Task #20: Benchmark comparison with reference implementations

## 15. Open Questions

1. **Should we support no_std completely?**
   - Currently requires `alloc` for vectors
   - Could provide fixed-size array APIs for embedded use

2. **SIMD optimization priority?**
   - Significant speedup potential (2-4x)
   - Adds complexity and platform-specific code
   - Consider after core functionality is solid

3. **Interoperability test strategy?**
   - Need reference implementation test vectors
   - Consider using official NIST KAT (Known Answer Tests)
   - Test cross-implementation compatibility

4. **Fuzzing coverage?**
   - Which modules to fuzz first?
   - Integration with CI/CD?

5. **Constant-time validation tools?**
   - Use valgrind/cachegrind for timing leak detection?
   - Automated CT testing in CI?

## 16. References

- [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Kyber/Dilithium Reference Implementations](https://github.com/pq-crystals/)
- [Rust Crypto Project](https://github.com/RustCrypto)
- [Side-Channel Resistance in Rust](https://www.chosenplaintext.ca/articles/rust-timing.html)

---

**Version:** 1.0
**Last Updated:** 2026-01-25
**Status:** Final (Ready for autonomous development)
