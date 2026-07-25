# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-07-25

### Added

- **ML-KEM (FIPS 203)**: Full implementation with all three parameter sets (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
- **ML-DSA (FIPS 204)**: Full implementation with all three parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87)
- **Deterministic APIs**: Deterministic encapsulation and signing for reproducible testing and hardened protocols
- **FIPS Conformance**: Byte-for-byte compliance with NIST test vectors (KAT cross-checks against reference implementations)
- **Fault Injection Protection**: Re-encryption verification in decapsulation, bounds checking, integrity validation
- **Constant-Time Operations**: All cryptographic operations on secret data run in constant time
- **Automatic Key Zeroization**: Private keys and shared secrets automatically wiped on drop
- **Comprehensive Security Documentation**: SECURITY.md with threat model, countermeasures, limitations, and usage guidelines
- **Zero Unsafe Code**: Pure safe Rust implementation

### Security Considerations

- **Not yet audited**: This is a reference implementation. Independent security audit recommended before use in production systems handling classified or high-value data.
- **Timing Side-Channels**: Constant-time implementation is bounded by Rust compiler and CPU behavior. For maximum security, consider additional runtime isolation.
- **Hardware-Level Attacks**: This library does not protect against side-channels at the CPU/cache/power level. Deployment in high-security contexts should include additional countermeasures.

### Future Roadmap

#### Phase 1: Architecture Stabilization (Post-V1)

The current codebase is purpose-built for NIST's lattice standards (ML-KEM/ML-DSA). Future expansion beyond this scope will require architectural decisions:

1. **Scope Decision** (required first):
   - **Option A - Focused Scope**: Remain a specialized ML-KEM/ML-DSA library with hybrid scheme support
   - **Option B - Extended Scope**: Evolve toward a general-purpose post-quantum cryptography toolkit
   
   Each path has distinct implications for API stability, maintenance surface, and performance tradeoffs.

2. **If choosing focused scope (Option A)**:
   - Add hybrid constructions (classical RSA/ECDSA + ML-KEM/ML-DSA)
   - Add ML-KEM/ML-DSA variants and additional parameter sets (if NIST releases them)
   - Implement SLH-DSA (FIPS 205 stateless hash-based signatures) as a complementary algorithm
   - Optimize for embedded/satellite use cases (CubeSat, IoT)

3. **If choosing extended scope (Option B)**:
   - **Refactor to trait-based abstractions**: Replace concrete Polynomial/NTT with generic ring abstractions
   - **Support multiple lattice families**: NTRU, Falcon, other LWE/Module-LWE variants
   - **API redesign**: Stabilize PublicKey/PrivateKey interfaces for extensibility
   - **Cost**: 2-3K additional LoC for abstraction layer; minor performance regression

#### Phase 2: Performance & Hardening (12+ months post-V1)

- Runtime constant-time verification via specialized CPU counter tools
- Fault injection testing harness (CLEARTEXT model)
- Formal verification of critical NTT/polynomial operations (using interactive theorem prover)
- SIMD vectorization for NTT operations (x86-64, ARM64)

#### Phase 3: Ecosystem Integration (24+ months post-V1)

- TLS 1.3 hybrid (OQS profiles)
- PKCS#11 provider
- Hardware security module (HSM) integration patterns

### Current Limitations

- **Degree-256 Polynomial**: Hardcoded to X^256 + 1, q = 3329. Adding non-module-lattice algorithms requires significant rewrites.
- **No Trait Abstractions**: Algorithm family traits do not exist; adding new algorithms requires careful code organization to avoid duplication.
- **No SIMD**: Baseline scalar implementation; no vectorized NTT.
- **Minimal Runtime Hardening**: Protection against software side-channels only; requires deployment-level protections for high-security scenarios.

### Migration Path for New Algorithms

If future work adds support for additional algorithms:

1. **Shallow Extension** (hybrid schemes, new parameter sets):
   - Minimal changes to common/; extend param enums
   - Add new top-level module (e.g., src/hybrid/)
   - Example: `src/hybrid/classical_pq_hybrid.rs` composing classical RSA + ML-KEM

2. **Deep Extension** (new lattice families or ring structures):
   - Create abstraction layer in common/: `RingElement`, `NTTTransform`, `PolynomialRing` traits
   - Refactor Polynomial → concrete `ModuleLatticePolynomial` implementing `RingElement`
   - Create algorithm-specific modules under src/ (e.g., src/ntru/, src/falcon/)
   - Expected scope: 3-5K LoC for abstraction + algorithm-specific code
   - Breaking API change; bump to v2.0.0

### Deprecated

None (v1.0 is the initial stable release).

---

## [0.1.0] - 2026-Q2

Initial development release. Core ML-KEM and ML-DSA implementations with FIPS compliance.
