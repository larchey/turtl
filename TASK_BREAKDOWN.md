# TURTL - Task Breakdown

## Task Organization Principles

1. **One task = One file or feature** (usually)
2. **Mark dependencies clearly** (Task X needs Task Y complete)
3. **Start with foundation, build up** (bug fixes → docs → optimization)
4. **Group by phase** (Critical Fixes → Documentation → Validation → Optimization)
5. **Be specific** (workers follow these exactly)

## Priority Legend

- 🔴 **P0 (Critical):** Blocking bugs, must fix for basic functionality
- 🟡 **P1 (High):** Required for production readiness
- 🟢 **P2 (Medium):** Important for quality and usability
- 🔵 **P3 (Nice-to-have):** Optimization and enhancement features

---

## Phase 1: Critical Bug Fixes (Week 1)

### Task #1: Fix ML-DSA NTT Implementation 🔴
- **Description:** Fix the NTT forward/inverse transforms for ML-DSA parameter sets to produce correct coefficient magnitudes. Root cause: NTT for q=8380417 produces wildly incorrect outputs causing 100% rejection in signing.
- **File(s):** src/common/ntt.rs
- **Dependencies:** None (blocking all ML-DSA functionality)
- **Acceptance Criteria:**
  - NTT roundtrip test passes: `ntt_inverse(ntt_forward(poly)) == poly`
  - Small input coefficients `[2, -1, 2, ...]` produce reasonable NTT outputs (not millions)
  - Signing succeeds with <100 retries for ML-DSA-44/65/87
  - All 7 tests in `tests/dsa_test_vectors.rs` pass
  - NTT implementation matches FIPS 204 Section 8.4 line-by-line
- **Estimated Complexity:** High
- **Notes:** This is THE critical blocker. Compare implementation with FIPS 204 specification carefully. Check root calculation, Montgomery reduction, and modular arithmetic.

### Task #2: Verify ML-DSA Signing Functionality 🔴
- **Description:** After NTT fix, comprehensively test ML-DSA signing with all parameter sets to ensure it works correctly.
- **File(s):** tests/dsa_test_vectors.rs, tests/simple_sign_test.rs
- **Dependencies:** Task #1 (needs working NTT)
- **Acceptance Criteria:**
  - All parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87) can sign messages
  - Signing completes in <1000 retries on average
  - Signatures verify correctly
  - Test vectors from NIST pass
  - Simple sign test passes
- **Estimated Complexity:** Medium
- **Notes:** This validates that Task #1 fixed the problem completely.

### Task #3: Fix Failing Negative Test Cases 🔴
- **Description:** Fix the 4 failing tests in negative_test_cases.rs that are blocked by the ML-DSA signing bug.
- **File(s):** tests/negative_test_cases.rs
- **Dependencies:** Task #1, Task #2
- **Acceptance Criteria:**
  - All 17 tests in negative_test_cases.rs pass
  - Tests cover: invalid key sizes, invalid signature sizes, tampered signatures, invalid contexts
  - Error handling is comprehensive
- **Estimated Complexity:** Low
- **Notes:** These tests should pass once signing works. May need minor adjustments.

### Task #4: Add NTT Correctness Tests 🔴
- **Description:** Create comprehensive unit tests for NTT to prevent regressions and validate correctness for both ML-KEM and ML-DSA.
- **File(s):** tests/ntt_correctness_test.rs (new file)
- **Dependencies:** Task #1
- **Acceptance Criteria:**
  - Roundtrip tests: `ntt_inverse(ntt_forward(poly)) == poly` for both parameters
  - Known vector tests from FIPS 203/204 appendices
  - Edge case tests: zero polynomial, all-ones, maximum coefficients
  - Tests for both q=3329 (ML-KEM) and q=8380417 (ML-DSA)
  - Linearity tests: `NTT(a + b) == NTT(a) + NTT(b)`
- **Estimated Complexity:** Medium
- **Notes:** Prevent future NTT regressions. Use NIST KAT vectors if available.

---

## Phase 2: Documentation & Examples (Week 2)

### Task #5: Create ML-KEM Basic Usage Example 🟡
- **Description:** Write a simple, well-commented example showing ML-KEM key generation, encapsulation, and decapsulation.
- **File(s):** examples/kem_basic.rs (new file)
- **Dependencies:** None (ML-KEM already works)
- **Acceptance Criteria:**
  - Example compiles and runs successfully
  - Demonstrates all 3 parameter sets (512, 768, 1024)
  - Shows complete workflow: keygen → encapsulate → decapsulate
  - Includes error handling
  - Has clear comments explaining each step
  - Output shows shared secret matches on both sides
- **Estimated Complexity:** Low
- **Notes:** This is developers' first introduction to the library. Make it crystal clear.

### Task #6: Create ML-DSA Basic Usage Example 🟡
- **Description:** Write a simple, well-commented example showing ML-DSA key generation, signing, and verification.
- **File(s):** examples/dsa_basic.rs (new file)
- **Dependencies:** Task #1, Task #2 (needs working ML-DSA)
- **Acceptance Criteria:**
  - Example compiles and runs successfully
  - Demonstrates all 3 parameter sets (44, 65, 87)
  - Shows complete workflow: keygen → sign → verify
  - Includes error handling
  - Has clear comments explaining each step
  - Output shows signature verification success
- **Estimated Complexity:** Low
- **Notes:** Similar structure to Task #5 but for signatures.

### Task #7: Write Security Considerations Documentation 🟡
- **Description:** Create comprehensive SECURITY.md documenting threat model, security features, and usage guidelines.
- **File(s):** docs/SECURITY.md (new file)
- **Dependencies:** None
- **Acceptance Criteria:**
  - Documents threat model (what we protect against)
  - Explains constant-time operations and their importance
  - Describes fault detection mechanisms
  - Covers memory zeroization
  - Provides secure usage guidelines
  - Lists known limitations (e.g., no hardware side-channel protection)
  - Includes security reporting process
  - References FIPS 203/204 security considerations
- **Estimated Complexity:** Medium
- **Notes:** Critical for production deployments. Be comprehensive and clear.

### Task #8: Create Hedged Signing Example 🟡
- **Description:** Write example demonstrating hedged vs deterministic signing in ML-DSA.
- **File(s):** examples/hedged_signing.rs (new file)
- **Dependencies:** Task #1, Task #2
- **Acceptance Criteria:**
  - Shows both deterministic signing (pure DSA.Sign)
  - Shows hedged signing (DSA.Sign with fresh randomness)
  - Explains trade-offs between the two approaches
  - Demonstrates that hedged signing produces different signatures for same message
  - Demonstrates that deterministic signing is reproducible
  - Includes comments on when to use each mode
- **Estimated Complexity:** Low
- **Notes:** Important security feature to highlight.

### Task #9: Improve README with Quickstart Guide 🟡
- **Description:** Enhance README.md with a quickstart section showing minimal usage examples and installation instructions.
- **File(s):** README.md
- **Dependencies:** Task #5, Task #6 (reference examples)
- **Acceptance Criteria:**
  - Quickstart section added at top of README
  - Shows cargo dependency installation
  - Includes minimal ML-KEM example (5-10 lines)
  - Includes minimal ML-DSA example (5-10 lines)
  - Links to full examples in examples/ directory
  - Lists all parameter sets and security levels
  - Mentions FIPS 203/204 compliance
  - Includes link to security documentation
- **Estimated Complexity:** Low
- **Notes:** Make README immediately useful for new users.

### Task #10: Add API Documentation (rustdoc) 🟡
- **Description:** Add comprehensive rustdoc comments to all public APIs in src/kem/mod.rs and src/dsa/mod.rs.
- **File(s):** src/kem/mod.rs, src/dsa/mod.rs, src/lib.rs
- **Dependencies:** None
- **Acceptance Criteria:**
  - All public functions have `///` doc comments
  - All public types have doc comments
  - Module-level documentation (`//!`) added
  - Examples included in doc comments (using ` ```rust` blocks)
  - Parameter descriptions included
  - Return value descriptions included
  - Error conditions documented
  - `cargo doc` generates clean documentation with no warnings
- **Estimated Complexity:** Medium
- **Notes:** Good API docs are essential for library users.

---

## Phase 3: Validation & Interoperability (Week 3)

### Task #11: ML-KEM Interoperability Tests 🟢
- **Description:** Create interoperability tests for ML-KEM using NIST Known Answer Tests (KAT) or reference implementation vectors.
- **File(s):** tests/kem_interop_test.rs (new file), tests/data/kem_kat/ (test vectors)
- **Dependencies:** None (ML-KEM works)
- **Acceptance Criteria:**
  - Tests against NIST official KAT vectors
  - All 3 parameter sets tested (512, 768, 1024)
  - Tests cover: keygen, encapsulation, decapsulation
  - Validates byte-level compatibility with reference implementation
  - At least 10 test vectors per parameter set
  - All tests pass
- **Estimated Complexity:** Medium
- **Notes:** Download KAT from NIST or pq-crystals repository. Ensures compatibility with other implementations.

### Task #12: ML-DSA Interoperability Tests 🟢
- **Description:** Create interoperability tests for ML-DSA using NIST Known Answer Tests (KAT) or reference implementation vectors.
- **File(s):** tests/dsa_interop_test.rs (new file), tests/data/dsa_kat/ (test vectors)
- **Dependencies:** Task #1, Task #2
- **Acceptance Criteria:**
  - Tests against NIST official KAT vectors
  - All 3 parameter sets tested (44, 65, 87)
  - Tests cover: keygen, signing, verification
  - Validates byte-level compatibility with reference implementation
  - At least 10 test vectors per parameter set
  - All tests pass
- **Estimated Complexity:** Medium
- **Notes:** Download KAT from NIST or pq-crystals repository.

### Task #13: Expand Security Audit Documentation 🟢
- **Description:** Expand AUDIT_SUMMARY.md with post-fix validation and additional security analysis.
- **File(s):** AUDIT_SUMMARY.md
- **Dependencies:** Task #1, Task #2, Task #3, Task #4
- **Acceptance Criteria:**
  - Document that ML-DSA NTT bug is fixed
  - Add validation results for the fix
  - Update test status (all tests passing)
  - Add section on remaining security considerations
  - Document any new findings from interop testing
  - Include recommendations for production deployment
- **Estimated Complexity:** Low
- **Notes:** Keep audit document up-to-date as primary security reference.

### Task #14: Benchmark Performance Baseline 🟢
- **Description:** Run comprehensive benchmarks and document baseline performance metrics for future optimization.
- **File(s):** docs/PERFORMANCE.md (new file)
- **Dependencies:** Task #1, Task #2 (need working implementations)
- **Acceptance Criteria:**
  - Run all benchmarks in benches/ directory
  - Document results for all parameter sets
  - Include: keygen, encaps, decaps, sign, verify timing
  - Measure memory usage per operation
  - Compare with reference implementation (if available)
  - Document test environment (CPU, OS, Rust version)
  - Provide baseline for future optimization tasks
- **Estimated Complexity:** Low
- **Notes:** This establishes the performance baseline before optimization.

### Task #15: Add Fuzzing Infrastructure 🟢
- **Description:** Set up fuzzing infrastructure using cargo-fuzz to find edge cases and potential bugs.
- **File(s):** fuzz/ directory (new), fuzz/fuzz_targets/*.rs
- **Dependencies:** None
- **Acceptance Criteria:**
  - cargo-fuzz configured in fuzz/ directory
  - Fuzz targets created for:
    - ML-KEM encapsulation (fuzz public key input)
    - ML-KEM decapsulation (fuzz ciphertext input)
    - ML-DSA verification (fuzz signature input)
    - NTT transforms (fuzz polynomial coefficients)
  - README in fuzz/ explaining how to run
  - At least 1 hour of fuzzing per target with no crashes
  - Any found bugs documented and fixed
- **Estimated Complexity:** Medium
- **Notes:** Fuzzing is critical for finding edge cases. Use AFL or libFuzzer.

---

## Phase 4: Optimization (Week 4+)

### Task #16: Profile NTT Performance Bottlenecks 🔵
- **Description:** Use profiling tools (perf, flamegraph) to identify performance bottlenecks in NTT implementation.
- **File(s):** benches/ntt_benchmark.rs
- **Dependencies:** Task #14 (need baseline)
- **Acceptance Criteria:**
  - Generate flamegraph for NTT operations
  - Identify top 5 hotspots in NTT code
  - Document findings in docs/PERFORMANCE.md
  - Propose optimization opportunities
  - Measure cache misses, branch mispredictions
- **Estimated Complexity:** Medium
- **Notes:** Use `cargo flamegraph` or `perf record/report`.

### Task #17: Optimize Polynomial Multiplication 🔵
- **Description:** Investigate and potentially implement Karatsuba or other optimized polynomial multiplication algorithms.
- **File(s):** src/common/poly.rs, benches/ntt_benchmark.rs
- **Dependencies:** Task #16 (need profiling data)
- **Acceptance Criteria:**
  - Research Karatsuba multiplication for NTT
  - Implement optimized variant (if worthwhile)
  - Benchmark before/after performance
  - Ensure all tests still pass
  - Document speedup in docs/PERFORMANCE.md
  - At least 10% performance improvement or don't merge
- **Estimated Complexity:** High
- **Notes:** Only optimize if profiling shows it's a real bottleneck.

### Task #18: Add SIMD/AVX2 NTT Implementation 🔵
- **Description:** Implement vectorized NTT using SIMD intrinsics for x86_64 platforms.
- **File(s):** src/common/ntt_simd.rs (new file), Cargo.toml (add feature flag)
- **Dependencies:** Task #16, Task #17
- **Acceptance Criteria:**
  - SIMD NTT implementation behind `simd` feature flag
  - Uses AVX2 intrinsics for x86_64
  - Falls back to scalar implementation on other platforms
  - Benchmarks show 2-4x speedup on supported platforms
  - All NTT tests pass with SIMD version
  - Maintains constant-time properties
  - Documented in docs/PERFORMANCE.md
- **Estimated Complexity:** Very High
- **Notes:** Significant complexity. Consider using libraries like `packed_simd`.

### Task #19: Optimize Memory Allocations 🔵
- **Description:** Reduce heap allocations in hot paths to improve performance and reduce memory footprint.
- **File(s):** src/common/poly.rs, src/kem/internal/mod.rs, src/dsa/internal/mod.rs
- **Dependencies:** Task #16 (need profiling)
- **Acceptance Criteria:**
  - Identify unnecessary allocations in profiling data
  - Use stack-allocated arrays where possible
  - Reuse buffers across operations
  - Benchmark before/after memory usage
  - All tests still pass
  - At least 20% reduction in heap allocations or don't merge
- **Estimated Complexity:** Medium
- **Notes:** Profile with valgrind/massif to find allocation hotspots.

### Task #20: Benchmark Comparison with Reference Implementations 🔵
- **Description:** Compare TURTL performance with official reference implementations and other Rust implementations.
- **File(s):** docs/PERFORMANCE.md, benches/comparison/ (new directory)
- **Dependencies:** Task #14, and optionally Task #17-19
- **Acceptance Criteria:**
  - Benchmark against pqcryb (reference C implementation)
  - Benchmark against other Rust PQC libraries (if available)
  - Compare all operations: keygen, encaps, decaps, sign, verify
  - Document relative performance (faster/slower by X%)
  - Identify areas where TURTL is slower
  - Create benchmark comparison table
- **Estimated Complexity:** Medium
- **Notes:** Helps understand competitive position and optimization priorities.

---

## Phase 5: Production Hardening (Week 5-6)

### Task #21: External Cryptography Audit 🔴
- **Description:** Hire professional cryptography auditor for independent security review of the implementation.
- **File(s):** docs/EXTERNAL_AUDIT.md (new file with audit report)
- **Dependencies:** Task #1-15 (all core functionality complete)
- **Acceptance Criteria:**
  - Contract with reputable cryptography auditing firm (Trail of Bits, NCC Group, etc.)
  - Full code review of NTT, polynomial arithmetic, signing, key exchange
  - Side-channel analysis
  - Formal audit report delivered
  - All critical and high-severity findings fixed
  - Publish sanitized audit summary
- **Estimated Complexity:** Very High (external dependency)
- **Notes:** MANDATORY for production cryptography. Budget $15k-$50k. Takes 2-4 weeks.

### Task #22: Validate Constant-Time Properties 🔴
- **Description:** Enable and validate timing tests to ensure constant-time operations are actually constant-time.
- **File(s):** tests/timing_invariance_test.rs, docs/TIMING_VALIDATION.md (new)
- **Dependencies:** Task #1-4 (need working implementation)
- **Acceptance Criteria:**
  - Unignore all tests in timing_invariance_test.rs
  - Run on dedicated test machine (minimal background noise)
  - Use statistical t-tests to detect timing leaks
  - Test with `ctgrind` (constant-time valgrind plugin)
  - All constant-time operations pass statistical tests (p > 0.05)
  - Document test methodology and results
  - Fix any timing leaks found
- **Estimated Complexity:** High
- **Notes:** Critical for side-channel resistance. May need multiple test runs for statistical significance.

### Task #23: Cross-Platform CI Testing 🟡
- **Description:** Add Windows, macOS, and ARM64 to CI matrix to catch platform-specific bugs.
- **File(s):** .github/workflows/ci.yml
- **Dependencies:** None (can run anytime)
- **Acceptance Criteria:**
  - CI matrix includes: Ubuntu, Windows, macOS
  - Test on both x86_64 and ARM64 (aarch64)
  - Test on Rust stable and nightly
  - All tests pass on all platforms
  - Fix any platform-specific bugs (endianness, compiler differences)
  - Document platform support in README
- **Estimated Complexity:** Medium
- **Notes:** Crypto bugs can be architecture-specific. ARM64 is important for mobile/embedded.

### Task #24: Security Monitoring Infrastructure 🟡
- **Description:** Set up continuous security monitoring with cargo-audit, SBOM generation, and Dependabot.
- **File(s):** .github/workflows/security.yml, SBOM.spdx, .github/dependabot.yml
- **Dependencies:** None (can run anytime)
- **Acceptance Criteria:**
  - Daily cargo-audit run in GitHub Actions
  - SBOM (Software Bill of Materials) generated on each release
  - Dependabot enabled for Cargo.toml
  - Security policy documented in SECURITY.md
  - Automated alerts for vulnerable dependencies
  - Document security monitoring process
- **Estimated Complexity:** Low
- **Notes:** Supply chain security is critical. SBOM helps users understand dependencies.

### Task #25: Memory Safety Testing (Miri/Valgrind) 🟡
- **Description:** Run tests under Miri and Valgrind to detect undefined behavior and memory leaks.
- **File(s):** .github/workflows/miri.yml, docs/MEMORY_SAFETY.md (new)
- **Dependencies:** Task #1-4 (need working tests)
- **Acceptance Criteria:**
  - All tests pass under `cargo +nightly miri test`
  - No undefined behavior detected by Miri
  - Run tests under Valgrind with leak detection
  - No memory leaks detected
  - Test with AddressSanitizer (ASAN)
  - Document results in MEMORY_SAFETY.md
  - Add Miri to CI (weekly run, can be slow)
- **Estimated Complexity:** Medium
- **Notes:** Miri is slow but catches subtle bugs. Run on subset of tests in CI.

### Task #26: Release Process and Security Disclosure 🟡
- **Description:** Document release process, semantic versioning policy, and security vulnerability disclosure.
- **File(s):** RELEASES.md, CHANGELOG.md, SECURITY.md (update)
- **Dependencies:** None (documentation task)
- **Acceptance Criteria:**
  - RELEASES.md with release process documentation
  - Semantic versioning policy defined
  - CHANGELOG.md initialized with format
  - Security vulnerability disclosure process in SECURITY.md:
    - Contact email (not public GitHub issues!)
    - Expected response time (48 hours)
    - Coordinated disclosure timeline (90 days)
    - PGP key for encrypted reports
  - Code signing process documented
  - Release checklist created
- **Estimated Complexity:** Low
- **Notes:** Clear processes prevent security mishandling.

### Task #27: Performance Regression CI 🟢
- **Description:** Add benchmark comparison to CI to detect performance regressions.
- **File(s):** .github/workflows/benchmark.yml
- **Dependencies:** Task #14 (baseline benchmarks)
- **Acceptance Criteria:**
  - Run benchmarks on every PR
  - Compare against main branch baseline
  - Fail CI if >10% regression in critical operations
  - Use criterion's history feature
  - Post benchmark results as PR comment
  - Track performance over time
- **Estimated Complexity:** Medium
- **Notes:** Prevents accidental performance regressions. Don't block on minor fluctuations.

### Task #28: Real-World Integration Examples 🟢
- **Description:** Create examples showing TURTL integration in real-world scenarios.
- **File(s):** examples/hybrid_pqc_classic.rs, examples/tls_handshake.rs, examples/secure_messaging.rs
- **Dependencies:** Task #5, #6 (basic examples)
- **Acceptance Criteria:**
  - Hybrid classical+PQC example (X25519 + ML-KEM)
  - Simulated TLS handshake with PQC
  - Secure messaging example (encrypt + sign)
  - Best practices guide for integration
  - Performance considerations documented
  - All examples compile and run
- **Estimated Complexity:** Medium
- **Notes:** Help users understand how to actually use TURTL in production.

---

## Dependency Graph

```
Phase 1 (Critical):
Task #1 (NTT Fix) [CRITICAL BLOCKER]
  ├─→ Task #2 (Verify ML-DSA)
  │     ├─→ Task #3 (Fix negative tests)
  │     ├─→ Task #6 (DSA example)
  │     ├─→ Task #8 (Hedged signing example)
  │     ├─→ Task #12 (DSA interop)
  │     └─→ Task #14 (Benchmarks)
  └─→ Task #4 (NTT tests)

Phase 2 (Documentation):
Task #5 (KEM example) [Independent]
Task #7 (SECURITY.md) [Independent]
Task #9 (README) → Task #5, Task #6
Task #10 (API docs) [Independent]

Phase 3 (Validation):
Task #11 (KEM interop) [Independent]
Task #13 (Audit doc) → Task #1, #2, #3, #4
Task #15 (Fuzzing) [Independent]

Phase 4 (Optimization):
Task #16 (Profiling) → Task #14
Task #17 (Poly opt) → Task #16
Task #18 (SIMD) → Task #16, #17
Task #19 (Memory opt) → Task #16
Task #20 (Comparison) → Task #14

Phase 5 (Production Hardening):
Task #21 (External audit) → Task #1-15 [EXTERNAL DEPENDENCY]
Task #22 (Constant-time validation) → Task #1-4 [CRITICAL]
Task #23 (Cross-platform CI) [Independent]
Task #24 (Security monitoring) [Independent]
Task #25 (Miri/Valgrind) → Task #1-4
Task #26 (Release process) [Independent]
Task #27 (Perf regression CI) → Task #14
Task #28 (Integration examples) → Task #5, #6
```

---

## MVP Definition

**Minimum Viable Product includes tasks:**
- Task #1: Fix ML-DSA NTT (CRITICAL)
- Task #2: Verify ML-DSA signing
- Task #3: Fix negative tests
- Task #4: NTT correctness tests
- Task #5: ML-KEM example
- Task #6: ML-DSA example
- Task #7: SECURITY.md
- Task #9: README improvements
- Task #10: API documentation

**Must have for MVP:**
- ✅ ML-KEM fully functional (already is)
- ✅ ML-DSA fully functional (needs Task #1-3)
- ✅ Clear usage examples (Task #5-6)
- ✅ Security documentation (Task #7)
- ✅ Good API docs (Task #10)

**Can defer post-MVP:**
- Interoperability tests (Task #11-12) - important but not blocking
- Fuzzing (Task #15) - good to have, not urgent
- All optimization tasks (Task #16-20) - performance is secondary to correctness

---

## Parallelization Strategy

**Can run in parallel:**
- **Phase 1:** Only Task #1 is critical path. Tasks #2, #3, #4 depend on it.
- **Phase 2:** Tasks #5, #7, #10 can all run in parallel. Task #6, #8 wait for Task #1.
- **Phase 3:** Tasks #11, #15 can run in parallel.
- **Phase 4:** All tasks depend on Task #16 except Task #20.

**Must run sequentially:**
- Task #1 must complete before Tasks #2, #3, #4, #6, #8, #12, #14
- Task #14 must complete before Task #16
- Task #16 must complete before Task #17, #18, #19

**Optimal worker allocation:**
- **Week 1:** 1 worker on Task #1 (critical), 3 workers on Tasks #5, #7, #10
- **Week 2:** After Task #1 done, spawn workers for Tasks #2, #3, #4, #6, #8, #9
- **Week 3:** Workers for Tasks #11, #12, #13, #14, #15
- **Week 4:** Sequential optimization tasks #16 → #17-19-20
- **Week 5-6:** Production hardening - Tasks #22-28 in parallel, Task #21 external

---

## Task Checklist

### Phase 1: Critical (Week 1)
- [ ] Task #1: Fix ML-DSA NTT Implementation 🔴
- [ ] Task #2: Verify ML-DSA Signing Functionality 🔴
- [ ] Task #3: Fix Failing Negative Test Cases 🔴
- [ ] Task #4: Add NTT Correctness Tests 🔴

### Phase 2: Documentation (Week 2)
- [ ] Task #5: Create ML-KEM Basic Usage Example 🟡
- [ ] Task #6: Create ML-DSA Basic Usage Example 🟡
- [ ] Task #7: Write Security Considerations Documentation 🟡
- [ ] Task #8: Create Hedged Signing Example 🟡
- [ ] Task #9: Improve README with Quickstart Guide 🟡
- [ ] Task #10: Add API Documentation (rustdoc) 🟡

### Phase 3: Validation (Week 3)
- [ ] Task #11: ML-KEM Interoperability Tests 🟢
- [ ] Task #12: ML-DSA Interoperability Tests 🟢
- [ ] Task #13: Expand Security Audit Documentation 🟢
- [ ] Task #14: Benchmark Performance Baseline 🟢
- [ ] Task #15: Add Fuzzing Infrastructure 🟢

### Phase 4: Optimization (Week 4+)
- [ ] Task #16: Profile NTT Performance Bottlenecks 🔵
- [ ] Task #17: Optimize Polynomial Multiplication 🔵
- [ ] Task #18: Add SIMD/AVX2 NTT Implementation 🔵
- [ ] Task #19: Optimize Memory Allocations 🔵
- [ ] Task #20: Benchmark Comparison with Reference Implementations 🔵

### Phase 5: Production Hardening (Week 5-6)
- [ ] Task #21: External Cryptography Audit 🔴 [EXTERNAL DEPENDENCY]
- [ ] Task #22: Validate Constant-Time Properties 🔴
- [ ] Task #23: Cross-Platform CI Testing 🟡
- [ ] Task #24: Security Monitoring Infrastructure 🟡
- [ ] Task #25: Memory Safety Testing (Miri/Valgrind) 🟡
- [ ] Task #26: Release Process and Security Disclosure 🟡
- [ ] Task #27: Performance Regression CI 🟢
- [ ] Task #28: Real-World Integration Examples 🟢

---

**Total Tasks:** 28
**Estimated Duration:** 5-6 weeks with 3-5 parallel workers
**Last Updated:** 2026-01-25
**Critical Path:** Task #1 → Task #2 → Task #3 → Production readiness requires Tasks #21-22
