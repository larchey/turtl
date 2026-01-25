# TURTL - Multiclaude Worker Prompts

## How to Use This File

1. **Copy the task prompt exactly** when spawning a worker
2. **Include all context** - file paths, specs, references
3. **Be specific** - workers will follow these literally
4. **Reference design docs** - ensure workers understand the full context

---

## Task #1: Fix ML-DSA NTT Implementation 🔴

### Worker Prompt

```
Fix the ML-DSA NTT implementation in src/common/ntt.rs (Task #1):

CRITICAL BUG: The NTT forward/inverse transforms for ML-DSA (modulus q=8380417) produce wildly incorrect outputs. Small input coefficients like [2, -1, 2, -1] produce huge outputs like [6390728, 8238925, ...] which cause signing to fail with 100% rejection rate.

Root cause identified: NTT implementation doesn't match FIPS 204 Section 8.4 specification.

Your task:
1. Read FIPS 204 Section 8.4 carefully (Number-Theoretic Transform)
2. Compare current ntt.rs implementation line-by-line with spec
3. Fix the following likely issues:
   - Root of unity calculation for q=8380417
   - Montgomery reduction for 32-bit modulus
   - Negative coefficient handling in centered representation
   - Bit-reversal permutation

4. Ensure ntt_forward() and ntt_inverse() are correct inverses:
   - Test: ntt_inverse(ntt_forward(poly)) should equal poly
   - Test with small coefficients: [2, -1, 2, -1, ...]
   - Verify output magnitudes are reasonable (not millions)

5. Specific functions to fix:
   - ntt_forward() for ML-DSA parameter (q=8380417)
   - ntt_inverse() for ML-DSA parameter
   - montgomery_reduce_mldsa() if issues found
   - Precomputed roots in NTT_ROOTS_MLDSA constant

6. DO NOT break ML-KEM NTT (q=3329) which currently works

Testing requirements:
- Add unit test: ntt_roundtrip_mldsa() that verifies forward/inverse are true inverses
- Test with at least 10 random polynomials
- Test edge cases: zero polynomial, all-ones, maximum coefficients
- Verify tests/dsa_test_vectors.rs passes (currently fails due to this bug)
- Verify tests/simple_sign_test.rs passes

References:
- FIPS 204 Section 8.4 (NTT specification)
- FIPS 204 Appendix (test vectors)
- See PROJECT_DESIGN.md Section 3 (Technical Stack)
- See TASK_BREAKDOWN.md Task #1 for acceptance criteria
- Current code location: src/common/ntt.rs lines 90-350

Acceptance:
- NTT roundtrip test passes for ML-DSA
- Signing completes successfully (no more 100% rejection)
- All DSA tests pass
- ML-KEM tests still pass (don't break working code)
```

---

## Task #2: Verify ML-DSA Signing Functionality 🔴

### Worker Prompt

```
Verify ML-DSA signing works correctly after NTT fix (Task #2):

REQUIRES: Task #1 (NTT fix) must be complete.

After the NTT bug fix, comprehensively test that ML-DSA signing is functional for all parameter sets.

Your task:
1. Run all existing ML-DSA tests:
   - cargo test --test dsa_test_vectors
   - cargo test --test simple_sign_test
   - cargo test --lib dsa

2. If tests fail, investigate and fix remaining issues in:
   - src/dsa/sign.rs
   - src/dsa/verify.rs
   - src/dsa/internal/mod.rs

3. Add comprehensive signing tests in tests/dsa_signing_test.rs:
   - Test all 3 parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87
   - Test signing with empty message
   - Test signing with large message (1MB+)
   - Test signing with various context strings
   - Test deterministic signing (same message → same signature)
   - Verify retry count is reasonable (<1000 on average)

4. Measure and document:
   - Average retry count for successful signing
   - Success rate (should be >99%)
   - Typical signing latency

5. Ensure signature verification works:
   - Generated signatures verify correctly
   - Tampered signatures fail verification
   - Wrong public key fails verification

Files to modify/create:
- tests/dsa_signing_test.rs (new file)
- Update AUDIT_SUMMARY.md with verification results

References:
- FIPS 204 Section 5 (ML-DSA.Sign specification)
- See PROJECT_DESIGN.md Section 5 (API Design)
- See TASK_BREAKDOWN.md Task #2

Acceptance:
- All 7 tests in dsa_test_vectors.rs pass
- simple_sign_test.rs passes
- New dsa_signing_test.rs has 10+ tests, all passing
- Signing completes in <1000 retries on average
- Documentation updated
```

---

## Task #3: Fix Failing Negative Test Cases 🔴

### Worker Prompt

```
Fix the 4 failing tests in negative_test_cases.rs (Task #3):

REQUIRES: Task #1 (NTT fix) and Task #2 (signing verification) complete.

Currently 4 out of 17 tests in tests/negative_test_cases.rs are failing due to the ML-DSA signing bug. Now that signing works, fix or update these tests.

Your task:
1. Run cargo test --test negative_test_cases and identify which tests fail

2. For each failing test:
   - Understand what it's testing (invalid input handling)
   - Determine if test is correct or needs updating
   - Fix either the test or the underlying error handling code

3. Tests should cover:
   - Invalid public key sizes (too small, too large)
   - Invalid private key sizes
   - Invalid signature sizes
   - Invalid ciphertext sizes
   - Tampered signatures
   - Tampered ciphertexts
   - Invalid context strings (>255 bytes per FIPS 204)
   - Wrong parameter set combinations

4. Ensure all error types are tested:
   - TurtlError::InvalidPublicKeySize
   - TurtlError::InvalidPrivateKeySize
   - TurtlError::InvalidSignatureSize
   - TurtlError::InvalidCiphertextSize
   - TurtlError::InvalidContextSize
   - TurtlError::VerificationFailure

Files to modify:
- tests/negative_test_cases.rs
- Potentially src/error.rs if new error types needed
- Potentially src/dsa/verify.rs or src/kem/decapsulate.rs for error handling

References:
- FIPS 203 Section 7.2 (ML-KEM error conditions)
- FIPS 204 Section 5.2 (ML-DSA error conditions)
- See PROJECT_DESIGN.md Section 8 (Error Handling)
- See TASK_BREAKDOWN.md Task #3

Acceptance:
- All 17 tests in negative_test_cases.rs pass
- Each error type from TurtlError enum is tested
- Tests are well-documented with comments
- Error messages are clear and helpful
```

---

## Task #4: Add NTT Correctness Tests 🔴

### Worker Prompt

```
Create comprehensive NTT correctness tests (Task #4):

REQUIRES: Task #1 (NTT fix) complete.

Add thorough unit tests for NTT to prevent regressions and validate correctness.

Your task:
1. Create tests/ntt_correctness_test.rs with the following tests:

**Roundtrip Tests:**
- test_ntt_roundtrip_mlkem(): For q=3329 (ML-KEM modulus)
  - Test 100 random polynomials
  - Verify: ntt_inverse(ntt_forward(poly)) == poly

- test_ntt_roundtrip_mldsa(): For q=8380417 (ML-DSA modulus)
  - Test 100 random polynomials
  - Verify: ntt_inverse(ntt_forward(poly)) == poly

**Edge Case Tests:**
- test_ntt_zero_polynomial(): NTT of all-zeros should be all-zeros
- test_ntt_identity(): NTT of delta function (1 at position 0)
- test_ntt_all_ones(): NTT of polynomial with all coefficients = 1
- test_ntt_maximum_coefficients(): Near-maximum values (q-1)

**Linearity Tests:**
- test_ntt_linearity(): Verify NTT(a + b) == NTT(a) + NTT(b)
- test_ntt_scalar_mult(): Verify NTT(k*a) == k*NTT(a)

**Known Vector Tests (if available):**
- test_ntt_fips203_vectors(): Use test vectors from FIPS 203 appendix
- test_ntt_fips204_vectors(): Use test vectors from FIPS 204 appendix

**Magnitude Tests:**
- test_ntt_output_bounds(): Verify NTT output coefficients are in range [0, q-1]
- test_ntt_small_input(): Small inputs like [2, -1, 2, -1] should produce reasonable outputs

2. Use property-based testing if helpful (proptest crate)

3. Document each test clearly with comments explaining what property is being validated

Files to create:
- tests/ntt_correctness_test.rs (new file, ~300 lines)

References:
- FIPS 203 Appendix (ML-KEM test vectors)
- FIPS 204 Appendix (ML-DSA test vectors)
- src/common/ntt.rs (implementation being tested)
- See TASK_BREAKDOWN.md Task #4

Acceptance:
- At least 10 distinct test functions
- Tests cover both ML-KEM and ML-DSA parameter sets
- All tests pass
- Tests include both randomized and deterministic cases
- Code coverage for ntt.rs increases to 95%+
```

---

## Task #5: Create ML-KEM Basic Usage Example 🟡

### Worker Prompt

```
Create a simple ML-KEM usage example (Task #5):

Write a clear, well-commented example demonstrating basic ML-KEM usage for developers.

Your task:
1. Create examples/kem_basic.rs with a complete example showing:
   - Key generation for all 3 parameter sets (512, 768, 1024)
   - Encapsulation (Alice generates ciphertext + shared secret)
   - Decapsulation (Bob recovers shared secret from ciphertext)
   - Verification that both sides have the same shared secret

2. Example structure:
```rust
use turtl::kem::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ML-KEM Basic Example\n");

    // Demonstrate each parameter set
    demo_kem_512()?;
    demo_kem_768()?;
    demo_kem_1024()?;

    Ok(())
}

fn demo_kem_512() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ML-KEM-512 (Security Level 1) ===");

    // 1. Key generation (Bob)
    // ...

    // 2. Encapsulation (Alice)
    // ...

    // 3. Decapsulation (Bob)
    // ...

    // 4. Verify shared secrets match
    // ...

    Ok(())
}
```

3. Include:
   - Clear step-by-step comments
   - Explanation of what each parameter set provides
   - Error handling with proper Result types
   - Output that shows operation success
   - Timing information (optional but nice)

4. Make it runnable: cargo run --example kem_basic

Files to create:
- examples/kem_basic.rs (new file, ~150 lines)

References:
- src/kem/mod.rs (API being demonstrated)
- FIPS 203 overview
- See PROJECT_DESIGN.md Section 5 (API Design)
- See TASK_BREAKDOWN.md Task #5

Acceptance:
- Example compiles without warnings
- Example runs successfully
- Shows all 3 parameter sets
- Output is clear and informative
- Code is well-commented
- Error handling is demonstrated
```

---

## Task #6: Create ML-DSA Basic Usage Example 🟡

### Worker Prompt

```
Create a simple ML-DSA usage example (Task #6):

REQUIRES: Task #1, Task #2 (working ML-DSA implementation)

Write a clear, well-commented example demonstrating basic ML-DSA signing and verification.

Your task:
1. Create examples/dsa_basic.rs with a complete example showing:
   - Key generation for all 3 parameter sets (44, 65, 87)
   - Signing a message
   - Verifying a signature
   - Demonstrating signature verification failure on tampered message

2. Example structure:
```rust
use turtl::dsa::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ML-DSA Basic Example\n");

    // Demonstrate each parameter set
    demo_dsa_44()?;
    demo_dsa_65()?;
    demo_dsa_87()?;

    // Demonstrate signature verification failure
    demo_verification_failure()?;

    Ok(())
}

fn demo_dsa_44() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ML-DSA-44 (Security Level 2) ===");

    // 1. Key generation
    // ...

    // 2. Sign a message
    let message = b"Hello, post-quantum world!";
    // ...

    // 3. Verify signature
    // ...

    Ok(())
}
```

3. Include:
   - Clear step-by-step comments
   - Explanation of parameter sets and security levels
   - Context string usage (can be empty)
   - Error handling
   - Output showing signature verification success/failure

4. Make it runnable: cargo run --example dsa_basic

Files to create:
- examples/dsa_basic.rs (new file, ~200 lines)

References:
- src/dsa/mod.rs (API being demonstrated)
- FIPS 204 overview
- See PROJECT_DESIGN.md Section 5 (API Design)
- See TASK_BREAKDOWN.md Task #6

Acceptance:
- Example compiles without warnings
- Example runs successfully
- Shows all 3 parameter sets
- Demonstrates both successful and failed verification
- Code is well-commented
- Error handling is proper
```

---

## Task #7: Write Security Considerations Documentation 🟡

### Worker Prompt

```
Create comprehensive security documentation (Task #7):

Write docs/SECURITY.md documenting TURTL's security model, threat protection, and usage guidelines.

Your task:
1. Create docs/SECURITY.md with the following sections:

**1. Threat Model**
- What TURTL protects against:
  - Quantum computer attacks (Shor's algorithm)
  - Classical cryptanalysis
  - Side-channel attacks (timing, cache)
  - Fault injection attacks
  - Memory disclosure attacks

- What TURTL does NOT protect against:
  - Physical attacks on hardware
  - Malware on the system
  - Compromised RNG
  - Implementation bugs in dependencies

**2. Security Features**
- Constant-time operations:
  - Explain what they are and why they matter
  - List which operations are constant-time
  - Limitations (compiler optimizations may break guarantees)

- Memory zeroization:
  - Automatic cleanup of secrets
  - Zeroize trait usage
  - Limitations (can't prevent all memory disclosure)

- Fault detection:
  - Double verification in signatures
  - Re-encryption validation in KEM
  - Bounds checking

**3. Usage Guidelines**
- Secure key generation:
  - Importance of good RNG
  - When to regenerate keys

- Secure signing:
  - When to use deterministic vs hedged
  - Context string usage
  - Signature verification best practices

- Secure key exchange:
  - When to use ML-KEM
  - Ephemeral vs static keys
  - Forward secrecy considerations

**4. Known Limitations**
- No hardware side-channel protection (DPA, SPA)
- Constant-time guarantees limited by compiler/OS
- No protection against fault attacks on hardware
- Memory safety relies on Rust's guarantees

**5. Security Reporting**
- How to report vulnerabilities
- Expected response time
- Disclosure policy

**6. Compliance**
- FIPS 203 conformance
- FIPS 204 conformance
- Security level explanations

2. Write clearly for security professionals and developers
3. Include references to FIPS 203/204 security considerations
4. Be honest about limitations

Files to create:
- docs/SECURITY.md (new file, ~800 lines)

References:
- FIPS 203 Security Considerations
- FIPS 204 Security Considerations
- src/security/ modules
- See PROJECT_DESIGN.md Section 6 (Security Model)
- See TASK_BREAKDOWN.md Task #7

Acceptance:
- All major security topics covered
- Clear explanations for non-experts
- Honest about limitations
- Actionable usage guidelines
- References to standards
```

---

## Task #8: Create Hedged Signing Example 🟡

### Worker Prompt

```
Create example demonstrating hedged vs deterministic signing (Task #8):

REQUIRES: Task #1, Task #2 (working ML-DSA)

Show developers the difference between deterministic and hedged signing modes.

Your task:
1. Create examples/hedged_signing.rs demonstrating:
   - Deterministic signing (same message → same signature)
   - Hedged signing (same message → different signatures due to fresh randomness)
   - When to use each mode
   - Security trade-offs

2. Example structure:
```rust
use turtl::dsa::*;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Hedged vs Deterministic Signing\n");

    demo_deterministic()?;
    demo_hedged()?;

    println!("\nWhen to use each mode:");
    print_usage_guide();

    Ok(())
}

fn demo_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Deterministic Signing ===");

    let (pk, sk) = dsa_keygen(DsaParam::Dsa65)?;
    let message = b"Test message";

    // Sign same message twice
    let sig1 = dsa_sign(&sk, message, b"")?;
    let sig2 = dsa_sign(&sk, message, b"")?;

    // Signatures should be identical
    assert_eq!(sig1.data, sig2.data);
    println!("✓ Same message produces identical signatures");

    Ok(())
}

fn demo_hedged() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Hedged Signing ===");

    let (pk, sk) = dsa_keygen(DsaParam::Dsa65)?;
    let message = b"Test message";
    let mut rng = OsRng;

    // Sign same message twice with hedged mode
    let sig1 = dsa_sign_hedged(&sk, message, b"", &mut rng)?;
    let sig2 = dsa_sign_hedged(&sk, message, b"", &mut rng)?;

    // Signatures should be different
    assert_ne!(sig1.data, sig2.data);
    println!("✓ Same message produces different signatures (randomized)");

    // But both should verify
    assert!(dsa_verify(&pk, message, b"", &sig1)?);
    assert!(dsa_verify(&pk, message, b"", &sig2)?);
    println!("✓ Both signatures verify correctly");

    Ok(())
}

fn print_usage_guide() {
    println!("
**Deterministic Signing:**
- Use when: Signature reproducibility is important
- Use when: You want to detect if signing process changes
- Trade-off: Vulnerable if RNG is compromised during keygen

**Hedged Signing:**
- Use when: Extra security margin is needed
- Use when: Protecting against future RNG vulnerabilities
- Trade-off: Not reproducible, uses more randomness
- Recommended for most applications
    ");
}
```

3. Include detailed comments explaining:
   - Why hedged mode adds fresh randomness
   - Security implications of each mode
   - Reproducibility vs security trade-off

Files to create:
- examples/hedged_signing.rs (new file, ~150 lines)

References:
- src/dsa/sign.rs (hedged implementation)
- FIPS 204 Section 5.2 (hedged signing)
- See TASK_BREAKDOWN.md Task #8

Acceptance:
- Example compiles and runs
- Demonstrates both modes clearly
- Explains trade-offs
- Includes usage recommendations
- Code is well-commented
```

---

## Task #9: Improve README with Quickstart Guide 🟡

### Worker Prompt

```
Enhance README.md with quickstart section (Task #9):

REQUIRES: Task #5, Task #6 (examples to reference)

Make README immediately useful for new users with a quickstart section.

Your task:
1. Read current README.md to understand existing structure

2. Add a new "Quickstart" section near the top (after project description) containing:

**Installation:**
```toml
[dependencies]
turtl = "0.1"
```

**Minimal ML-KEM Example (5-10 lines):**
```rust
use turtl::kem::*;

let (pk, sk) = kem_keygen(KemParam::Kem768)?;
let (ct, ss_alice) = kem_encapsulate(&pk)?;
let ss_bob = kem_decapsulate(&sk, &ct)?;
assert_eq!(ss_alice.as_bytes(), ss_bob.as_bytes());
```

**Minimal ML-DSA Example (5-10 lines):**
```rust
use turtl::dsa::*;

let (pk, sk) = dsa_keygen(DsaParam::Dsa65)?;
let sig = dsa_sign(&sk, b"message", b"")?;
assert!(dsa_verify(&pk, b"message", b"", &sig)?);
```

**Parameter Sets Table:**
| Algorithm | Parameter Set | Security Level | Key Size | Signature/CT Size |
|-----------|---------------|----------------|----------|-------------------|
| ML-KEM | KEM-512 | 1 (128-bit) | ... | ... |
| ML-KEM | KEM-768 | 3 (192-bit) | ... | ... |
| ML-KEM | KEM-1024 | 5 (256-bit) | ... | ... |
| ML-DSA | DSA-44 | 2 (128-bit) | ... | ... |
| ML-DSA | DSA-65 | 3 (192-bit) | ... | ... |
| ML-DSA | DSA-87 | 5 (256-bit) | ... | ... |

3. Add links section:
- [Full Examples](examples/) - Detailed usage examples
- [Security Guide](docs/SECURITY.md) - Security considerations
- [API Documentation](https://docs.rs/turtl) - Complete API reference
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) - ML-KEM Standard
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) - ML-DSA Standard

4. Ensure existing sections remain:
- Project description
- Features
- Building
- Testing
- License

Files to modify:
- README.md

References:
- examples/kem_basic.rs (for code snippets)
- examples/dsa_basic.rs (for code snippets)
- src/kem/params.rs and src/dsa/params.rs (for parameter table)
- See TASK_BREAKDOWN.md Task #9

Acceptance:
- Quickstart section is clear and concise
- Code examples are copy-pasteable and work
- Parameter table is accurate and complete
- Links are correct
- README renders nicely on GitHub
- Total README length is <500 lines (keep it concise)
```

---

## Task #10: Add API Documentation (rustdoc) 🟡

### Worker Prompt

```
Add comprehensive rustdoc comments to public APIs (Task #10):

Add detailed documentation to all public functions and types for generated API docs.

Your task:
1. Add module-level documentation (`//!`) to:
   - src/lib.rs (crate overview)
   - src/kem/mod.rs (ML-KEM module overview)
   - src/dsa/mod.rs (ML-DSA module overview)

2. Add doc comments (`///`) to all public items in:
   - src/kem/mod.rs:
     - `kem_keygen()` - document parameters, returns, errors
     - `kem_encapsulate()` - document usage, security notes
     - `kem_decapsulate()` - document usage, implicit rejection
     - `KemParam` enum - document each variant
     - `KemPublicKey`, `KemPrivateKey`, `KemCiphertext` types
     - Methods on `KemParam` (key sizes, security levels)

   - src/dsa/mod.rs:
     - `dsa_keygen()` - document parameters, returns, errors
     - `dsa_sign()` - document deterministic mode, context usage
     - `dsa_sign_hedged()` - document hedged mode, when to use
     - `dsa_verify()` - document verification process, errors
     - `DsaParam` enum - document each variant
     - `DsaPublicKey`, `DsaPrivateKey`, `Signature` types
     - `Stamp` struct and methods
     - Methods on `DsaParam`

   - src/error.rs:
     - Document each `TurtlError` variant (when it occurs)

3. Include in documentation:
   - Function purpose and usage
   - Parameter descriptions
   - Return value descriptions
   - Error conditions (which errors can be returned)
   - Code examples using ` ```rust` blocks
   - Security notes where relevant
   - References to FIPS 203/204 sections

4. Example documentation format:
```rust
/// Generates a new ML-KEM key pair.
///
/// # Arguments
///
/// * `param` - The parameter set (KEM-512, KEM-768, or KEM-1024)
///
/// # Returns
///
/// A tuple containing `(public_key, private_key)` on success.
///
/// # Errors
///
/// Returns `TurtlError::RandomnessError` if key generation fails
/// (extremely rare with properly functioning RNG).
///
/// # Example
///
/// ```rust
/// use turtl::kem::*;
///
/// let (pk, sk) = kem_keygen(KemParam::Kem768)?;
/// println!("Generated {}-bit security level keys", pk.param.security_level());
/// # Ok::<(), turtl::TurtlError>(())
/// ```
///
/// # Security
///
/// This function uses the system's cryptographically secure RNG.
/// Ensure the system RNG is properly seeded.
///
/// # Reference
///
/// FIPS 203 Section 7.1 - ML-KEM.KeyGen
pub fn kem_keygen(param: KemParam) -> Result<(KemPublicKey, KemPrivateKey), TurtlError> {
    // ...
}
```

5. Verify documentation:
   - Run `cargo doc --no-deps --open` and review output
   - Ensure no warnings from rustdoc
   - Check that examples compile (rustdoc tests them)

Files to modify:
- src/lib.rs
- src/kem/mod.rs
- src/dsa/mod.rs
- src/error.rs

References:
- Rust API Guidelines (https://rust-lang.github.io/api-guidelines/documentation.html)
- FIPS 203 and FIPS 204 specifications
- See PROJECT_DESIGN.md Section 5 (API Design)
- See TASK_BREAKDOWN.md Task #10

Acceptance:
- All public functions have `///` doc comments
- All public types have doc comments
- Module-level docs (`//!`) added
- Examples included in doc comments
- `cargo doc` produces no warnings
- Documentation is clear and helpful
- Security notes included where relevant
```

---

## Task #11: ML-KEM Interoperability Tests 🟢

### Worker Prompt

```
Create ML-KEM interoperability tests (Task #11):

Add tests using NIST Known Answer Tests (KAT) to validate byte-level compatibility.

Your task:
1. Obtain NIST KAT test vectors for ML-KEM:
   - Download from https://csrc.nist.gov/projects/post-quantum-cryptography
   - Or use pq-crystals/kyber repository test vectors
   - Focus on FIPS 203 final standard vectors

2. Create tests/kem_interop_test.rs with tests for:
   - ML-KEM-512 key generation from known seed
   - ML-KEM-768 key generation from known seed
   - ML-KEM-1024 key generation from known seed
   - Encapsulation with known randomness
   - Decapsulation with known ciphertext
   - At least 10 test vectors per parameter set

3. Test structure:
```rust
#[test]
fn test_kem_512_kat_001() {
    // Known seed (from NIST KAT)
    let seed = hex::decode("...").unwrap();

    // Expected public key (from NIST KAT)
    let expected_pk = hex::decode("...").unwrap();

    // Expected private key (from NIST KAT)
    let expected_sk = hex::decode("...").unwrap();

    // Generate key with deterministic RNG seeded with KAT seed
    let (pk, sk) = kem_keygen_with_seed(KemParam::Kem512, &seed).unwrap();

    // Verify byte-level match
    assert_eq!(pk.key, expected_pk);
    assert_eq!(sk.key, expected_sk);
}
```

4. You may need to add `kem_keygen_with_seed()` helper for deterministic testing:
   - Add to src/kem/keypair.rs
   - Takes fixed seed instead of using system RNG
   - Only for testing, not public API

5. Store test vectors in:
   - tests/data/kem_kat/kem512.txt
   - tests/data/kem_kat/kem768.txt
   - tests/data/kem_kat/kem1024.txt
   - Parse these files in test code

Files to create:
- tests/kem_interop_test.rs (new file, ~500 lines)
- tests/data/kem_kat/*.txt (test vector files)
- Possibly src/kem/keypair.rs (add test helper)

References:
- NIST KAT format documentation
- FIPS 203 Appendix A (test vectors)
- See TASK_BREAKDOWN.md Task #11

Acceptance:
- At least 30 test vectors total (10 per parameter set)
- Tests cover keygen, encaps, decaps
- All tests pass
- Validates byte-level compatibility with reference implementation
- Test vectors are from official NIST source
```

---

## Task #12: ML-DSA Interoperability Tests 🟢

### Worker Prompt

```
Create ML-DSA interoperability tests (Task #12):

REQUIRES: Task #1, Task #2 (working ML-DSA implementation)

Add tests using NIST Known Answer Tests (KAT) to validate byte-level compatibility.

Your task:
1. Obtain NIST KAT test vectors for ML-DSA:
   - Download from https://csrc.nist.gov/projects/post-quantum-cryptography
   - Or use pq-crystals/dilithium repository test vectors
   - Focus on FIPS 204 final standard vectors

2. Create tests/dsa_interop_test.rs with tests for:
   - ML-DSA-44 key generation from known seed
   - ML-DSA-65 key generation from known seed
   - ML-DSA-87 key generation from known seed
   - Deterministic signing with known key and message
   - Signature verification with known signature
   - At least 10 test vectors per parameter set

3. Test structure similar to Task #11:
```rust
#[test]
fn test_dsa_65_kat_001() {
    let seed = hex::decode("...").unwrap();
    let message = hex::decode("...").unwrap();
    let context = b"";

    let expected_pk = hex::decode("...").unwrap();
    let expected_sk = hex::decode("...").unwrap();
    let expected_sig = hex::decode("...").unwrap();

    // Generate key with deterministic RNG
    let (pk, sk) = dsa_keygen_with_seed(DsaParam::Dsa65, &seed).unwrap();

    // Verify keys match
    assert_eq!(pk.key, expected_pk);
    assert_eq!(sk.key, expected_sk);

    // Sign message deterministically
    let sig = dsa_sign(&sk, &message, context).unwrap();

    // Verify signature matches (deterministic signing!)
    assert_eq!(sig.data, expected_sig);

    // Verify signature
    assert!(dsa_verify(&pk, &message, context, &sig).unwrap());
}
```

4. You may need to add `dsa_keygen_with_seed()` helper for deterministic testing

5. Store test vectors in tests/data/dsa_kat/*.txt

Files to create:
- tests/dsa_interop_test.rs (new file, ~600 lines)
- tests/data/dsa_kat/*.txt (test vector files)
- Possibly src/dsa/keypair.rs (add test helper)

References:
- NIST KAT format documentation
- FIPS 204 Appendix A (test vectors)
- See TASK_BREAKDOWN.md Task #12

Acceptance:
- At least 30 test vectors total (10 per parameter set)
- Tests cover keygen, signing, verification
- All tests pass
- Validates byte-level compatibility with reference implementation
- Test vectors are from official NIST source
- Deterministic signing produces exact same signature as reference
```

---

## Task #13: Expand Security Audit Documentation 🟢

### Worker Prompt

```
Update AUDIT_SUMMARY.md with post-fix validation (Task #13):

REQUIRES: Task #1, #2, #3, #4 complete (all critical bugs fixed)

Update the audit summary to reflect that the NTT bug has been fixed and document current security status.

Your task:
1. Read existing AUDIT_SUMMARY.md to understand current state

2. Add a new section: "Post-Fix Validation (2026-01-XX)"
   - Document that ML-DSA NTT bug was fixed in Task #1
   - Describe the fix (what was changed)
   - Validation results:
     - All DSA tests now pass
     - Signing success rate (should be >99%)
     - Average retry count (should be <1000)
   - NTT correctness tests added (Task #4)

3. Update "Current Status" section:
   - Change ML-DSA status from "BROKEN" to "FUNCTIONAL"
   - Update test pass/fail counts
   - Note that all 107+ tests now pass

4. Add "Remaining Security Considerations" section:
   - Items still pending: interop tests, fuzzing, SIMD optimization
   - Known limitations (no hardware side-channel protection)
   - Recommendations for production use
   - Security best practices

5. Update "Recommendations" section:
   - ML-KEM: Ready for production (with caveats)
   - ML-DSA: Ready for production (post-fix)
   - Testing recommendations
   - Deployment considerations

6. Add "Validation Checklist":
   - [ ] All unit tests passing ✅
   - [ ] All integration tests passing ✅
   - [ ] ML-KEM interoperability tests (Task #11)
   - [ ] ML-DSA interoperability tests (Task #12)
   - [ ] Fuzzing (Task #15)
   - [ ] Performance benchmarks (Task #14)
   - [ ] Security documentation (Task #7) ✅
   - [ ] Code review by cryptography expert (pending)

Files to modify:
- AUDIT_SUMMARY.md

References:
- Existing AUDIT_SUMMARY.md content
- Test results from Task #1-4
- See TASK_BREAKDOWN.md Task #13

Acceptance:
- Document clearly states NTT bug is fixed
- Validation results are documented
- Current status is accurate
- Remaining work is clearly listed
- Recommendations are actionable
- Document is well-organized and professional
```

---

## Task #14: Benchmark Performance Baseline 🟢

### Worker Prompt

```
Document performance baseline (Task #14):

REQUIRES: Task #1, #2 (working implementations for both algorithms)

Run comprehensive benchmarks and document baseline performance for future optimization.

Your task:
1. Run all existing benchmarks:
   ```
   cargo bench --bench kem_benchmark
   cargo bench --bench dsa_benchmark
   cargo bench --bench ntt_benchmark
   ```

2. Create docs/PERFORMANCE.md documenting:

**Test Environment:**
- CPU model and frequency
- RAM amount
- OS version
- Rust compiler version
- Optimization level (--release)
- Date of benchmark

**ML-KEM Performance:**
| Operation | KEM-512 | KEM-768 | KEM-1024 |
|-----------|---------|---------|----------|
| KeyGen | X μs | X μs | X μs |
| Encapsulate | X μs | X μs | X μs |
| Decapsulate | X μs | X μs | X μs |

**ML-DSA Performance:**
| Operation | DSA-44 | DSA-65 | DSA-87 |
|-----------|--------|--------|--------|
| KeyGen | X μs | X μs | X μs |
| Sign (avg) | X ms | X ms | X ms |
| Sign (retries) | X | X | X |
| Verify | X μs | X μs | X μs |

**NTT Performance:**
| Operation | ML-KEM (q=3329) | ML-DSA (q=8380417) |
|-----------|-----------------|---------------------|
| NTT Forward | X μs | X μs |
| NTT Inverse | X μs | X μs |

**Memory Usage:**
- Stack usage per operation (estimate)
- Heap allocations per operation
- Total memory footprint

**Throughput Estimates:**
- Operations per second for each algorithm
- Messages signed per second
- Key exchanges per second

3. Compare with reference implementation (if available):
   - Download pq-crystals reference C implementation
   - Compile and benchmark same operations
   - Add comparison table to PERFORMANCE.md

4. Add "Optimization Opportunities" section:
   - Identify slowest operations (candidates for optimization)
   - Estimate potential speedup (e.g., "NTT could be 2-4x faster with SIMD")
   - Prioritize optimization tasks

Files to create:
- docs/PERFORMANCE.md (new file, ~400 lines)

Files to potentially modify:
- benches/*.rs (if benchmarks need improvements)

References:
- Existing benchmark files in benches/
- criterion.rs documentation
- See TASK_BREAKDOWN.md Task #14

Acceptance:
- All benchmarks run successfully
- Performance data documented in clear tables
- Test environment fully specified
- Comparison with reference implementation (if feasible)
- Optimization opportunities identified
- Baseline established for future optimization tasks
```

---

## Task #15: Add Fuzzing Infrastructure 🟢

### Worker Prompt

```
Set up fuzzing infrastructure with cargo-fuzz (Task #15):

Add fuzzing to find edge cases and potential bugs in TURTL.

Your task:
1. Install and configure cargo-fuzz:
   ```
   cargo install cargo-fuzz
   cargo fuzz init
   ```

2. Create fuzz targets in fuzz/fuzz_targets/:

**a) fuzz_kem_encapsulate.rs:**
- Fuzz public key input to encapsulation
- Test various key sizes, malformed keys
- Ensure no panics or crashes

**b) fuzz_kem_decapsulate.rs:**
- Fuzz ciphertext input to decapsulation
- Test various ciphertext sizes, malformed ciphertexts
- Ensure proper error handling (no panics)

**c) fuzz_dsa_verify.rs:**
- Fuzz signature input to verification
- Test various signature sizes, malformed signatures
- Test message and context fuzzing
- Ensure no panics

**d) fuzz_ntt.rs:**
- Fuzz polynomial coefficients to NTT
- Test edge cases: extreme values, zero, negative
- Ensure NTT doesn't panic on any input

3. Example fuzz target structure:
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use turtl::kem::*;

fuzz_target!(|data: &[u8]| {
    // Try to construct a public key from fuzzed data
    if data.len() < 100 { return; }  // Skip too-short inputs

    let param = KemParam::Kem768;
    let pk = KemPublicKey {
        param,
        key: data.to_vec(),
    };

    // Try to encapsulate (should not panic)
    let _ = kem_encapsulate(&pk);

    // Expect either success or proper error handling
    // NO PANICS ALLOWED
});
```

4. Create fuzz/README.md explaining:
   - How to run fuzzing: `cargo fuzz run fuzz_target_name`
   - Recommended fuzzing duration (at least 1 hour per target)
   - How to reproduce crashes
   - How to add new fuzz targets

5. Run initial fuzzing:
   - Fuzz each target for at least 1 hour
   - Document any crashes/bugs found
   - Fix any issues discovered
   - Re-run until clean

6. Add to CI (optional but recommended):
   - Add GitHub Actions job for fuzzing
   - Run short fuzzing session (5 minutes) on each PR

Files to create:
- fuzz/fuzz_targets/fuzz_kem_encapsulate.rs
- fuzz/fuzz_targets/fuzz_kem_decapsulate.rs
- fuzz/fuzz_targets/fuzz_dsa_verify.rs
- fuzz/fuzz_targets/fuzz_ntt.rs
- fuzz/README.md
- fuzz/Cargo.toml (auto-generated by cargo fuzz init)

References:
- cargo-fuzz documentation: https://rust-fuzz.github.io/book/cargo-fuzz.html
- See TASK_BREAKDOWN.md Task #15

Acceptance:
- 4+ fuzz targets created
- Each target runs without crashes for 1+ hour
- README explains how to use fuzzing
- Any found bugs are documented and fixed
- Fuzzing infrastructure is ready for ongoing use
```

---

## Task #16: Profile NTT Performance Bottlenecks 🔵

### Worker Prompt

```
Profile NTT implementation to identify optimization opportunities (Task #16):

REQUIRES: Task #14 (performance baseline established)

Use profiling tools to identify performance bottlenecks in NTT code.

Your task:
1. Install profiling tools:
   ```
   cargo install flamegraph
   cargo install cargo-instruments  # macOS only
   ```
   Or use perf on Linux

2. Generate flamegraph for NTT benchmarks:
   ```
   cargo flamegraph --bench ntt_benchmark -- --bench
   ```
   This creates flamegraph.svg showing time distribution

3. Profile with perf (Linux):
   ```
   cargo build --release --bench ntt_benchmark
   perf record -g target/release/deps/ntt_benchmark-* --bench
   perf report
   ```

4. Analyze and document:
   - Top 5 hotspots in NTT code (functions taking most time)
   - Cache miss rates (use `perf stat -e cache-misses`)
   - Branch misprediction rates
   - Instruction-level breakdown

5. Update docs/PERFORMANCE.md with "Profiling Results" section:
   - Include flamegraph (or link to it)
   - List hotspots with percentage of time
   - Identify optimization opportunities:
     - Which functions are slowest?
     - Are there unnecessary allocations?
     - Cache locality issues?
     - Branch prediction problems?

6. Propose optimizations:
   - SIMD vectorization potential
   - Algorithm improvements (Karatsuba?)
   - Memory layout optimization
   - Loop unrolling opportunities

Files to modify:
- docs/PERFORMANCE.md (add profiling section)

Files to create:
- docs/flamegraph.svg (or similar)

References:
- Rust Performance Book: https://nnethercote.github.io/perf-book/
- See TASK_BREAKDOWN.md Task #16

Acceptance:
- Flamegraph generated and analyzed
- Top 5 hotspots identified and documented
- Optimization opportunities clearly listed
- Proposed optimizations are specific and actionable
- Results documented in PERFORMANCE.md
```

---

## Task #17: Optimize Polynomial Multiplication 🔵

### Worker Prompt

```
Optimize polynomial multiplication if profiling shows it's a bottleneck (Task #17):

REQUIRES: Task #16 (profiling complete)

Investigate and potentially implement optimized polynomial multiplication.

Your task:
1. Review profiling results from Task #16
   - Is polynomial multiplication a significant bottleneck?
   - If not, document that and skip optimization (or propose alternative)

2. If polynomial multiplication is a bottleneck:
   - Research Karatsuba multiplication for NTT-based polynomial multiplication
   - Research other optimization techniques (Toom-Cook, etc.)
   - Determine if optimization is worthwhile

3. Implement optimization (if justified):
   - Create optimized variant in src/common/poly_opt.rs
   - Keep original implementation as fallback
   - Add feature flag: `optimized-poly` in Cargo.toml

4. Benchmark before/after:
   - Run NTT benchmarks with original code
   - Run NTT benchmarks with optimized code
   - Measure speedup percentage
   - Ensure speedup is at least 10% or don't merge

5. Ensure correctness:
   - All NTT tests still pass with optimized code
   - Add specific tests for optimized variant
   - Verify with test vectors

6. Document optimization in docs/PERFORMANCE.md:
   - Describe what was optimized
   - Benchmark results (before/after)
   - Trade-offs (code complexity vs speed)

Files to create/modify:
- src/common/poly_opt.rs (if optimization implemented)
- Cargo.toml (add feature flag if needed)
- docs/PERFORMANCE.md (update)

References:
- Karatsuba algorithm: https://en.wikipedia.org/wiki/Karatsuba_algorithm
- NTT optimization literature
- See TASK_BREAKDOWN.md Task #17

Acceptance:
- Profiling confirms this is a worthwhile optimization
- Implementation is correct (all tests pass)
- Speedup is at least 10%
- Optimization is documented
- OR: Document that optimization is not worthwhile and explain why
```

---

## Task #18: Add SIMD/AVX2 NTT Implementation 🔵

### Worker Prompt

```
Implement vectorized NTT using SIMD intrinsics (Task #18):

REQUIRES: Task #16, Task #17 (profiling and other optimizations done)

Add SIMD-accelerated NTT for x86_64 platforms with AVX2 support.

Your task:
1. Create src/common/ntt_simd.rs with SIMD NTT implementation:
   - Use AVX2 intrinsics (256-bit vectors)
   - Implement both forward and inverse NTT
   - Maintain constant-time properties
   - Fall back to scalar on non-AVX2 platforms

2. Use platform detection:
   ```rust
   #[cfg(target_arch = "x86_64")]
   use std::arch::x86_64::*;

   fn ntt_forward_simd(poly: &Polynomial, param: NttParam) -> Polynomial {
       #[cfg(target_feature = "avx2")]
       {
           // SIMD implementation
       }
       #[cfg(not(target_feature = "avx2"))]
       {
           // Fall back to scalar
           ntt_forward(poly, param)
       }
   }
   ```

3. Add feature flag in Cargo.toml:
   ```toml
   [features]
   simd = []
   ```

4. Vectorize the core NTT butterfly operations:
   - Process 8 coefficients at a time (AVX2 = 256 bits, i32 = 32 bits)
   - Use SIMD for modular arithmetic where possible
   - Maintain correctness!

5. Benchmark SIMD vs scalar:
   - Run benches/ntt_benchmark.rs with and without SIMD
   - Document speedup (target: 2-4x faster)
   - Test on multiple CPUs if possible

6. Maintain correctness:
   - All NTT tests must pass with SIMD version
   - Verify output is bitwise identical to scalar version
   - Test on both AVX2 and non-AVX2 systems

7. Document in docs/PERFORMANCE.md:
   - SIMD implementation details
   - Benchmark results
   - Platform requirements (AVX2)
   - How to enable: `cargo build --features simd`

Files to create:
- src/common/ntt_simd.rs (new file, ~500 lines)

Files to modify:
- Cargo.toml (add simd feature)
- src/common/mod.rs (conditionally export SIMD functions)
- docs/PERFORMANCE.md (document SIMD)

References:
- Rust SIMD guide: https://rust-lang.github.io/packed_simd/perf-guide/
- AVX2 intrinsics: https://software.intel.com/sites/landingpage/IntrinsicsGuide/
- NTT vectorization papers (search for "vectorized NTT")
- See TASK_BREAKDOWN.md Task #18

Acceptance:
- SIMD NTT implementation compiles and runs
- Speedup is at least 2x on AVX2-capable CPUs
- All tests pass with SIMD enabled
- Falls back gracefully on non-SIMD platforms
- Constant-time properties maintained
- Well documented

Notes:
- This is a VERY HIGH complexity task
- Consider using existing SIMD libraries if helpful
- Test thoroughly - SIMD bugs are subtle
```

---

## Task #19: Optimize Memory Allocations 🔵

### Worker Prompt

```
Reduce heap allocations in hot paths (Task #19):

REQUIRES: Task #16 (profiling shows allocation hotspots)

Optimize memory usage by reducing unnecessary heap allocations.

Your task:
1. Profile heap allocations:
   ```
   # Linux
   valgrind --tool=massif cargo bench --bench ntt_benchmark
   ms_print massif.out.* > heap_profile.txt

   # Or use DHAT
   valgrind --tool=dhat cargo bench --bench ntt_benchmark
   ```

2. Identify allocation hotspots:
   - Which functions allocate most frequently?
   - Are allocations necessary or can they be stack-based?
   - Can buffers be reused across operations?

3. Optimization strategies:
   - Use stack-allocated arrays where possible: `[i32; 256]` instead of `Vec<i32>`
   - Reuse buffers in loops
   - Use `arrayvec` crate for fixed-size vectors
   - Pass mutable buffers instead of allocating new ones

4. Example optimization:
   ```rust
   // Before (allocates on each call)
   fn ntt_forward(poly: &Polynomial) -> Polynomial {
       let mut result = Vec::with_capacity(256);
       // ...
       Polynomial { coeffs: result }
   }

   // After (uses stack or reuses buffer)
   fn ntt_forward_inplace(poly: &mut Polynomial) {
       // Modify poly in place, no allocation
   }

   // Or use stack
   fn ntt_forward(poly: &Polynomial) -> Polynomial {
       let mut result = [0i32; 256];  // Stack allocation
       // ...
       Polynomial { coeffs: result.to_vec() }
   }
   ```

5. Measure impact:
   - Benchmark before/after with massif or DHAT
   - Document reduction in heap allocations (target: 20%+ reduction)
   - Measure performance impact (should not slow down)

6. Ensure correctness:
   - All tests still pass
   - No memory safety issues
   - No stack overflow (watch stack usage)

7. Document in docs/PERFORMANCE.md:
   - Allocation hotspots identified
   - Optimizations applied
   - Before/after comparison
   - Performance impact

Files to modify:
- src/common/poly.rs (likely candidate)
- src/common/ntt.rs (likely candidate)
- src/kem/internal/mod.rs (possibly)
- src/dsa/internal/mod.rs (possibly)
- Cargo.toml (if adding arrayvec dependency)
- docs/PERFORMANCE.md (document results)

References:
- Rust Performance Book: https://nnethercote.github.io/perf-book/heap-allocations.html
- arrayvec crate: https://docs.rs/arrayvec/
- See TASK_BREAKDOWN.md Task #19

Acceptance:
- Allocation profiling completed
- At least 20% reduction in heap allocations OR explanation why not worthwhile
- All tests pass
- Performance is maintained or improved
- Documentation updated
```

---

## Task #20: Benchmark Comparison with Reference Implementations 🔵

### Worker Prompt

```
Compare TURTL performance with reference implementations (Task #20):

REQUIRES: Task #14 (baseline established), optionally Task #17-19 (optimizations)

Benchmark TURTL against official reference implementations and competitors.

Your task:
1. Download and build reference implementations:
   - pq-crystals/kyber (ML-KEM reference C implementation)
   - pq-crystals/dilithium (ML-DSA reference C implementation)
   - Optionally: other Rust PQC libraries if they exist

2. Create benches/comparison/ directory with comparison benchmarks:
   - Ensure fair comparison (same CPU, same test data)
   - Benchmark the same operations (keygen, encaps, decaps, sign, verify)
   - Use the same compiler optimization levels

3. Create comparison harness:
   - benches/comparison/compare_kem.sh (shell script)
   - Build reference implementations with optimizations
   - Run both TURTL and reference benchmarks
   - Collect results in comparable format

4. Create comparison table in docs/PERFORMANCE.md:

**ML-KEM Performance Comparison**
| Operation | TURTL (KEM-768) | Reference C | Ratio | Notes |
|-----------|-----------------|-------------|-------|-------|
| KeyGen | X μs | Y μs | X/Y | |
| Encapsulate | X μs | Y μs | X/Y | |
| Decapsulate | X μs | Y μs | X/Y | |

**ML-DSA Performance Comparison**
| Operation | TURTL (DSA-65) | Reference C | Ratio | Notes |
|-----------|----------------|-------------|-------|-------|
| KeyGen | X μs | Y μs | X/Y | |
| Sign | X ms | Y ms | X/Y | |
| Verify | X μs | Y μs | X/Y | |

5. Analyze results:
   - Where is TURTL faster? (likely: safety overhead compensated by optimizations)
   - Where is TURTL slower? (identify why - safety checks, allocations, etc.)
   - What's the overhead of Rust safety vs C?
   - Are there opportunities for further optimization?

6. Compare with other Rust implementations (if available):
   - Search crates.io for PQC libraries
   - Benchmark if found
   - Note differences (safety, features, completeness)

7. Document findings:
   - Add "Performance Comparison" section to docs/PERFORMANCE.md
   - Be honest about relative performance
   - Explain trade-offs (safety vs speed, features vs simplicity)
   - Identify future optimization priorities based on gaps

Files to create:
- benches/comparison/compare_kem.sh
- benches/comparison/compare_dsa.sh
- benches/comparison/README.md (how to run)

Files to modify:
- docs/PERFORMANCE.md (add comparison section)

External dependencies:
- Clone pq-crystals/kyber and pq-crystals/dilithium
- May need to build with CMake or Make

References:
- pq-crystals repositories: https://github.com/pq-crystals
- Criterion benchmarking: https://bheisler.github.io/criterion.rs/book/
- See TASK_BREAKDOWN.md Task #20

Acceptance:
- Comparison benchmarks run successfully
- Results documented in clear tables
- Analysis explains performance differences
- Identifies specific areas for future optimization
- Fair comparison (apples-to-apples)
- Honest assessment of TURTL's competitive position
```

---

## Task #21: External Cryptography Audit 🔴

### Worker Prompt

```
Coordinate external cryptography audit (Task #21):

REQUIRES: Tasks #1-15 complete (all core functionality)

This task involves coordinating with a professional cryptography auditing firm for independent security review.

Your task:
1. Research and document reputable cryptography auditing firms:
   - Trail of Bits (https://www.trailofbits.com/)
   - NCC Group (https://www.nccgroup.com/)
   - Kudelski Security
   - QuarksLab
   - Document their expertise, pricing, timeline

2. Create audit scope document (docs/AUDIT_SCOPE.md):
   - Code to be audited: src/common/ntt.rs, src/kem/, src/dsa/, src/security/
   - Focus areas:
     - NTT implementation correctness vs FIPS 203/204
     - Side-channel resistance (timing, cache)
     - Constant-time operation validation
     - Cryptographic correctness
   - Out of scope: Performance optimization, documentation quality
   - Timeline: 2-4 weeks
   - Deliverables: Formal audit report, findings presentation

3. Create RFP (Request for Proposal) template:
   - Project description
   - Audit scope
   - Required expertise (lattice-based cryptography)
   - Timeline expectations
   - Budget range ($15k-$50k)

4. Document the process in docs/AUDIT_PROCESS.md:
   - How to select auditor
   - How to coordinate audit
   - How to handle findings
   - How to publish results

5. Note: This task documents the process. ACTUAL hiring requires human decision.

Files to create:
- docs/AUDIT_SCOPE.md (audit scope definition)
- docs/AUDIT_PROCESS.md (process documentation)
- docs/AUDITOR_RESEARCH.md (firm comparison)
- docs/RFP_TEMPLATE.md (request for proposal)

References:
- See TASK_BREAKDOWN.md Task #21
- Trail of Bits public audits: https://github.com/trailofbits/publications

Acceptance:
- Auditor research completed with 3+ firms evaluated
- Audit scope clearly defined
- RFP template ready to send
- Process documented for human coordination
- Note: Actual audit requires human to hire firm and coordinate
```

### Implementation Notes
- This task CANNOT be fully automated (requires budget approval, contracts)
- Worker should prepare all materials for human decision-maker
- External audit is MANDATORY for production cryptography
- Budget 2-4 weeks after contract signed

---

## Task #22: Validate Constant-Time Properties 🔴

### Worker Prompt

```
Validate constant-time operations with statistical testing (Task #22):

REQUIRES: Task #1-4 (working implementation)

Enable and run timing tests to ensure constant-time properties are maintained.

Your task:
1. Unignore timing tests in tests/timing_invariance_test.rs:
   - Remove #[ignore] attributes
   - Add comments explaining what each test validates

2. Enhance timing tests with statistical rigor:
   - Implement Welch's t-test for timing differences
   - Test each constant-time operation 10,000+ times
   - Collect timing samples with CPU cycle counters
   - Statistical threshold: p-value > 0.05 (no detectable leak)

3. Test these operations for constant-time:
   - ct_cmov (constant-time conditional move)
   - ct_eq (constant-time equality)
   - ct_select (constant-time selection)
   - KEM decapsulation (implicit rejection must be CT)
   - DSA signature verification

4. Set up `ctgrind` testing:
   ```bash
   # Install ctgrind (valgrind plugin for constant-time validation)
   # Run tests under ctgrind
   valgrind --tool=ctgrind cargo test constant_time
   ```

5. Document methodology in docs/TIMING_VALIDATION.md:
   - Test environment requirements (dedicated machine, minimal noise)
   - Statistical methodology (Welch's t-test, sample sizes)
   - How to interpret results
   - Known limitations (compiler optimizations may break CT)

6. Add CI job for timing validation (mark as manual):
   ```yaml
   # .github/workflows/timing.yml
   # Runs on manual trigger only (requires quiet environment)
   ```

7. If timing leaks found:
   - Document the leak
   - Fix if possible (may require algorithm changes)
   - If unfixable, document limitation

Files to modify:
- tests/timing_invariance_test.rs (unignore, enhance)

Files to create:
- docs/TIMING_VALIDATION.md (methodology and results)
- .github/workflows/timing.yml (manual CI job)
- tools/run_timing_tests.sh (helper script)

References:
- dudect: https://github.com/oreparaz/dudect
- ctgrind: https://github.com/agl/ctgrind
- See TASK_BREAKDOWN.md Task #22

Acceptance:
- All timing tests unignored and running
- Statistical tests implemented (t-tests)
- Tests run successfully with p > 0.05 for all CT operations
- ctgrind validation completed
- Methodology documented
- Any leaks found are documented and ideally fixed
```

---

## Task #23: Cross-Platform CI Testing 🟡

### Worker Prompt

```
Add cross-platform testing to CI (Task #23):

Add Windows, macOS, and ARM64 to CI matrix to catch platform-specific bugs.

Your task:
1. Update .github/workflows/ci.yml to add matrix strategy:
   ```yaml
   strategy:
     matrix:
       os: [ubuntu-latest, windows-latest, macos-latest]
       rust: [stable, nightly]
       include:
         # ARM64 testing on Linux
         - os: ubuntu-latest
           target: aarch64-unknown-linux-gnu
   runs-on: ${{ matrix.os }}
   ```

2. Handle platform-specific differences:
   - Windows: Path separators, line endings
   - macOS: Different CPU architecture (ARM64 on M1+)
   - ARM64: Endianness testing

3. Add cross-compilation test for ARM64:
   ```yaml
   - name: Install ARM64 target
     run: rustup target add aarch64-unknown-linux-gnu
   - name: Build for ARM64
     run: cargo build --target aarch64-unknown-linux-gnu
   ```

4. Ensure all tests pass on all platforms:
   - Run full test suite on Windows, macOS, Linux
   - Fix any platform-specific failures
   - Common issues:
     - File path separators (use std::path)
     - Endianness (TURTL should be endian-neutral)
     - Integer size assumptions

5. Update README.md with platform support:
   ```markdown
   ## Platform Support

   TURTL is tested on:
   - Linux (x86_64, ARM64)
   - macOS (x86_64, Apple Silicon)
   - Windows (x86_64)
   - Rust stable and nightly
   ```

6. Add platform badges to README:
   ```markdown
   ![Linux](https://github.com/user/turtl/workflows/CI/badge.svg?os=ubuntu-latest)
   ![macOS](https://github.com/user/turtl/workflows/CI/badge.svg?os=macos-latest)
   ![Windows](https://github.com/user/turtl/workflows/CI/badge.svg?os=windows-latest)
   ```

Files to modify:
- .github/workflows/ci.yml (add matrix strategy)
- README.md (document platform support)

References:
- GitHub Actions matrix: https://docs.github.com/en/actions/using-jobs/using-a-matrix-for-your-jobs
- See TASK_BREAKDOWN.md Task #23

Acceptance:
- CI runs on Ubuntu, Windows, macOS
- ARM64 cross-compilation succeeds
- All tests pass on all platforms
- Platform support documented in README
- CI badges added
```

---

## Task #24: Security Monitoring Infrastructure 🟡

### Worker Prompt

```
Set up continuous security monitoring (Task #24):

Add cargo-audit, SBOM generation, and Dependabot for supply chain security.

Your task:
1. Create .github/workflows/security.yml for daily vulnerability scans:
   ```yaml
   name: Security Audit

   on:
     schedule:
       - cron: '0 0 * * *'  # Daily at midnight UTC
     push:
       branches: [main]
     pull_request:

   jobs:
     audit:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - name: Cargo Audit
           run: |
             cargo install cargo-audit
             cargo audit
   ```

2. Set up SBOM (Software Bill of Materials) generation:
   ```bash
   # Install cargo-sbom
   cargo install cargo-sbom

   # Generate SBOM
   cargo sbom --output-format spdx > SBOM.spdx
   cargo sbom --output-format cyclonedx > SBOM.json
   ```

3. Add SBOM generation to release workflow:
   - Generate SBOM on every release
   - Attach SBOM files to GitHub release
   - Document in RELEASES.md

4. Enable Dependabot:
   Create .github/dependabot.yml:
   ```yaml
   version: 2
   updates:
     - package-ecosystem: "cargo"
       directory: "/"
       schedule:
         interval: "weekly"
       open-pull-requests-limit: 5
   ```

5. Document security monitoring in SECURITY.md:
   ```markdown
   ## Security Monitoring

   TURTL uses:
   - cargo-audit: Daily vulnerability scans
   - Dependabot: Automated dependency updates
   - SBOM: Software Bill of Materials for transparency

   View security advisories: https://github.com/user/turtl/security/advisories
   ```

6. Set up GitHub Security Advisories:
   - Enable private vulnerability reporting
   - Configure security policy
   - Document in SECURITY.md

Files to create:
- .github/workflows/security.yml
- .github/dependabot.yml
- SBOM.spdx (template, generated on release)
- SBOM.json (template, generated on release)

Files to modify:
- SECURITY.md (add security monitoring section)
- RELEASES.md (document SBOM generation)

References:
- cargo-audit: https://github.com/rustsec/rustsec
- SBOM: https://www.ntia.gov/sbom
- Dependabot: https://docs.github.com/en/code-security/dependabot
- See TASK_BREAKDOWN.md Task #24

Acceptance:
- Daily security scans running
- Dependabot enabled and configured
- SBOM generation automated
- Security monitoring documented
- GitHub security advisories enabled
```

---

## Task #25: Memory Safety Testing (Miri/Valgrind) 🟡

### Worker Prompt

```
Run memory safety tests with Miri and Valgrind (Task #25):

REQUIRES: Task #1-4 (working tests)

Detect undefined behavior and memory leaks using specialized tools.

Your task:
1. Set up Miri testing:
   ```bash
   # Install Miri
   rustup +nightly component add miri

   # Run tests under Miri
   cargo +nightly miri test
   ```

2. Create subset of tests for Miri (it's slow):
   - Run unit tests only (skip long integration tests)
   - Focus on: NTT, polynomial arithmetic, crypto operations
   - Document which tests are Miri-compatible

3. Add Miri CI workflow (.github/workflows/miri.yml):
   ```yaml
   name: Miri

   on:
     schedule:
       - cron: '0 0 * * 0'  # Weekly (Miri is slow)
     workflow_dispatch:  # Manual trigger

   jobs:
     miri:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - name: Install Miri
           run: |
             rustup toolchain install nightly --component miri
             cargo +nightly miri setup
         - name: Run Miri tests
           run: cargo +nightly miri test --lib
   ```

4. Set up Valgrind testing:
   ```bash
   # Build test binary
   cargo test --no-run

   # Run under Valgrind
   valgrind --leak-check=full \
            --show-leak-kinds=all \
            --track-origins=yes \
            target/debug/deps/turtl-*
   ```

5. Test with AddressSanitizer (ASAN):
   ```bash
   RUSTFLAGS="-Z sanitizer=address" \
   cargo +nightly test --target x86_64-unknown-linux-gnu
   ```

6. Document results in docs/MEMORY_SAFETY.md:
   - Miri test results (pass/fail, any UB detected)
   - Valgrind results (memory leaks, invalid reads/writes)
   - ASAN results (address violations)
   - Interpretation of results
   - Any false positives or known issues

7. Fix any issues found:
   - Undefined behavior detected by Miri → critical bug
   - Memory leaks → likely in tests, not library (Vec zeroization should prevent)
   - Document if unfixable (e.g., in dependency)

Files to create:
- .github/workflows/miri.yml
- docs/MEMORY_SAFETY.md
- tools/run_valgrind.sh (helper script)

References:
- Miri: https://github.com/rust-lang/miri
- Valgrind: https://valgrind.org/
- Sanitizers: https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html
- See TASK_BREAKDOWN.md Task #25

Acceptance:
- Miri tests run successfully (no UB detected)
- Valgrind reports no memory leaks
- ASAN tests pass
- Results documented in MEMORY_SAFETY.md
- Any issues found are fixed or documented
- Weekly Miri CI job configured
```

---

## Task #26: Release Process and Security Disclosure 🟡

### Worker Prompt

```
Document release process and security vulnerability disclosure (Task #26):

Create comprehensive documentation for releases and security handling.

Your task:
1. Create RELEASES.md documenting release process:
   ```markdown
   # Release Process

   ## Versioning

   TURTL follows Semantic Versioning 2.0:
   - MAJOR: Breaking API changes
   - MINOR: New features, backward compatible
   - PATCH: Bug fixes, backward compatible

   ## Pre-release Checklist

   - [ ] All tests passing
   - [ ] Benchmarks run (no regressions)
   - [ ] CHANGELOG.md updated
   - [ ] Version bumped in Cargo.toml
   - [ ] Documentation updated
   - [ ] Security audit complete (for major releases)
   - [ ] SBOM generated

   ## Release Steps

   1. Create release branch: `git checkout -b release/v0.2.0`
   2. Update version: Edit Cargo.toml
   3. Update CHANGELOG.md with release notes
   4. Run full test suite: `cargo test --release`
   5. Generate SBOM: `cargo sbom > SBOM.spdx`
   6. Commit: `git commit -m "Release v0.2.0"`
   7. Tag: `git tag -s v0.2.0 -m "Release v0.2.0"`
   8. Push: `git push --tags`
   9. Create GitHub release with SBOM attached
   10. Publish to crates.io: `cargo publish`

   ## Post-release

   - Announce on security mailing list
   - Update documentation site
   - Monitor for issues
   ```

2. Initialize CHANGELOG.md:
   ```markdown
   # Changelog

   All notable changes to TURTL will be documented in this file.

   The format is based on [Keep a Changelog](https://keepachangelog.com/),
   and this project adheres to [Semantic Versioning](https://semver.org/).

   ## [Unreleased]

   ### Added
   - Initial ML-KEM implementation (FIPS 203)
   - Initial ML-DSA implementation (FIPS 204)
   - Constant-time operations
   - Memory zeroization
   - Fault detection mechanisms

   ### Fixed
   - ML-DSA NTT implementation (Task #1)

   ## [0.1.0] - 2026-XX-XX (Upcoming)

   ### Added
   - First public release
   - ML-KEM-512, ML-KEM-768, ML-KEM-1024
   - ML-DSA-44, ML-DSA-65, ML-DSA-87
   ```

3. Expand SECURITY.md with vulnerability disclosure:
   ```markdown
   ## Reporting Security Vulnerabilities

   **DO NOT open public GitHub issues for security vulnerabilities.**

   ### Contact

   Email: security@turtl-project.org (create this alias)
   PGP Key: [Generate and publish key]

   ### What to Include

   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if known)

   ### Response Timeline

   - Initial response: Within 48 hours
   - Status update: Within 7 days
   - Fix timeline: Depends on severity
     - Critical: Within 7 days
     - High: Within 30 days
     - Medium: Within 90 days

   ### Disclosure Policy

   - Coordinated disclosure: 90 days from report
   - Earlier if fix is available and deployed
   - Credit given to reporter (unless anonymous requested)

   ### Security Response Team

   - [Your name/contact]
   - [Backup contact]

   ### Past Vulnerabilities

   None reported yet. This section will list CVEs as they occur.
   ```

4. Document code signing process:
   ```bash
   # Generate GPG key for signing
   gpg --full-generate-key

   # Sign release
   git tag -s v0.1.0 -m "Release v0.1.0"

   # Sign release artifacts
   gpg --detach-sign --armor target/release/libturtl.rlib
   ```

5. Create release checklist template:
   - .github/RELEASE_CHECKLIST.md

Files to create:
- RELEASES.md (release process)
- CHANGELOG.md (change log)
- .github/RELEASE_CHECKLIST.md (template)

Files to modify:
- SECURITY.md (add vulnerability disclosure)

References:
- Semantic Versioning: https://semver.org/
- Keep a Changelog: https://keepachangelog.com/
- See TASK_BREAKDOWN.md Task #26

Acceptance:
- Release process fully documented
- CHANGELOG initialized
- Security disclosure process clear
- Code signing documented
- Email alias recommendations provided
- All templates ready
```

---

## Task #27: Performance Regression CI 🟢

### Worker Prompt

```
Add performance regression detection to CI (Task #27):

REQUIRES: Task #14 (baseline benchmarks)

Prevent accidental performance regressions with automated benchmark comparison.

Your task:
1. Create .github/workflows/benchmark.yml:
   ```yaml
   name: Benchmark

   on:
     pull_request:
       branches: [main]

   jobs:
     benchmark:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
           with:
             fetch-depth: 0  # Need history for comparison

         - name: Install Rust
           uses: actions-rust-lang/setup-rust-toolchain@v1

         - name: Run benchmarks on PR
           run: cargo bench -- --save-baseline pr

         - name: Checkout main
           run: git checkout main

         - name: Run benchmarks on main
           run: cargo bench -- --save-baseline main

         - name: Compare benchmarks
           run: |
             cargo install critcmp
             critcmp main pr > benchmark_diff.txt
             cat benchmark_diff.txt

         - name: Check for regressions
           run: |
             # Parse benchmark_diff.txt
             # Fail if any benchmark is >10% slower
             # (Implementation needed)

         - name: Comment on PR
           uses: actions/github-script@v6
           with:
             script: |
               const fs = require('fs');
               const diff = fs.readFileSync('benchmark_diff.txt', 'utf8');
               github.rest.issues.createComment({
                 issue_number: context.issue.number,
                 owner: context.repo.owner,
                 repo: context.repo.repo,
                 body: `## Benchmark Results\n\n\`\`\`\n${diff}\n\`\`\``,
               });
   ```

2. Configure Criterion to store history:
   - Criterion already stores results in target/criterion/
   - Use `--save-baseline` flag for named baselines

3. Create comparison script (tools/compare_benchmarks.sh):
   ```bash
   #!/bin/bash
   # Compare two benchmark runs
   # Usage: ./compare_benchmarks.sh main pr

   BASELINE1=$1
   BASELINE2=$2
   THRESHOLD=10  # 10% regression threshold

   critcmp $BASELINE1 $BASELINE2 | tee comparison.txt

   # Parse and check for regressions >10%
   # Exit 1 if regression detected
   ```

4. Add benchmark documentation to docs/PERFORMANCE.md:
   ```markdown
   ## Performance Regression Testing

   Every PR is automatically benchmarked against main branch.

   Threshold: 10% regression fails CI

   To run benchmarks locally:
   ```bash
   cargo bench
   ```

   To compare with main:
   ```bash
   git checkout main
   cargo bench -- --save-baseline main
   git checkout your-branch
   cargo bench -- --save-baseline pr
   critcmp main pr
   ```
   ```

5. Handle benchmark noise/flakiness:
   - Document that benchmarks should run on dedicated hardware
   - Allow small fluctuations (<5%)
   - Strict threshold for large regressions (>10%)

6. Track performance over time:
   - Consider using https://bencher.dev/ for visualization
   - Or store results as JSON and plot with scripts

Files to create:
- .github/workflows/benchmark.yml
- tools/compare_benchmarks.sh

Files to modify:
- docs/PERFORMANCE.md (add regression testing section)

References:
- Criterion.rs: https://bheisler.github.io/criterion.rs/book/
- critcmp: https://github.com/BurntSushi/critcmp
- See TASK_BREAKDOWN.md Task #27

Acceptance:
- Benchmark CI runs on every PR
- Comparison with main branch baseline
- PR comment shows benchmark results
- CI fails if >10% regression detected
- Documentation explains how to use
- Handles benchmark noise appropriately
```

---

## Task #28: Real-World Integration Examples 🟢

### Worker Prompt

```
Create real-world integration examples (Task #28):

REQUIRES: Task #5, #6 (basic examples)

Show developers how to use TURTL in practical scenarios.

Your task:
1. Create examples/hybrid_pqc_classic.rs:
   - Demonstrate hybrid classical+PQC key exchange
   - Use X25519 (classical ECDH) + ML-KEM (PQC)
   - Combine shared secrets: `final_secret = KDF(x25519_secret || mlkem_secret)`
   - Show why hybrid is recommended during transition period

   ```rust
   // Example structure
   use turtl::kem::*;
   use x25519_dalek::{EphemeralSecret, PublicKey};

   fn hybrid_key_exchange() -> [u8; 32] {
       // Classical: X25519
       let x25519_secret = EphemeralSecret::random();
       let x25519_public = PublicKey::from(&x25519_secret);
       // ... exchange and compute shared secret

       // PQC: ML-KEM
       let (pk, sk) = kem_keygen(KemParam::Kem768)?;
       let (ct, ss) = kem_encapsulate(&pk)?;
       // ... exchange ciphertext

       // Combine using KDF
       let combined = kdf(&[&x25519_ss, &mlkem_ss]);
       combined
   }
   ```

2. Create examples/tls_handshake.rs:
   - Simulate TLS 1.3 handshake with PQC
   - Show where ML-KEM fits in handshake
   - Show where ML-DSA fits for certificates
   - Document how to integrate with rustls (conceptually)

3. Create examples/secure_messaging.rs:
   - End-to-end encrypted messaging example
   - Use ML-KEM for key exchange
   - Use ML-DSA for message signatures
   - Show encrypt-then-sign pattern

   ```rust
   struct SecureMessage {
       ciphertext: Vec<u8>,      // Encrypted with shared secret
       signature: Signature,       // Signature over ciphertext
   }

   fn send_secure_message(recipient_pk: &KemPublicKey,
                          signer_sk: &DsaPrivateKey,
                          message: &[u8]) -> SecureMessage {
       // 1. Key exchange
       let (ct, ss) = kem_encapsulate(recipient_pk)?;

       // 2. Encrypt message with shared secret (use AES-GCM)
       let ciphertext = aes_gcm_encrypt(&ss, message);

       // 3. Sign ciphertext
       let signature = dsa_sign(signer_sk, &ciphertext, b"")?;

       SecureMessage { ciphertext, signature }
   }
   ```

4. Create examples/best_practices.rs:
   - Key management (rotation, storage)
   - Error handling patterns
   - Performance optimization tips
   - Security considerations checklist

5. Create docs/INTEGRATION_GUIDE.md:
   ```markdown
   # Integration Guide

   ## Hybrid Mode (Recommended)

   During the transition to PQC, use hybrid mode...

   ## Key Management

   - Generate fresh keys for each session (ephemeral)
   - Store long-term keys securely (OS keychain)
   - Rotate keys regularly

   ## Performance Considerations

   - ML-KEM is fast (~100μs keygen)
   - ML-DSA signing is slower (~1ms with retries)
   - Cache public keys when possible

   ## Common Pitfalls

   - Don't reuse nonces
   - Don't skip signature verification
   - Don't use deterministic signing if RNG might be weak
   ```

6. Add dependencies for examples (as dev-dependencies):
   ```toml
   [dev-dependencies]
   x25519-dalek = "2.0"
   aes-gcm = "0.10"
   sha2 = "0.10"
   ```

Files to create:
- examples/hybrid_pqc_classic.rs (~200 lines)
- examples/tls_handshake.rs (~250 lines)
- examples/secure_messaging.rs (~200 lines)
- examples/best_practices.rs (~150 lines)
- docs/INTEGRATION_GUIDE.md (~500 lines)

Files to modify:
- Cargo.toml (add dev-dependencies)
- README.md (link to integration examples)

References:
- Hybrid PQC: https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/
- TLS 1.3: https://www.rfc-editor.org/rfc/rfc8446
- See TASK_BREAKDOWN.md Task #28

Acceptance:
- All 4 examples compile and run
- Examples are well-commented
- Integration guide is comprehensive
- Shows realistic usage patterns
- Documents best practices
- README links to examples
```

---

**Total Tasks:** 28
**Last Updated:** 2026-01-25
**Status:** Ready for autonomous development including production hardening

## Usage Notes for PM Agent

When spawning workers, copy the entire "Worker Prompt" section from the relevant task above. These prompts are intentionally detailed and specific to guide workers autonomously.

**Critical Path:**
- Phase 1 (Tasks #1-4): Must complete first - Task #1 is the blocker
- Phase 2 (Tasks #5-10): Mostly parallel, some depend on #1
- Phase 3 (Tasks #11-15): Parallel after Phase 1
- Phase 4 (Tasks #16-20): Sequential optimizations
- Phase 5 (Tasks #21-28): Production hardening - mostly parallel except #21 (external)

**Production Readiness:**
- MVP: Tasks #1-10 complete
- Production Ready: Tasks #1-22 complete (including external audit)
- Gold Standard: All 28 tasks complete
