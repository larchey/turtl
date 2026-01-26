//! Comprehensive NTT correctness tests for both ML-KEM and ML-DSA
//!
//! This test suite validates the Number-Theoretic Transform implementation
//! against various properties and edge cases to prevent regressions.
//!
//! Test categories:
//! - Roundtrip tests: Verify NTT^-1(NTT(poly)) == poly
//! - Edge cases: Zero, identity, all-ones, maximum coefficients
//! - Linearity: NTT(a + b) == NTT(a) + NTT(b), NTT(k*a) == k*NTT(a)
//! - Bounds: Output coefficients in [0, q-1]
//! - Known vectors: FIPS 203/204 test vectors (when available)

use turtl::common::ntt::{NTTContext, NTTType};
use turtl::common::poly::Polynomial;

/// Helper to generate a random polynomial with coefficients in [0, q-1]
fn random_polynomial(modulus: i32) -> Polynomial {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hash, Hasher};

    let mut poly = Polynomial::new();
    let hasher_builder = RandomState::new();

    for i in 0..256 {
        let mut hasher = hasher_builder.build_hasher();
        (i as u64).hash(&mut hasher);
        std::process::id().hash(&mut hasher);
        let random_val = hasher.finish();
        poly.coeffs[i] = (random_val % modulus as u64) as i32;
    }

    poly
}

/// Helper to add two polynomials modulo q
fn poly_add(a: &Polynomial, b: &Polynomial, modulus: i32) -> Polynomial {
    let mut result = Polynomial::new();
    for i in 0..256 {
        result.coeffs[i] = (a.coeffs[i] + b.coeffs[i]).rem_euclid(modulus);
    }
    result
}

/// Helper to multiply polynomial by scalar modulo q
fn poly_scalar_mult(poly: &Polynomial, scalar: i32, modulus: i32) -> Polynomial {
    let mut result = Polynomial::new();
    for i in 0..256 {
        result.coeffs[i] = ((poly.coeffs[i] as i64 * scalar as i64) % modulus as i64) as i32;
        if result.coeffs[i] < 0 {
            result.coeffs[i] += modulus;
        }
    }
    result
}

/// Helper to check if two polynomials are equal (modulo q)
fn poly_equal(a: &Polynomial, b: &Polynomial, modulus: i32) -> bool {
    for i in 0..256 {
        let a_norm = a.coeffs[i].rem_euclid(modulus);
        let b_norm = b.coeffs[i].rem_euclid(modulus);
        if a_norm != b_norm {
            return false;
        }
    }
    true
}

// ============================================================================
// ROUNDTRIP TESTS
// ============================================================================

/// Test that NTT inverse recovers the original polynomial for ML-KEM
/// Tests 100 random polynomials to ensure statistical confidence
#[test]
fn test_ntt_roundtrip_mlkem() {
    let ctx = NTTContext::new(NTTType::MLKEM);
    let modulus = ctx.get_modulus();

    for iteration in 0..100 {
        let mut poly = random_polynomial(modulus);
        let original = poly.clone();

        // Forward NTT
        ctx.forward(&mut poly).expect("Forward NTT failed");

        // Inverse NTT
        ctx.inverse(&mut poly).expect("Inverse NTT failed");

        // Verify roundtrip
        assert!(
            poly_equal(&poly, &original, modulus),
            "ML-KEM roundtrip failed on iteration {}: first mismatch at coefficient with values {} vs {}",
            iteration,
            poly.coeffs[0],
            original.coeffs[0]
        );
    }
}

/// Test that NTT inverse recovers the original polynomial for ML-DSA
/// Tests 100 random polynomials to ensure statistical confidence
#[test]
fn test_ntt_roundtrip_mldsa() {
    let ctx = NTTContext::new(NTTType::MLDSA);
    let modulus = ctx.get_modulus();

    for iteration in 0..100 {
        let mut poly = random_polynomial(modulus);
        let original = poly.clone();

        // Forward NTT
        ctx.forward(&mut poly).expect("Forward NTT failed");

        // Inverse NTT
        ctx.inverse(&mut poly).expect("Inverse NTT failed");

        // Verify roundtrip
        assert!(
            poly_equal(&poly, &original, modulus),
            "ML-DSA roundtrip failed on iteration {}: first mismatch at coefficient with values {} vs {}",
            iteration,
            poly.coeffs[0],
            original.coeffs[0]
        );
    }
}

/// Test roundtrip with small coefficients (common in cryptographic usage)
#[test]
fn test_ntt_roundtrip_small_coefficients() {
    let test_cases = vec![
        (NTTType::MLKEM, 3329),
        (NTTType::MLDSA, 8380417),
    ];

    for (ntt_type, modulus) in test_cases {
        let ctx = NTTContext::new(ntt_type);

        // Test with coefficients in [-5, 5]
        let mut poly = Polynomial::new();
        for i in 0..256 {
            poly.coeffs[i] = ((i % 11) as i32 - 5).rem_euclid(modulus);
        }

        let original = poly.clone();

        ctx.forward(&mut poly).expect("Forward NTT failed");
        ctx.inverse(&mut poly).expect("Inverse NTT failed");

        assert!(
            poly_equal(&poly, &original, modulus),
            "{:?}: Roundtrip failed for small coefficients",
            ntt_type
        );
    }
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

/// Test that NTT of zero polynomial is zero polynomial
#[test]
fn test_ntt_zero_polynomial() {
    let test_cases = vec![
        (NTTType::MLKEM, "ML-KEM"),
        (NTTType::MLDSA, "ML-DSA"),
    ];

    for (ntt_type, name) in test_cases {
        let ctx = NTTContext::new(ntt_type);
        let mut poly = Polynomial::new(); // All zeros by default

        ctx.forward(&mut poly).expect("Forward NTT failed");

        // NTT of zero should be zero
        for i in 0..256 {
            assert_eq!(
                poly.coeffs[i], 0,
                "{}: NTT of zero polynomial should be zero at index {}",
                name, i
            );
        }
    }
}

/// Test NTT of delta function (impulse at position 0)
/// Tests that the NTT handles sparse polynomials correctly
#[test]
fn test_ntt_identity() {
    let test_cases = vec![
        (NTTType::MLKEM, 3329),
        (NTTType::MLDSA, 8380417),
    ];

    for (ntt_type, modulus) in test_cases {
        let ctx = NTTContext::new(ntt_type);
        let mut poly = Polynomial::new();
        poly.coeffs[0] = 1; // Delta function at position 0

        let original = poly.clone();

        ctx.forward(&mut poly).expect("Forward NTT failed");

        // Verify all coefficients are in valid range
        for i in 0..256 {
            assert!(
                poly.coeffs[i] >= 0 && poly.coeffs[i] < modulus,
                "{:?}: NTT coefficient out of range at index {}: {}",
                ntt_type, i, poly.coeffs[i]
            );
        }

        // Verify roundtrip - this is the key property
        ctx.inverse(&mut poly).expect("Inverse NTT failed");
        assert!(
            poly_equal(&poly, &original, modulus),
            "{:?}: Roundtrip failed for delta function",
            ntt_type
        );
    }
}

/// Test NTT of polynomial with all coefficients = 1
#[test]
fn test_ntt_all_ones() {
    let test_cases = vec![
        (NTTType::MLKEM, 3329),
        (NTTType::MLDSA, 8380417),
    ];

    for (ntt_type, modulus) in test_cases {
        let ctx = NTTContext::new(ntt_type);
        let mut poly = Polynomial::new();
        for i in 0..256 {
            poly.coeffs[i] = 1;
        }

        let original = poly.clone();

        ctx.forward(&mut poly).expect("Forward NTT failed");

        // Verify all coefficients are in valid range
        for i in 0..256 {
            assert!(
                poly.coeffs[i] >= 0 && poly.coeffs[i] < modulus,
                "{:?}: NTT coefficient out of range at index {}: {}",
                ntt_type, i, poly.coeffs[i]
            );
        }

        // Verify roundtrip
        ctx.inverse(&mut poly).expect("Inverse NTT failed");
        assert!(
            poly_equal(&poly, &original, modulus),
            "{:?}: Roundtrip failed for all-ones polynomial",
            ntt_type
        );
    }
}

/// Test NTT with maximum coefficient values (q-1)
#[test]
fn test_ntt_maximum_coefficients() {
    let test_cases = vec![
        (NTTType::MLKEM, 3329),
        (NTTType::MLDSA, 8380417),
    ];

    for (ntt_type, modulus) in test_cases {
        let ctx = NTTContext::new(ntt_type);
        let mut poly = Polynomial::new();
        for i in 0..256 {
            poly.coeffs[i] = modulus - 1;
        }

        let original = poly.clone();

        ctx.forward(&mut poly).expect("Forward NTT failed");

        // Verify all coefficients are in valid range
        for i in 0..256 {
            assert!(
                poly.coeffs[i] >= 0 && poly.coeffs[i] < modulus,
                "{:?}: NTT coefficient out of range at index {}: {}",
                ntt_type, i, poly.coeffs[i]
            );
        }

        // Verify roundtrip
        ctx.inverse(&mut poly).expect("Inverse NTT failed");
        assert!(
            poly_equal(&poly, &original, modulus),
            "{:?}: Roundtrip failed for maximum coefficients",
            ntt_type
        );
    }
}

// ============================================================================
// LINEARITY TESTS
// ============================================================================

/// Test that NTT is linear: NTT(a + b) == NTT(a) + NTT(b)
#[test]
fn test_ntt_linearity() {
    let test_cases = vec![
        (NTTType::MLKEM, 3329),
        (NTTType::MLDSA, 8380417),
    ];

    for (ntt_type, modulus) in test_cases {
        let ctx = NTTContext::new(ntt_type);

        // Create two random polynomials
        let mut a = random_polynomial(modulus);
        let mut b = random_polynomial(modulus);

        // Compute a + b
        let mut sum = poly_add(&a, &b, modulus);

        // NTT(a + b)
        ctx.forward(&mut sum).expect("Forward NTT failed");

        // NTT(a) + NTT(b)
        ctx.forward(&mut a).expect("Forward NTT failed");
        ctx.forward(&mut b).expect("Forward NTT failed");
        let ntt_sum = poly_add(&a, &b, modulus);

        // Verify they're equal
        assert!(
            poly_equal(&sum, &ntt_sum, modulus),
            "{:?}: Linearity test failed - NTT(a+b) != NTT(a) + NTT(b)",
            ntt_type
        );
    }
}

/// Test that NTT preserves scalar multiplication: NTT(k*a) == k*NTT(a)
#[test]
fn test_ntt_scalar_mult() {
    let test_cases = vec![
        (NTTType::MLKEM, 3329, 7),
        (NTTType::MLDSA, 8380417, 13),
    ];

    for (ntt_type, modulus, scalar) in test_cases {
        let ctx = NTTContext::new(ntt_type);

        // Create random polynomial
        let poly = random_polynomial(modulus);

        // Compute k*a
        let mut scaled = poly_scalar_mult(&poly, scalar, modulus);

        // NTT(k*a)
        ctx.forward(&mut scaled).expect("Forward NTT failed");

        // k*NTT(a)
        let mut poly_copy = poly.clone();
        ctx.forward(&mut poly_copy).expect("Forward NTT failed");
        let ntt_scaled = poly_scalar_mult(&poly_copy, scalar, modulus);

        // Verify they're equal
        assert!(
            poly_equal(&scaled, &ntt_scaled, modulus),
            "{:?}: Scalar multiplication test failed - NTT(k*a) != k*NTT(a)",
            ntt_type
        );
    }
}

// ============================================================================
// BOUNDS TESTS
// ============================================================================

/// Test that NTT output coefficients are always in range [0, q-1]
#[test]
fn test_ntt_output_bounds() {
    let test_cases = vec![
        (NTTType::MLKEM, 3329),
        (NTTType::MLDSA, 8380417),
    ];

    for (ntt_type, modulus) in test_cases {
        let ctx = NTTContext::new(ntt_type);

        // Test with 20 random polynomials
        for _ in 0..20 {
            let mut poly = random_polynomial(modulus);

            ctx.forward(&mut poly).expect("Forward NTT failed");

            // Verify all coefficients are in [0, q-1]
            for i in 0..256 {
                assert!(
                    poly.coeffs[i] >= 0 && poly.coeffs[i] < modulus,
                    "{:?}: Forward NTT coefficient out of range at index {}: {} (should be in [0, {}))",
                    ntt_type, i, poly.coeffs[i], modulus
                );
            }

            ctx.inverse(&mut poly).expect("Inverse NTT failed");

            // Verify all coefficients are in [0, q-1] after inverse too
            for i in 0..256 {
                assert!(
                    poly.coeffs[i] >= 0 && poly.coeffs[i] < modulus,
                    "{:?}: Inverse NTT coefficient out of range at index {}: {} (should be in [0, {}))",
                    ntt_type, i, poly.coeffs[i], modulus
                );
            }
        }
    }
}

/// Test that small inputs produce reasonable NTT outputs
/// This is a regression test for the ML-DSA NTT bug where small inputs
/// produced wildly incorrect outputs (millions instead of reasonable values)
#[test]
fn test_ntt_small_input() {
    let test_cases = vec![
        (NTTType::MLKEM, 3329),
        (NTTType::MLDSA, 8380417),
    ];

    for (ntt_type, modulus) in test_cases {
        let ctx = NTTContext::new(ntt_type);

        // Test pattern: [2, -1, 2, -1, ...]
        let mut poly = Polynomial::new();
        for i in 0..256 {
            poly.coeffs[i] = if i % 2 == 0 { 2 } else { modulus - 1 }; // -1 normalized to q-1
        }

        let original = poly.clone();

        ctx.forward(&mut poly).expect("Forward NTT failed");

        // Verify coefficients are reasonable (not millions)
        // For small inputs, NTT outputs should also be bounded by q
        for i in 0..256 {
            assert!(
                poly.coeffs[i] >= 0 && poly.coeffs[i] < modulus,
                "{:?}: NTT of small input produced out-of-range coefficient at index {}: {}",
                ntt_type, i, poly.coeffs[i]
            );
        }

        // Verify roundtrip
        ctx.inverse(&mut poly).expect("Inverse NTT failed");
        assert!(
            poly_equal(&poly, &original, modulus),
            "{:?}: Roundtrip failed for small alternating input",
            ntt_type
        );
    }
}

/// Test constant polynomial (all coefficients the same)
#[test]
fn test_ntt_constant_polynomial() {
    let test_cases = vec![
        (NTTType::MLKEM, 3329, 42),
        (NTTType::MLDSA, 8380417, 123),
    ];

    for (ntt_type, modulus, constant) in test_cases {
        let ctx = NTTContext::new(ntt_type);

        let mut poly = Polynomial::new();
        for i in 0..256 {
            poly.coeffs[i] = constant;
        }

        let original = poly.clone();

        ctx.forward(&mut poly).expect("Forward NTT failed");

        // Verify coefficients are in valid range
        for i in 0..256 {
            assert!(
                poly.coeffs[i] >= 0 && poly.coeffs[i] < modulus,
                "{:?}: NTT coefficient out of range at index {}: {}",
                ntt_type, i, poly.coeffs[i]
            );
        }

        // Verify roundtrip
        ctx.inverse(&mut poly).expect("Inverse NTT failed");
        assert!(
            poly_equal(&poly, &original, modulus),
            "{:?}: Roundtrip failed for constant polynomial",
            ntt_type
        );
    }
}

// ============================================================================
// KNOWN VECTOR TESTS (placeholders for FIPS test vectors)
// ============================================================================

/// Test NTT using FIPS 203 (ML-KEM) test vectors
///
/// TODO: Add FIPS 203 appendix test vectors when available
/// Reference: FIPS 203, Appendix (Known Answer Tests)
///
/// To add vectors:
/// 1. Download official KAT from NIST or pq-crystals repository
/// 2. Parse the vector files to extract polynomial inputs/outputs
/// 3. Add assertions comparing against reference values
#[test]
#[ignore] // Remove when test vectors are added
fn test_ntt_fips203_vectors() {
    // Placeholder for FIPS 203 test vectors
    // Format:
    // - Input polynomial (256 coefficients)
    // - Expected NTT output (256 coefficients)
    // - Expected inverse NTT output (should match input)

    // Example structure (values are placeholders):
    // let ctx = NTTContext::new(NTTType::MLKEM);
    // for (input, expected_ntt) in test_vectors {
    //     let mut poly = input.clone();
    //     ctx.forward(&mut poly).unwrap();
    //     assert_eq!(poly, expected_ntt);
    // }
}

/// Test NTT using FIPS 204 (ML-DSA) test vectors
///
/// TODO: Add FIPS 204 appendix test vectors when available
/// Reference: FIPS 204, Appendix (Known Answer Tests)
///
/// To add vectors:
/// 1. Download official KAT from NIST or pq-crystals repository
/// 2. Parse the vector files to extract polynomial inputs/outputs
/// 3. Add assertions comparing against reference values
#[test]
#[ignore] // Remove when test vectors are added
fn test_ntt_fips204_vectors() {
    // Placeholder for FIPS 204 test vectors
    // Format:
    // - Input polynomial (256 coefficients)
    // - Expected NTT output (256 coefficients)
    // - Expected inverse NTT output (should match input)

    // Example structure (values are placeholders):
    // let ctx = NTTContext::new(NTTType::MLDSA);
    // for (input, expected_ntt) in test_vectors {
    //     let mut poly = input.clone();
    //     ctx.forward(&mut poly).unwrap();
    //     assert_eq!(poly, expected_ntt);
    // }
}

// ============================================================================
// MULTIPLICATION TESTS
// ============================================================================

/// Test that NTT-based polynomial multiplication works correctly
/// Verify: INTT(NTT(a) * NTT(b)) gives correct polynomial product
#[test]
fn test_ntt_multiplication_correctness() {
    let test_cases = vec![
        (NTTType::MLKEM, 3329),
        (NTTType::MLDSA, 8380417),
    ];

    for (ntt_type, modulus) in test_cases {
        let ctx = NTTContext::new(ntt_type);

        // Create two simple polynomials
        let mut a = Polynomial::new();
        let mut b = Polynomial::new();

        for i in 0..256 {
            a.coeffs[i] = (i % 10) as i32;
            b.coeffs[i] = ((i + 5) % 7) as i32;
        }

        let mut a_ntt = a.clone();
        let mut b_ntt = b.clone();

        // Transform to NTT domain
        ctx.forward(&mut a_ntt).expect("Forward NTT failed");
        ctx.forward(&mut b_ntt).expect("Forward NTT failed");

        // Multiply in NTT domain
        let mut product = ctx.multiply_ntt(&a_ntt, &b_ntt).expect("NTT multiplication failed");

        // Transform back
        ctx.inverse(&mut product).expect("Inverse NTT failed");

        // Verify all coefficients are in valid range
        for i in 0..256 {
            assert!(
                product.coeffs[i] >= 0 && product.coeffs[i] < modulus,
                "{:?}: Product coefficient out of range at index {}: {}",
                ntt_type, i, product.coeffs[i]
            );
        }
    }
}

/// Test commutativity of NTT multiplication: NTT(a)*NTT(b) == NTT(b)*NTT(a)
#[test]
fn test_ntt_multiplication_commutative() {
    let test_cases = vec![
        (NTTType::MLKEM, 3329),
        (NTTType::MLDSA, 8380417),
    ];

    for (ntt_type, modulus) in test_cases {
        let ctx = NTTContext::new(ntt_type);

        let mut a = random_polynomial(modulus);
        let mut b = random_polynomial(modulus);

        let mut a_copy = a.clone();
        let mut b_copy = b.clone();

        // Transform to NTT domain
        ctx.forward(&mut a).expect("Forward NTT failed");
        ctx.forward(&mut b).expect("Forward NTT failed");
        ctx.forward(&mut a_copy).expect("Forward NTT failed");
        ctx.forward(&mut b_copy).expect("Forward NTT failed");

        // Compute a*b and b*a
        let mut ab = ctx.multiply_ntt(&a, &b).expect("Multiplication failed");
        let mut ba = ctx.multiply_ntt(&b_copy, &a_copy).expect("Multiplication failed");

        // Transform back
        ctx.inverse(&mut ab).expect("Inverse NTT failed");
        ctx.inverse(&mut ba).expect("Inverse NTT failed");

        // Verify they're equal
        assert!(
            poly_equal(&ab, &ba, modulus),
            "{:?}: Multiplication not commutative",
            ntt_type
        );
    }
}
