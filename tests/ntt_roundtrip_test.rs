use turtl::common::ntt::{NTTContext, NTTType};
use turtl::common::poly::Polynomial;

#[test]
fn test_mldsa_ntt_roundtrip() {
    let ntt_ctx = NTTContext::new(NTTType::MLDSA);

    // Test with small coefficients (similar to s1 in ML-DSA)
    let mut original = Polynomial::new();
    for i in 0..256 {
        original.coeffs[i] = (i % 5) as i32 - 2; // [-2, -1, 0, 1, 2, -2, -1, ...]
    }

    println!("Original (first 10): {:?}", &original.coeffs[0..10]);

    // Forward NTT
    let mut in_ntt = original.clone();
    ntt_ctx.forward(&mut in_ntt).unwrap();

    println!("After NTT (first 10): {:?}", &in_ntt.coeffs[0..10]);

    // Inverse NTT
    let mut recovered = in_ntt.clone();
    ntt_ctx.inverse(&mut recovered).unwrap();

    println!("After inverse (first 10): {:?}", &recovered.coeffs[0..10]);

    // Check if we recovered the original (comparing modular equivalents)
    let ntt_ctx = NTTContext::new(NTTType::MLDSA);
    let modulus = ntt_ctx.modulus;

    let mut matches = true;
    let mut max_error = 0;
    for i in 0..256 {
        // Normalize both to [0, q-1] for comparison
        let orig_normalized = original.coeffs[i].rem_euclid(modulus);
        let recovered_normalized = recovered.coeffs[i].rem_euclid(modulus);

        let error = (orig_normalized - recovered_normalized).abs();
        if error > max_error {
            max_error = error;
        }
        if error > 0 {
            matches = false;
            if i < 10 {
                println!(
                    "Mismatch at {}: original={} (normalized={}), recovered={}",
                    i, original.coeffs[i], orig_normalized, recovered_normalized
                );
            }
        }
    }

    println!("Round-trip successful: {}", matches);
    println!("Max error: {}", max_error);

    assert!(
        matches,
        "NTT round-trip should recover original coefficients"
    );
}

/// In Z_q[X]/(X^256+1), the NTT evaluates polynomials at roots of unity.
/// A constant polynomial f(x)=2 evaluates to 2*sum(omega^i) at each root omega,
/// which involves modular inverses and can produce large values in [0, q-1].
/// This is mathematically correct — the key property is that NTT roundtrips exactly.
#[test]
fn test_mldsa_ntt_constant_roundtrip() {
    let ntt_ctx = NTTContext::new(NTTType::MLDSA);

    let mut poly = Polynomial::new();
    for i in 0..256 {
        poly.coeffs[i] = 2;
    }

    let original = poly.clone();
    ntt_ctx.forward(&mut poly).unwrap();

    // NTT coefficients may be large (up to q-1) — this is expected
    for coeff in &poly.coeffs {
        assert!(
            *coeff >= 0 && *coeff < ntt_ctx.modulus,
            "NTT coefficient out of range: {}",
            coeff
        );
    }

    ntt_ctx.inverse(&mut poly).unwrap();

    for i in 0..256 {
        assert_eq!(
            poly.coeffs[i], original.coeffs[i],
            "Roundtrip mismatch at index {}: got {}, expected {}",
            i, poly.coeffs[i], original.coeffs[i]
        );
    }
}
