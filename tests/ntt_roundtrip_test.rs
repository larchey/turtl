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
                println!("Mismatch at {}: original={} (normalized={}), recovered={}",
                    i, original.coeffs[i], orig_normalized, recovered_normalized);
            }
        }
    }

    println!("Round-trip successful: {}", matches);
    println!("Max error: {}", max_error);

    assert!(matches, "NTT round-trip should recover original coefficients");
}

#[test]
fn test_mldsa_ntt_preserves_small_values() {
    let ntt_ctx = NTTContext::new(NTTType::MLDSA);

    // Test that small inputs produce reasonable NTT outputs
    let mut small_poly = Polynomial::new();
    for i in 0..256 {
        small_poly.coeffs[i] = 2; // All coefficients are 2
    }

    let mut ntt_poly = small_poly.clone();
    ntt_ctx.forward(&mut ntt_poly).unwrap();

    // Find max coefficient in NTT domain
    let mut max_coeff = 0;
    for i in 0..256 {
        let abs_coeff = ntt_poly.coeffs[i].abs();
        if abs_coeff > max_coeff {
            max_coeff = abs_coeff;
        }
    }

    println!("Max NTT coefficient for constant input 2: {}", max_coeff);

    // For a constant polynomial, NTT should also be bounded
    // This is a sanity check - the exact value depends on NTT definition
    // but it shouldn't be in the millions
    assert!(max_coeff < 1_000_000,
        "NTT of small constant should not produce huge coefficients: max={}", max_coeff);
}
