use turtl::common::ntt::{NTTContext, NTTType};
use turtl::common::poly::Polynomial;

#[test]
fn test_cs1_magnitude() {
    let ntt_ctx = NTTContext::new(NTTType::MLDSA);

    // Create a polynomial with all coefficients = 2 (like s1 in the debug output)
    let mut s1 = Polynomial::new();
    for i in 0..256 {
        s1.coeffs[i] = 2;
    }

    // Create a sparse polynomial like c (39 coefficients set to 1)
    let mut c = Polynomial::new();
    for i in 0..39 {
        c.coeffs[i * 6] = 1; // Spread them out
    }

    println!("s1 (first 10): {:?}", &s1.coeffs[0..10]);
    println!("c (first 40): {:?}", &c.coeffs[0..40]);

    // Transform to NTT domain
    let mut s1_hat = s1.clone();
    let mut c_hat = c.clone();
    ntt_ctx.forward(&mut s1_hat).unwrap();
    ntt_ctx.forward(&mut c_hat).unwrap();

    println!("s1_hat (first 10): {:?}", &s1_hat.coeffs[0..10]);
    println!("c_hat (first 10): {:?}", &c_hat.coeffs[0..10]);

    // Multiply in NTT domain
    let mut cs1 = ntt_ctx.multiply_ntt(&c_hat, &s1_hat).unwrap();

    // Inverse NTT
    ntt_ctx.inverse(&mut cs1).unwrap();

    println!("cs1 after inverse (first 10): {:?}", &cs1.coeffs[0..10]);

    // Convert to centered representation to check magnitude
    let modulus = ntt_ctx.modulus;
    let half_q = modulus / 2;
    let mut max_centered = 0;
    for &coeff in &cs1.coeffs {
        let centered = if coeff > half_q {
            coeff - modulus
        } else {
            coeff
        };
        let abs_val = centered.abs();
        if abs_val > max_centered {
            max_centered = abs_val;
        }
    }

    println!("Max cs1 coefficient (centered): {}", max_centered);

    // Should be around tau * max(s1) = 39 * 2 = 78
    // Allow some leeway due to circular convolution, but should be < 200
    assert!(max_centered < 200,
           "cs1 coefficients too large: max={}, expected ~78", max_centered);
}
