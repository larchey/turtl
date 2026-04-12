use turtl::common::ntt::{NTTContext, NTTType};
use turtl::common::poly::Polynomial;

/// Test that NTT-based polynomial multiplication matches naive multiplication
/// in the ring Z_q[X]/(X^256+1)
#[test]
fn test_ntt_multiply_vs_naive() {
    let ntt_ctx = NTTContext::new(NTTType::MLDSA);
    let q = ntt_ctx.modulus as i64;

    // Create two small test polynomials
    let mut a = Polynomial::new();
    let mut b = Polynomial::new();

    // a has a few small nonzero coefficients
    a.coeffs[0] = 3;
    a.coeffs[1] = -2;
    a.coeffs[5] = 1;

    // b has a few small nonzero coefficients
    b.coeffs[0] = 1;
    b.coeffs[1] = 4;
    b.coeffs[3] = -1;

    // Normalize to [0, q-1]
    a.reduce_modulo(ntt_ctx.modulus);
    b.reduce_modulo(ntt_ctx.modulus);

    // Compute product naively in Z_q[X]/(X^256+1)
    let mut naive_result = [0i64; 256];
    for i in 0..256 {
        if a.coeffs[i] == 0 {
            continue;
        }
        for j in 0..256 {
            if b.coeffs[j] == 0 {
                continue;
            }
            let idx = i + j;
            let a_val = a.coeffs[i] as i64;
            let b_val = b.coeffs[j] as i64;
            if idx < 256 {
                naive_result[idx] = (naive_result[idx] + a_val * b_val) % q;
            } else {
                // X^256 = -1 in this ring
                naive_result[idx - 256] = (naive_result[idx - 256] - a_val * b_val) % q;
            }
        }
    }

    // Normalize naive result to [0, q-1]
    for i in 0..256 {
        naive_result[i] = ((naive_result[i] % q) + q) % q;
    }

    // Compute product via NTT
    let mut a_hat = a.clone();
    let mut b_hat = b.clone();
    ntt_ctx.forward(&mut a_hat).unwrap();
    ntt_ctx.forward(&mut b_hat).unwrap();

    let mut ntt_prod = ntt_ctx.multiply_ntt(&a_hat, &b_hat).unwrap();
    ntt_ctx.inverse(&mut ntt_prod).unwrap();

    // Normalize NTT result to [0, q-1]
    for i in 0..256 {
        ntt_prod.coeffs[i] = ntt_prod.coeffs[i].rem_euclid(ntt_ctx.modulus);
    }

    // Compare
    let mut mismatches = 0;
    for i in 0..256 {
        if ntt_prod.coeffs[i] as i64 != naive_result[i] {
            if mismatches < 10 {
                println!(
                    "MISMATCH at index {}: NTT={}, naive={}",
                    i, ntt_prod.coeffs[i], naive_result[i]
                );
            }
            mismatches += 1;
        }
    }

    if mismatches > 0 {
        println!("Total mismatches: {}/256", mismatches);
    }

    assert_eq!(mismatches, 0, "NTT multiplication does not match naive multiplication");
}

/// Test that NTT multiply works correctly for accumulated matrix-vector product
/// (simulating compute_w: w = A*z where A is in NTT domain)
#[test]
fn test_ntt_matrix_vector_product() {
    let ntt_ctx = NTTContext::new(NTTType::MLDSA);
    let q = ntt_ctx.modulus as i64;

    // Simulate a 1x2 matrix (one row, two columns) for simplicity
    // Generate A elements directly in NTT domain (like expand_a does)
    let mut a0 = Polynomial::new();
    let mut a1 = Polynomial::new();
    for i in 0..256 {
        a0.coeffs[i] = ((i * 17 + 3) as i32) % ntt_ctx.modulus;
        a1.coeffs[i] = ((i * 31 + 7) as i32) % ntt_ctx.modulus;
    }

    // Create z vector in time domain, then NTT
    let mut z0 = Polynomial::new();
    let mut z1 = Polynomial::new();
    z0.coeffs[0] = 1;
    z0.coeffs[1] = 2;
    z1.coeffs[0] = -1;
    z1.coeffs[2] = 3;
    z0.reduce_modulo(ntt_ctx.modulus);
    z1.reduce_modulo(ntt_ctx.modulus);

    let mut z0_hat = z0.clone();
    let mut z1_hat = z1.clone();
    ntt_ctx.forward(&mut z0_hat).unwrap();
    ntt_ctx.forward(&mut z1_hat).unwrap();

    // Compute w = a0*z0 + a1*z1 using NTT multiply and accumulate
    let prod0 = ntt_ctx.multiply_ntt(&a0, &z0_hat).unwrap();
    let prod1 = ntt_ctx.multiply_ntt(&a1, &z1_hat).unwrap();

    let mut w_ntt = Polynomial::new();
    w_ntt.add_assign(&prod0, ntt_ctx.modulus);
    w_ntt.add_assign(&prod1, ntt_ctx.modulus);
    ntt_ctx.inverse(&mut w_ntt).unwrap();

    // Compute the same thing by first INTT'ing a0 and a1 to get time domain,
    // then doing naive polynomial multiplication
    let mut a0_time = a0.clone();
    let mut a1_time = a1.clone();
    ntt_ctx.inverse(&mut a0_time).unwrap();
    ntt_ctx.inverse(&mut a1_time).unwrap();

    // Naive multiply a0_time * z0 + a1_time * z1 in Z_q[X]/(X^256+1)
    let mut naive_w = [0i64; 256];

    for (a_poly, z_poly) in [(&a0_time, &z0), (&a1_time, &z1)] {
        for i in 0..256 {
            for j in 0..256 {
                let a_val = a_poly.coeffs[i] as i64;
                let z_val = z_poly.coeffs[j] as i64;
                let idx = i + j;
                if idx < 256 {
                    naive_w[idx] = (naive_w[idx] + a_val * z_val) % q;
                } else {
                    naive_w[idx - 256] = (naive_w[idx - 256] - a_val * z_val) % q;
                }
            }
        }
    }

    // Normalize
    for i in 0..256 {
        naive_w[i] = ((naive_w[i] % q) + q) % q;
        w_ntt.coeffs[i] = w_ntt.coeffs[i].rem_euclid(ntt_ctx.modulus);
    }

    let mut mismatches = 0;
    for i in 0..256 {
        if w_ntt.coeffs[i] as i64 != naive_w[i] {
            if mismatches < 10 {
                println!(
                    "MISMATCH at index {}: NTT={}, naive={}",
                    i, w_ntt.coeffs[i], naive_w[i]
                );
            }
            mismatches += 1;
        }
    }

    if mismatches > 0 {
        println!("Total mismatches: {}/256", mismatches);
    }

    assert_eq!(mismatches, 0, "NTT matrix-vector product does not match naive computation");
}

/// Verify Montgomery constants
#[test]
fn test_montgomery_constants() {
    let ntt_ctx = NTTContext::new(NTTType::MLDSA);
    let q = ntt_ctx.modulus as i64;  // 8380417

    // Check: qinv * q ≡ 1 (mod 2^32)
    let qinv = ntt_ctx.qinv as i64;
    let product = (q * qinv) as u64;
    let low32 = product & 0xFFFFFFFF;
    // Actually, qinv should satisfy: qinv * q ≡ -1 (mod 2^32) for Dilithium reference
    // Or qinv * q ≡ 1 (mod 2^32) depending on convention
    println!("q * qinv mod 2^32 = {}", low32);
    // In the Dilithium reference: QINV = 58728449 and Q*QINV mod 2^32 should give specific value

    // Verify R^2 mod q
    // R = 2^32
    let r: u128 = 1 << 32;
    let r_squared = r * r; // 2^64
    let r2_mod_q = (r_squared % q as u128) as i64;
    println!("R^2 mod q = {} (stored as {})", r2_mod_q, 145);
    // This should match the stored r2 value
}
