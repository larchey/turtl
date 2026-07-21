//! Checks whether turtl's ML-KEM NTT multiply matches schoolbook negacyclic
//! polynomial multiplication mod (x^256 + 1, q=3329). This is the definitive
//! correctness test for the NTT convolution.

use turtl::common::ntt::{NTTContext, NTTType};
use turtl::common::poly::Polynomial;

const Q: i64 = 3329;

fn schoolbook(a: &Polynomial, b: &Polynomial) -> Polynomial {
    // Negacyclic convolution: c[k] = sum_{i+j=k} a[i]b[j] - sum_{i+j=k+256} a[i]b[j], mod q
    let mut c = Polynomial::new();
    let mut acc = [0i64; 512];
    for i in 0..256 {
        for j in 0..256 {
            acc[i + j] += a.coeffs[i] as i64 * b.coeffs[j] as i64;
        }
    }
    for k in 0..256 {
        let v = (acc[k] - acc[k + 256]).rem_euclid(Q);
        c.coeffs[k] = v as i32;
    }
    c
}

fn main() {
    let ctx = NTTContext::new(NTTType::MLKEM);

    // Two small deterministic polynomials
    let mut a = Polynomial::new();
    let mut b = Polynomial::new();
    for i in 0..256 {
        a.coeffs[i] = ((i * 3 + 1) % 7) as i32;
        b.coeffs[i] = ((i * 5 + 2) % 11) as i32;
    }

    let expected = schoolbook(&a, &b);

    let mut ah = a.clone();
    let mut bh = b.clone();
    ctx.forward(&mut ah).unwrap();
    ctx.forward(&mut bh).unwrap();
    let mut prod = ctx.multiply_ntt(&ah, &bh).unwrap();
    ctx.inverse(&mut prod).unwrap();

    let mut mismatches = 0;
    for i in 0..256 {
        if prod.coeffs[i] != expected.coeffs[i] {
            mismatches += 1;
            if mismatches <= 5 {
                println!("  coeff[{i}]: ntt={} schoolbook={}", prod.coeffs[i], expected.coeffs[i]);
            }
        }
    }
    println!("ML-KEM NTT multiply vs schoolbook: {} / 256 mismatches", mismatches);
    println!("RESULT: {}", if mismatches == 0 { "CORRECT" } else { "WRONG — multiply_ntt is not negacyclic convolution" });
}
