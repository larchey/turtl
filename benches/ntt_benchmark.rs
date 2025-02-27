//! Benchmarks for Number-Theoretic Transform operations.
//!
//! This module contains benchmarks for the NTT and its inverse,
//! which are critical operations in both ML-KEM and ML-DSA.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use turtl::common::ntt::NTTContext;
use turtl::common::poly::Polynomial;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub fn ntt_forward_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("NTT Forward Transform");
    let ntt_ctx = NTTContext::new();
    
    // Test with random polynomials
    let mut rng = ChaCha20Rng::seed_from_u64(0xdeadbeef);
    
    // Create test polynomials with different patterns
    let random_poly = generate_random_polynomial(&mut rng);
    let sparse_poly = generate_sparse_polynomial(&mut rng, 64); // 25% non-zero
    let dense_poly = generate_dense_polynomial(&mut rng);
    
    group.bench_function(BenchmarkId::new("Random Polynomial", "256 coeffs"), |b| {
        b.iter(|| {
            let mut poly = random_poly.clone();
            ntt_ctx.forward(black_box(&mut poly)).unwrap();
        })
    });
    
    group.bench_function(BenchmarkId::new("Sparse Polynomial", "64 non-zero coeffs"), |b| {
        b.iter(|| {
            let mut poly = sparse_poly.clone();
            ntt_ctx.forward(black_box(&mut poly)).unwrap();
        })
    });
    
    group.bench_function(BenchmarkId::new("Dense Polynomial", "256 coeffs"), |b| {
        b.iter(|| {
            let mut poly = dense_poly.clone();
            ntt_ctx.forward(black_box(&mut poly)).unwrap();
        })
    });
    
    group.finish();
}

pub fn ntt_inverse_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("NTT Inverse Transform");
    let ntt_ctx = NTTContext::new();
    
    // Test with random polynomials
    let mut rng = ChaCha20Rng::seed_from_u64(0xdeadbeef);
    
    // Create test polynomials with different patterns
    let mut random_poly = generate_random_polynomial(&mut rng);
    let mut sparse_poly = generate_sparse_polynomial(&mut rng, 64); // 25% non-zero
    let mut dense_poly = generate_dense_polynomial(&mut rng);
    
    // Forward transform first to get polynomials in NTT domain
    ntt_ctx.forward(&mut random_poly).unwrap();
    ntt_ctx.forward(&mut sparse_poly).unwrap();
    ntt_ctx.forward(&mut dense_poly).unwrap();
    
    group.bench_function(BenchmarkId::new("Random Polynomial", "256 coeffs"), |b| {
        b.iter(|| {
            let mut poly = random_poly.clone();
            ntt_ctx.inverse(black_box(&mut poly)).unwrap();
        })
    });
    
    group.bench_function(BenchmarkId::new("Sparse Polynomial", "64 non-zero coeffs"), |b| {
        b.iter(|| {
            let mut poly = sparse_poly.clone();
            ntt_ctx.inverse(black_box(&mut poly)).unwrap();
        })
    });
    
    group.bench_function(BenchmarkId::new("Dense Polynomial", "256 coeffs"), |b| {
        b.iter(|| {
            let mut poly = dense_poly.clone();
            ntt_ctx.inverse(black_box(&mut poly)).unwrap();
        })
    });
    
    group.finish();
}

pub fn ntt_multiply_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("NTT Polynomial Multiplication");
    let ntt_ctx = NTTContext::new();
    
    // Test with random polynomials
    let mut rng = ChaCha20Rng::seed_from_u64(0xdeadbeef);
    
    // Create test polynomials in NTT domain
    let mut a = generate_random_polynomial(&mut rng);
    let mut b = generate_random_polynomial(&mut rng);
    
    ntt_ctx.forward(&mut a).unwrap();
    ntt_ctx.forward(&mut b).unwrap();
    
    group.bench_function("Polynomial Multiplication in NTT Domain", |bench| {
        bench.iter(|| {
            ntt_ctx.multiply_ntt(black_box(&a), black_box(&b)).unwrap()
        })
    });
    
    group.finish();
}

pub fn ntt_roundtrip_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("NTT Complete Roundtrip");
    let ntt_ctx = NTTContext::new();
    
    // Test with random polynomials
    let mut rng = ChaCha20Rng::seed_from_u64(0xdeadbeef);
    
    // Create test polynomials with different patterns
    let random_poly = generate_random_polynomial(&mut rng);
    
    group.bench_function("Forward->Multiply->Inverse", |b| {
        b.iter(|| {
            let mut a = random_poly.clone();
            let mut b = random_poly.clone();
            
            // Forward NTT
            ntt_ctx.forward(black_box(&mut a)).unwrap();
            ntt_ctx.forward(black_box(&mut b)).unwrap();
            
            // Multiply in NTT domain
            let mut c = ntt_ctx.multiply_ntt(black_box(&a), black_box(&b)).unwrap();
            
            // Inverse NTT
            ntt_ctx.inverse(black_box(&mut c)).unwrap();
            
            c
        })
    });
    
    group.finish();
}

// Helper functions to generate test polynomials

fn generate_random_polynomial(rng: &mut ChaCha20Rng) -> Polynomial {
    let mut poly = Polynomial::new();
    let q = 8380417; // ML-KEM/ML-DSA modulus
    
    for i in 0..256 {
        poly.coeffs[i] = rng.gen_range(0..q);
    }
    
    poly
}

fn generate_sparse_polynomial(rng: &mut ChaCha20Rng, non_zero_count: usize) -> Polynomial {
    let mut poly = Polynomial::new();
    let q = 8380417; // ML-KEM/ML-DSA modulus
    
    // Choose random positions for non-zero coefficients
    let mut positions = Vec::new();
    while positions.len() < non_zero_count {
        let pos = rng.gen_range(0..256);
        if !positions.contains(&pos) {
            positions.push(pos);
        }
    }
    
    // Set chosen positions to random values
    for &pos in &positions {
        poly.coeffs[pos] = rng.gen_range(0..q);
    }
    
    poly
}

fn generate_dense_polynomial(rng: &mut ChaCha20Rng) -> Polynomial {
    let mut poly = Polynomial::new();
    
    // Use only small values (0, 1, -1)
    for i in 0..256 {
        poly.coeffs[i] = rng.gen_range(-1..=1);
    }
    
    poly
}

criterion_group!(
    ntt_benches,
    ntt_forward_benchmark,
    ntt_inverse_benchmark,
    ntt_multiply_benchmark,
    ntt_roundtrip_benchmark,
);
criterion_main!(ntt_benches);