//! Benchmarks for ML-KEM operations.
//!
//! This module contains benchmarks for key generation, encapsulation, and
//! decapsulation operations for each ML-KEM parameter set.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use turtl::kem::{self, ParameterSet, KeyPair, PublicKey, PrivateKey, Ciphertext, SharedSecret};
use turtl::error::Result;

pub fn ml_kem_keygen_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM Key Generation");
    
    // Benchmark for each parameter set
    for param_set in &[
        ParameterSet::ML_KEM_512,
        ParameterSet::ML_KEM_768,
        ParameterSet::ML_KEM_1024,
    ] {
        let param_name = match param_set {
            ParameterSet::ML_KEM_512 => "ML-KEM-512",
            ParameterSet::ML_KEM_768 => "ML-KEM-768",
            ParameterSet::ML_KEM_1024 => "ML-KEM-1024",
        };
        
        group.bench_function(BenchmarkId::new("KeyGen", param_name), |b| {
            b.iter(|| {
                KeyPair::generate(black_box(*param_set)).unwrap()
            })
        });
    }
    
    group.finish();
}

pub fn ml_kem_encaps_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM Encapsulation");
    
    // Generate key pairs for each parameter set
    let keypair_512 = KeyPair::generate(ParameterSet::ML_KEM_512).unwrap();
    let keypair_768 = KeyPair::generate(ParameterSet::ML_KEM_768).unwrap();
    let keypair_1024 = KeyPair::generate(ParameterSet::ML_KEM_1024).unwrap();
    
    // Benchmark encapsulation for each parameter set
    group.bench_function(BenchmarkId::new("Encaps", "ML-KEM-512"), |b| {
        b.iter(|| {
            kem::encapsulate(black_box(&keypair_512.public_key())).unwrap()
        })
    });
    
    group.bench_function(BenchmarkId::new("Encaps", "ML-KEM-768"), |b| {
        b.iter(|| {
            kem::encapsulate(black_box(&keypair_768.public_key())).unwrap()
        })
    });
    
    group.bench_function(BenchmarkId::new("Encaps", "ML-KEM-1024"), |b| {
        b.iter(|| {
            kem::encapsulate(black_box(&keypair_1024.public_key())).unwrap()
        })
    });
    
    group.finish();
}

pub fn ml_kem_decaps_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM Decapsulation");
    
    // Generate key pairs for each parameter set
    let keypair_512 = KeyPair::generate(ParameterSet::ML_KEM_512).unwrap();
    let keypair_768 = KeyPair::generate(ParameterSet::ML_KEM_768).unwrap();
    let keypair_1024 = KeyPair::generate(ParameterSet::ML_KEM_1024).unwrap();
    
    // Generate ciphertexts for each parameter set
    let (ciphertext_512, _) = kem::encapsulate(&keypair_512.public_key()).unwrap();
    let (ciphertext_768, _) = kem::encapsulate(&keypair_768.public_key()).unwrap();
    let (ciphertext_1024, _) = kem::encapsulate(&keypair_1024.public_key()).unwrap();
    
    // Benchmark decapsulation for each parameter set
    group.bench_function(BenchmarkId::new("Decaps", "ML-KEM-512"), |b| {
        b.iter(|| {
            kem::decapsulate(
                black_box(&keypair_512.private_key()),
                black_box(&ciphertext_512)
            ).unwrap()
        })
    });
    
    group.bench_function(BenchmarkId::new("Decaps", "ML-KEM-768"), |b| {
        b.iter(|| {
            kem::decapsulate(
                black_box(&keypair_768.private_key()),
                black_box(&ciphertext_768)
            ).unwrap()
        })
    });
    
    group.bench_function(BenchmarkId::new("Decaps", "ML-KEM-1024"), |b| {
        b.iter(|| {
            kem::decapsulate(
                black_box(&keypair_1024.private_key()),
                black_box(&ciphertext_1024)
            ).unwrap()
        })
    });
    
    group.finish();
}

pub fn ml_kem_full_exchange_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM Full Exchange");
    
    for param_set in &[
        ParameterSet::ML_KEM_512,
        ParameterSet::ML_KEM_768,
        ParameterSet::ML_KEM_1024,
    ] {
        let param_name = match param_set {
            ParameterSet::ML_KEM_512 => "ML-KEM-512",
            ParameterSet::ML_KEM_768 => "ML-KEM-768",
            ParameterSet::ML_KEM_1024 => "ML-KEM-1024",
        };
        
        group.bench_function(BenchmarkId::new("Full Exchange", param_name), |b| {
            b.iter(|| {
                // Generate key pair
                let keypair = KeyPair::generate(black_box(*param_set)).unwrap();
                
                // Encapsulate
                let (ciphertext, shared_secret1) = kem::encapsulate(&keypair.public_key()).unwrap();
                
                // Decapsulate
                let shared_secret2 = kem::decapsulate(&keypair.private_key(), &ciphertext).unwrap();
                
                // Verify shared secrets match
                assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
                
                (ciphertext, shared_secret1)
            })
        });
    }
    
    group.finish();
}

pub fn ml_kem_shell_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM Shell Key Derivation");
    
    // Generate a shared secret
    let keypair = KeyPair::generate(ParameterSet::ML_KEM_512).unwrap();
    let (_, shared_secret) = kem::encapsulate(&keypair.public_key()).unwrap();
    
    // Create a shell
    let shell = kem::shell::Shell::new(shared_secret);
    
    // Benchmark key derivation operations
    group.bench_function("Derive Encryption Key", |b| {
        b.iter(|| {
            black_box(shell.derive_encryption_key())
        })
    });
    
    group.bench_function("Derive Authentication Key", |b| {
        b.iter(|| {
            black_box(shell.derive_authentication_key())
        })
    });
    
    group.bench_function("Derive Key Pair", |b| {
        b.iter(|| {
            black_box(shell.derive_key_pair())
        })
    });
    
    // Benchmark with different context lengths
    for &context_len in &[4, 16, 64] {
        let context = vec![0u8; context_len];
        
        group.bench_function(BenchmarkId::new("Derive Contextual Key", format!("{}B", context_len)), |b| {
            b.iter(|| {
                black_box(shell.derive_key_for_context(&context)).unwrap()
            })
        });
    }
    
    group.finish();
}

criterion_group!(
    kem_benches,
    ml_kem_keygen_benchmark,
    ml_kem_encaps_benchmark,
    ml_kem_decaps_benchmark,
    ml_kem_full_exchange_benchmark,
    ml_kem_shell_benchmark,
);
criterion_main!(kem_benches);