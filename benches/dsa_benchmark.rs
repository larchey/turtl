//! Benchmarks for ML-DSA operations.
//!
//! This module contains benchmarks for key generation, signing, and
//! verification operations for each ML-DSA parameter set.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use turtl::dsa::{self, ParameterSet, KeyPair, SigningMode};
pub fn ml_dsa_keygen_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA Key Generation");
    
    // Benchmark for each parameter set
    for param_set in &[
        ParameterSet::MlDsa44,
        ParameterSet::MlDsa65,
        ParameterSet::MlDsa87,
    ] {
        let param_name = match param_set {
            ParameterSet::MlDsa44 => "ML-DSA-44",
            ParameterSet::MlDsa65 => "ML-DSA-65",
            ParameterSet::MlDsa87 => "ML-DSA-87",
        };
        
        group.bench_function(BenchmarkId::new("KeyGen", param_name), |b| {
            b.iter(|| {
                KeyPair::generate(black_box(*param_set)).unwrap()
            })
        });
    }
    
    group.finish();
}

pub fn ml_dsa_sign_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA Signing");
    
    // Generate key pairs for each parameter set
    let keypair_44 = KeyPair::generate(ParameterSet::MlDsa44).unwrap();
    let keypair_65 = KeyPair::generate(ParameterSet::MlDsa65).unwrap();
    let keypair_87 = KeyPair::generate(ParameterSet::MlDsa87).unwrap();
    
    // Test messages of different sizes
    let small_message = b"Small test message for signing";
    let medium_message = vec![b'A'; 1024]; // 1KB message
    let large_message = vec![b'B'; 8192];  // 8KB message
    
    // Empty context
    let context = b"";
    
    // Benchmark signing with different parameter sets and message sizes
    for (size_name, message) in [
        ("Small", small_message.as_slice()),
        ("Medium", medium_message.as_slice()),
        ("Large", large_message.as_slice()),
    ] {
        // Benchmark for hedged mode
        group.bench_function(BenchmarkId::new(format!("Sign-{}-Hedged", size_name), "ML-DSA-44"), |b| {
            b.iter(|| {
                dsa::sign(
                    black_box(&keypair_44.private_key()),
                    black_box(message),
                    black_box(context),
                    black_box(SigningMode::Hedged)
                ).unwrap()
            })
        });
        
        group.bench_function(BenchmarkId::new(format!("Sign-{}-Hedged", size_name), "ML-DSA-65"), |b| {
            b.iter(|| {
                dsa::sign(
                    black_box(&keypair_65.private_key()),
                    black_box(message),
                    black_box(context),
                    black_box(SigningMode::Hedged)
                ).unwrap()
            })
        });
        
        group.bench_function(BenchmarkId::new(format!("Sign-{}-Hedged", size_name), "ML-DSA-87"), |b| {
            b.iter(|| {
                dsa::sign(
                    black_box(&keypair_87.private_key()),
                    black_box(message),
                    black_box(context),
                    black_box(SigningMode::Hedged)
                ).unwrap()
            })
        });
        
        // Benchmark for deterministic mode
        group.bench_function(BenchmarkId::new(format!("Sign-{}-Deterministic", size_name), "ML-DSA-44"), |b| {
            b.iter(|| {
                dsa::sign(
                    black_box(&keypair_44.private_key()),
                    black_box(message),
                    black_box(context),
                    black_box(SigningMode::Deterministic)
                ).unwrap()
            })
        });
    }
    
    group.finish();
}

pub fn ml_dsa_verify_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA Verification");
    
    // Generate key pairs for each parameter set
    let keypair_44 = KeyPair::generate(ParameterSet::MlDsa44).unwrap();
    let keypair_65 = KeyPair::generate(ParameterSet::MlDsa65).unwrap();
    let keypair_87 = KeyPair::generate(ParameterSet::MlDsa87).unwrap();
    
    // Test messages of different sizes
    let small_message = b"Small test message for signing";
    let medium_message = vec![b'A'; 1024]; // 1KB message
    let large_message = vec![b'B'; 8192];  // 8KB message
    
    // Empty context
    let context = b"";
    
    // Create signatures for each parameter set and message size
    let sign_44_small = dsa::sign(&keypair_44.private_key(), small_message, context, SigningMode::Deterministic).unwrap();
    let sign_44_medium = dsa::sign(&keypair_44.private_key(), &medium_message, context, SigningMode::Deterministic).unwrap();
    let sign_44_large = dsa::sign(&keypair_44.private_key(), &large_message, context, SigningMode::Deterministic).unwrap();
    
    let sign_65_small = dsa::sign(&keypair_65.private_key(), small_message, context, SigningMode::Deterministic).unwrap();
    let sign_87_small = dsa::sign(&keypair_87.private_key(), small_message, context, SigningMode::Deterministic).unwrap();
    
    // Benchmark verification with different parameter sets and message sizes
    group.bench_function(BenchmarkId::new("Verify-Small", "ML-DSA-44"), |b| {
        b.iter(|| {
            dsa::verify(
                black_box(&keypair_44.public_key()),
                black_box(small_message),
                black_box(&sign_44_small),
                black_box(context)
            ).unwrap()
        })
    });
    
    group.bench_function(BenchmarkId::new("Verify-Medium", "ML-DSA-44"), |b| {
        b.iter(|| {
            dsa::verify(
                black_box(&keypair_44.public_key()),
                black_box(&medium_message),
                black_box(&sign_44_medium),
                black_box(context)
            ).unwrap()
        })
    });
    
    group.bench_function(BenchmarkId::new("Verify-Large", "ML-DSA-44"), |b| {
        b.iter(|| {
            dsa::verify(
                black_box(&keypair_44.public_key()),
                black_box(&large_message),
                black_box(&sign_44_large),
                black_box(context)
            ).unwrap()
        })
    });
    
    group.bench_function(BenchmarkId::new("Verify-Small", "ML-DSA-65"), |b| {
        b.iter(|| {
            dsa::verify(
                black_box(&keypair_65.public_key()),
                black_box(small_message),
                black_box(&sign_65_small),
                black_box(context)
            ).unwrap()
        })
    });
    
    group.bench_function(BenchmarkId::new("Verify-Small", "ML-DSA-87"), |b| {
        b.iter(|| {
            dsa::verify(
                black_box(&keypair_87.public_key()),
                black_box(small_message),
                black_box(&sign_87_small),
                black_box(context)
            ).unwrap()
        })
    });
    
    group.finish();
}

pub fn ml_dsa_full_cycle_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA Full Cycle");
    
    // Test message
    let message = b"Test message for full cycle benchmarking";
    
    // Empty context
    let context = b"";
    
    for param_set in &[
        ParameterSet::MlDsa44,
        ParameterSet::MlDsa65,
        ParameterSet::MlDsa87,
    ] {
        let param_name = match param_set {
            ParameterSet::MlDsa44 => "ML-DSA-44",
            ParameterSet::MlDsa65 => "ML-DSA-65",
            ParameterSet::MlDsa87 => "ML-DSA-87",
        };
        
        group.bench_function(BenchmarkId::new("Full Cycle", param_name), |b| {
            b.iter(|| {
                // Generate key pair
                let keypair = KeyPair::generate(black_box(*param_set)).unwrap();
                
                // Sign message
                let signature = dsa::sign(
                    &keypair.private_key(),
                    message,
                    context,
                    SigningMode::Hedged
                ).unwrap();
                
                // Verify signature
                let is_valid = dsa::verify(
                    &keypair.public_key(),
                    message,
                    &signature,
                    context
                ).unwrap();
                
                // Verify result
                assert!(is_valid);
                
                is_valid
            })
        });
    }
    
    group.finish();
}

pub fn ml_dsa_stamp_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA Stamp Operations");
    
    // Generate key pairs
    let keypair_44 = KeyPair::generate(ParameterSet::MlDsa44).unwrap();
    
    // Create stamp
    let stamp = dsa::stamp::Stamp::new(keypair_44.private_key());
    
    // Test messages
    let small_message = b"Small test message for stamping";
    let medium_message = vec![b'A'; 1024]; // 1KB message
    
    // Benchmark stamping with different message sizes
    group.bench_function("Stamp-Small", |b| {
        b.iter(|| {
            black_box(stamp.stamp_document(black_box(small_message))).unwrap()
        })
    });
    
    group.bench_function("Stamp-Medium", |b| {
        b.iter(|| {
            black_box(stamp.stamp_document(black_box(&medium_message))).unwrap()
        })
    });
    
    // Benchmark stamping with hash
    group.bench_function("Stamp-With-Hash", |b| {
        b.iter(|| {
            black_box(stamp.stamp_document_with_hash(
                black_box(small_message),
                black_box(dsa::HashFunction::SHA3_256)
            )).unwrap()
        })
    });
    
    group.finish();
}

criterion_group!(
    dsa_benches,
    ml_dsa_keygen_benchmark,
    ml_dsa_sign_benchmark,
    ml_dsa_verify_benchmark,
    ml_dsa_full_cycle_benchmark,
    ml_dsa_stamp_benchmark,
);
criterion_main!(dsa_benches);