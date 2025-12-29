//! Benchmarks for ML-KEM operations.
//!
//! This module contains benchmarks for key generation, encapsulation, and
//! decapsulation operations for each ML-KEM parameter set.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use turtl::kem::{self, ParameterSet, KeyPair};

/// Benchmark ML-KEM-512 key generation
fn bench_kem512_keygen(c: &mut Criterion) {
    c.bench_function("ML-KEM-512 KeyGen", |b| {
        b.iter(|| {
            let keypair = KeyPair::generate(black_box(ParameterSet::MlKem512));
            black_box(keypair)
        })
    });
}

/// Benchmark ML-KEM-768 key generation
fn bench_kem768_keygen(c: &mut Criterion) {
    c.bench_function("ML-KEM-768 KeyGen", |b| {
        b.iter(|| {
            let keypair = KeyPair::generate(black_box(ParameterSet::MlKem768));
            black_box(keypair)
        })
    });
}

/// Benchmark ML-KEM-1024 key generation
fn bench_kem1024_keygen(c: &mut Criterion) {
    c.bench_function("ML-KEM-1024 KeyGen", |b| {
        b.iter(|| {
            let keypair = KeyPair::generate(black_box(ParameterSet::MlKem1024));
            black_box(keypair)
        })
    });
}

/// Benchmark ML-KEM-512 encapsulation
fn bench_kem512_encapsulate(c: &mut Criterion) {
    let keypair = KeyPair::generate(ParameterSet::MlKem512).unwrap();
    let public_key = keypair.public_key();

    c.bench_function("ML-KEM-512 Encapsulate", |b| {
        b.iter(|| {
            let (ciphertext, shared_secret) = kem::encapsulate(black_box(&public_key))
                .unwrap();
            black_box((ciphertext, shared_secret))
        })
    });
}

/// Benchmark ML-KEM-768 encapsulation
fn bench_kem768_encapsulate(c: &mut Criterion) {
    let keypair = KeyPair::generate(ParameterSet::MlKem768).unwrap();
    let public_key = keypair.public_key();

    c.bench_function("ML-KEM-768 Encapsulate", |b| {
        b.iter(|| {
            let (ciphertext, shared_secret) = kem::encapsulate(black_box(&public_key))
                .unwrap();
            black_box((ciphertext, shared_secret))
        })
    });
}

/// Benchmark ML-KEM-1024 encapsulation
fn bench_kem1024_encapsulate(c: &mut Criterion) {
    let keypair = KeyPair::generate(ParameterSet::MlKem1024).unwrap();
    let public_key = keypair.public_key();

    c.bench_function("ML-KEM-1024 Encapsulate", |b| {
        b.iter(|| {
            let (ciphertext, shared_secret) = kem::encapsulate(black_box(&public_key))
                .unwrap();
            black_box((ciphertext, shared_secret))
        })
    });
}

/// Benchmark ML-KEM-512 decapsulation
fn bench_kem512_decapsulate(c: &mut Criterion) {
    let keypair = KeyPair::generate(ParameterSet::MlKem512).unwrap();
    let public_key = keypair.public_key();
    let private_key = keypair.private_key();
    let (ciphertext, _shared_secret) = kem::encapsulate(&public_key).unwrap();

    c.bench_function("ML-KEM-512 Decapsulate", |b| {
        b.iter(|| {
            let shared_secret = kem::decapsulate(black_box(&private_key), black_box(&ciphertext))
                .unwrap();
            black_box(shared_secret)
        })
    });
}

/// Benchmark ML-KEM-768 decapsulation
fn bench_kem768_decapsulate(c: &mut Criterion) {
    let keypair = KeyPair::generate(ParameterSet::MlKem768).unwrap();
    let public_key = keypair.public_key();
    let private_key = keypair.private_key();
    let (ciphertext, _shared_secret) = kem::encapsulate(&public_key).unwrap();

    c.bench_function("ML-KEM-768 Decapsulate", |b| {
        b.iter(|| {
            let shared_secret = kem::decapsulate(black_box(&private_key), black_box(&ciphertext))
                .unwrap();
            black_box(shared_secret)
        })
    });
}

/// Benchmark ML-KEM-1024 decapsulation
fn bench_kem1024_decapsulate(c: &mut Criterion) {
    let keypair = KeyPair::generate(ParameterSet::MlKem1024).unwrap();
    let public_key = keypair.public_key();
    let private_key = keypair.private_key();
    let (ciphertext, _shared_secret) = kem::encapsulate(&public_key).unwrap();

    c.bench_function("ML-KEM-1024 Decapsulate", |b| {
        b.iter(|| {
            let shared_secret = kem::decapsulate(black_box(&private_key), black_box(&ciphertext))
                .unwrap();
            black_box(shared_secret)
        })
    });
}

/// Benchmark all ML-KEM parameter sets for comparison
fn bench_all_parameter_sets(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM Parameter Sets");

    for param_set in [ParameterSet::MlKem512, ParameterSet::MlKem768, ParameterSet::MlKem1024] {
        let name = match param_set {
            ParameterSet::MlKem512 => "512",
            ParameterSet::MlKem768 => "768",
            ParameterSet::MlKem1024 => "1024",
            #[cfg(test)]
            _ => "test",
        };

        group.bench_with_input(BenchmarkId::new("KeyGen", name), &param_set, |b, &ps| {
            b.iter(|| {
                let keypair = KeyPair::generate(black_box(ps));
                black_box(keypair)
            })
        });

        let keypair = KeyPair::generate(param_set).unwrap();
        let public_key = keypair.public_key();
        let private_key = keypair.private_key();

        group.bench_with_input(BenchmarkId::new("Encapsulate", name), &public_key, |b, pk| {
            b.iter(|| {
                let (ciphertext, shared_secret) = kem::encapsulate(black_box(pk))
                    .unwrap();
                black_box((ciphertext, shared_secret))
            })
        });

        let (ciphertext, _shared_secret) = kem::encapsulate(&public_key).unwrap();

        group.bench_with_input(BenchmarkId::new("Decapsulate", name), &(&private_key, &ciphertext), |b, (sk, ct)| {
            b.iter(|| {
                let shared_secret = kem::decapsulate(black_box(sk), black_box(ct))
                    .unwrap();
                black_box(shared_secret)
            })
        });
    }

    group.finish();
}

criterion_group!(
    kem_benches,
    bench_kem512_keygen,
    bench_kem768_keygen,
    bench_kem1024_keygen,
    bench_kem512_encapsulate,
    bench_kem768_encapsulate,
    bench_kem1024_encapsulate,
    bench_kem512_decapsulate,
    bench_kem768_decapsulate,
    bench_kem1024_decapsulate,
    bench_all_parameter_sets,
);

criterion_main!(kem_benches);
