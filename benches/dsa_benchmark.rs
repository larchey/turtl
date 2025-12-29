//! Benchmarks for ML-DSA operations.
//!
//! This module contains benchmarks for key generation, signing, and
//! verification operations for each ML-DSA parameter set.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use turtl::dsa::{self, ParameterSet, SigningMode};

/// Benchmark ML-DSA-44 key generation
fn bench_dsa44_keygen(c: &mut Criterion) {
    c.bench_function("ML-DSA-44 KeyGen", |b| {
        b.iter(|| {
            let keypair = dsa::key_gen(black_box(ParameterSet::MlDsa44));
            black_box(keypair)
        })
    });
}

/// Benchmark ML-DSA-65 key generation
fn bench_dsa65_keygen(c: &mut Criterion) {
    c.bench_function("ML-DSA-65 KeyGen", |b| {
        b.iter(|| {
            let keypair = dsa::key_gen(black_box(ParameterSet::MlDsa65));
            black_box(keypair)
        })
    });
}

/// Benchmark ML-DSA-87 key generation
fn bench_dsa87_keygen(c: &mut Criterion) {
    c.bench_function("ML-DSA-87 KeyGen", |b| {
        b.iter(|| {
            let keypair = dsa::key_gen(black_box(ParameterSet::MlDsa87));
            black_box(keypair)
        })
    });
}

/// Benchmark ML-DSA-44 signing (hedged mode)
fn bench_dsa44_sign_hedged(c: &mut Criterion) {
    let (public_key, private_key) = dsa::key_gen(ParameterSet::MlDsa44).unwrap();
    let message = b"Benchmark message for ML-DSA signing performance testing";
    let context = b"";

    c.bench_function("ML-DSA-44 Sign (Hedged)", |b| {
        b.iter(|| {
            let signature = dsa::sign(
                black_box(&private_key),
                black_box(message),
                black_box(context),
                black_box(SigningMode::Hedged),
            )
            .unwrap();
            black_box(signature)
        })
    });
}

/// Benchmark ML-DSA-65 signing (hedged mode)
fn bench_dsa65_sign_hedged(c: &mut Criterion) {
    let (public_key, private_key) = dsa::key_gen(ParameterSet::MlDsa65).unwrap();
    let message = b"Benchmark message for ML-DSA signing performance testing";
    let context = b"";

    c.bench_function("ML-DSA-65 Sign (Hedged)", |b| {
        b.iter(|| {
            let signature = dsa::sign(
                black_box(&private_key),
                black_box(message),
                black_box(context),
                black_box(SigningMode::Hedged),
            )
            .unwrap();
            black_box(signature)
        })
    });
}

/// Benchmark ML-DSA-87 signing (hedged mode)
fn bench_dsa87_sign_hedged(c: &mut Criterion) {
    let (public_key, private_key) = dsa::key_gen(ParameterSet::MlDsa87).unwrap();
    let message = b"Benchmark message for ML-DSA signing performance testing";
    let context = b"";

    c.bench_function("ML-DSA-87 Sign (Hedged)", |b| {
        b.iter(|| {
            let signature = dsa::sign(
                black_box(&private_key),
                black_box(message),
                black_box(context),
                black_box(SigningMode::Hedged),
            )
            .unwrap();
            black_box(signature)
        })
    });
}

/// Benchmark ML-DSA-44 signing (deterministic mode)
fn bench_dsa44_sign_deterministic(c: &mut Criterion) {
    let (public_key, private_key) = dsa::key_gen(ParameterSet::MlDsa44).unwrap();
    let message = b"Benchmark message for ML-DSA signing performance testing";
    let context = b"";

    c.bench_function("ML-DSA-44 Sign (Deterministic)", |b| {
        b.iter(|| {
            let signature = dsa::sign(
                black_box(&private_key),
                black_box(message),
                black_box(context),
                black_box(SigningMode::Deterministic),
            )
            .unwrap();
            black_box(signature)
        })
    });
}

/// Benchmark ML-DSA-65 signing (deterministic mode)
fn bench_dsa65_sign_deterministic(c: &mut Criterion) {
    let (public_key, private_key) = dsa::key_gen(ParameterSet::MlDsa65).unwrap();
    let message = b"Benchmark message for ML-DSA signing performance testing";
    let context = b"";

    c.bench_function("ML-DSA-65 Sign (Deterministic)", |b| {
        b.iter(|| {
            let signature = dsa::sign(
                black_box(&private_key),
                black_box(message),
                black_box(context),
                black_box(SigningMode::Deterministic),
            )
            .unwrap();
            black_box(signature)
        })
    });
}

/// Benchmark ML-DSA-87 signing (deterministic mode)
fn bench_dsa87_sign_deterministic(c: &mut Criterion) {
    let (public_key, private_key) = dsa::key_gen(ParameterSet::MlDsa87).unwrap();
    let message = b"Benchmark message for ML-DSA signing performance testing";
    let context = b"";

    c.bench_function("ML-DSA-87 Sign (Deterministic)", |b| {
        b.iter(|| {
            let signature = dsa::sign(
                black_box(&private_key),
                black_box(message),
                black_box(context),
                black_box(SigningMode::Deterministic),
            )
            .unwrap();
            black_box(signature)
        })
    });
}

/// Benchmark ML-DSA-44 verification
fn bench_dsa44_verify(c: &mut Criterion) {
    let (public_key, private_key) = dsa::key_gen(ParameterSet::MlDsa44).unwrap();
    let message = b"Benchmark message for ML-DSA signing performance testing";
    let context = b"";
    let signature = dsa::sign(&private_key, message, context, SigningMode::Hedged).unwrap();

    c.bench_function("ML-DSA-44 Verify", |b| {
        b.iter(|| {
            let is_valid = dsa::verify(
                black_box(&public_key),
                black_box(message),
                black_box(&signature),
                black_box(context),
            )
            .unwrap();
            black_box(is_valid)
        })
    });
}

/// Benchmark ML-DSA-65 verification
fn bench_dsa65_verify(c: &mut Criterion) {
    let (public_key, private_key) = dsa::key_gen(ParameterSet::MlDsa65).unwrap();
    let message = b"Benchmark message for ML-DSA signing performance testing";
    let context = b"";
    let signature = dsa::sign(&private_key, message, context, SigningMode::Hedged).unwrap();

    c.bench_function("ML-DSA-65 Verify", |b| {
        b.iter(|| {
            let is_valid = dsa::verify(
                black_box(&public_key),
                black_box(message),
                black_box(&signature),
                black_box(context),
            )
            .unwrap();
            black_box(is_valid)
        })
    });
}

/// Benchmark ML-DSA-87 verification
fn bench_dsa87_verify(c: &mut Criterion) {
    let (public_key, private_key) = dsa::key_gen(ParameterSet::MlDsa87).unwrap();
    let message = b"Benchmark message for ML-DSA signing performance testing";
    let context = b"";
    let signature = dsa::sign(&private_key, message, context, SigningMode::Hedged).unwrap();

    c.bench_function("ML-DSA-87 Verify", |b| {
        b.iter(|| {
            let is_valid = dsa::verify(
                black_box(&public_key),
                black_box(message),
                black_box(&signature),
                black_box(context),
            )
            .unwrap();
            black_box(is_valid)
        })
    });
}

/// Benchmark all ML-DSA parameter sets for comparison
fn bench_all_parameter_sets(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-DSA Parameter Sets");

    for param_set in [ParameterSet::MlDsa44, ParameterSet::MlDsa65, ParameterSet::MlDsa87] {
        let name = match param_set {
            ParameterSet::MlDsa44 => "44",
            ParameterSet::MlDsa65 => "65",
            ParameterSet::MlDsa87 => "87",
            #[cfg(test)]
            _ => "test",
        };

        // Benchmark key generation
        group.bench_with_input(BenchmarkId::new("KeyGen", name), &param_set, |b, &ps| {
            b.iter(|| {
                let keypair = dsa::key_gen(black_box(ps));
                black_box(keypair)
            })
        });

        // Generate keys for signing/verification benchmarks
        let (public_key, private_key) = dsa::key_gen(param_set).unwrap();
        let message = b"Benchmark message for ML-DSA signing performance testing";
        let context = b"";

        // Benchmark signing (hedged mode)
        group.bench_with_input(
            BenchmarkId::new("Sign-Hedged", name),
            &(&private_key, message, context),
            |b, &(sk, msg, ctx)| {
                b.iter(|| {
                    let signature =
                        dsa::sign(black_box(sk), black_box(msg), black_box(ctx), SigningMode::Hedged)
                            .unwrap();
                    black_box(signature)
                })
            },
        );

        // Benchmark signing (deterministic mode)
        group.bench_with_input(
            BenchmarkId::new("Sign-Deterministic", name),
            &(&private_key, message, context),
            |b, &(sk, msg, ctx)| {
                b.iter(|| {
                    let signature = dsa::sign(
                        black_box(sk),
                        black_box(msg),
                        black_box(ctx),
                        SigningMode::Deterministic,
                    )
                    .unwrap();
                    black_box(signature)
                })
            },
        );

        // Generate signature for verification benchmark
        let signature = dsa::sign(&private_key, message, context, SigningMode::Hedged).unwrap();

        // Benchmark verification
        group.bench_with_input(
            BenchmarkId::new("Verify", name),
            &(&public_key, message, &signature, context),
            |b, &(pk, msg, sig, ctx)| {
                b.iter(|| {
                    let is_valid = dsa::verify(black_box(pk), black_box(msg), black_box(sig), black_box(ctx))
                        .unwrap();
                    black_box(is_valid)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    dsa_benches,
    bench_dsa44_keygen,
    bench_dsa65_keygen,
    bench_dsa87_keygen,
    bench_dsa44_sign_hedged,
    bench_dsa65_sign_hedged,
    bench_dsa87_sign_hedged,
    bench_dsa44_sign_deterministic,
    bench_dsa65_sign_deterministic,
    bench_dsa87_sign_deterministic,
    bench_dsa44_verify,
    bench_dsa65_verify,
    bench_dsa87_verify,
    bench_all_parameter_sets,
);

criterion_main!(dsa_benches);
