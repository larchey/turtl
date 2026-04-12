//! ML-DSA performance baseline.
//!
//! Records signing and verification times for all three parameter sets.

use std::time::Instant;
use turtl::dsa::{self, ParameterSet, SigningMode};

fn bench_parameter_set(param: ParameterSet, name: &str, iterations: usize) {
    eprintln!("\n--- {} ({} iterations) ---", name, iterations);

    // Generate keypair (measure once)
    let keygen_start = Instant::now();
    let (pk, sk) = dsa::key_gen(param).expect("keygen failed");
    let keygen_ms = keygen_start.elapsed().as_secs_f64() * 1000.0;
    eprintln!("KeyGen:        {:.2}ms", keygen_ms);

    // Prepare a realistic telemetry-sized payload (512 bytes — typical compressed telemetry)
    let payload: Vec<u8> = (0..512).map(|i| (i * 37 + 13) as u8).collect();

    // Measure signing
    let mut sign_times = Vec::with_capacity(iterations);
    let mut signatures = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let sig = dsa::sign(&sk, &payload, b"", SigningMode::Hedged).expect("sign failed");
        sign_times.push(start.elapsed().as_secs_f64() * 1000.0);
        signatures.push(sig);
    }

    // Measure verification
    let mut verify_times = Vec::with_capacity(iterations);
    for sig in &signatures {
        let start = Instant::now();
        let result = dsa::verify(&pk, &payload, sig, b"").expect("verify failed");
        verify_times.push(start.elapsed().as_secs_f64() * 1000.0);
        assert!(result, "Verification failed during benchmark");
    }

    // Compute stats
    let sign_mean = sign_times.iter().sum::<f64>() / iterations as f64;
    let verify_mean = verify_times.iter().sum::<f64>() / iterations as f64;

    let sign_min = sign_times.iter().cloned().fold(f64::MAX, f64::min);
    let sign_max = sign_times.iter().cloned().fold(f64::MIN, f64::max);
    let verify_min = verify_times.iter().cloned().fold(f64::MAX, f64::min);
    let verify_max = verify_times.iter().cloned().fold(f64::MIN, f64::max);

    let sign_stdev = (sign_times
        .iter()
        .map(|t| (t - sign_mean).powi(2))
        .sum::<f64>()
        / (iterations - 1) as f64)
        .sqrt();
    let verify_stdev = (verify_times
        .iter()
        .map(|t| (t - verify_mean).powi(2))
        .sum::<f64>()
        / (iterations - 1) as f64)
        .sqrt();

    eprintln!("Pub key size:  {} bytes", pk.as_bytes().len());
    eprintln!("Priv key size: {} bytes", sk.as_bytes().len());
    eprintln!("Signature:     {} bytes", signatures[0].as_bytes().len());
    eprintln!("Payload:       {} bytes", payload.len());
    eprintln!(
        "Sign   — mean: {:.2}ms  stdev: {:.2}ms  min: {:.2}ms  max: {:.2}ms",
        sign_mean, sign_stdev, sign_min, sign_max
    );
    eprintln!(
        "Verify — mean: {:.2}ms  stdev: {:.2}ms  min: {:.2}ms  max: {:.2}ms",
        verify_mean, verify_stdev, verify_min, verify_max
    );
}

#[test]
fn test_performance_baseline_debug() {
    let n = 20; // Fewer iterations in debug mode
    eprintln!("\n========================================");
    eprintln!("turtl ML-DSA Performance Baseline (DEBUG build)");
    eprintln!("NOTE: Run with --release for accurate numbers");
    eprintln!("========================================");

    bench_parameter_set(ParameterSet::MlDsa44, "ML-DSA-44", n);
    bench_parameter_set(ParameterSet::MlDsa65, "ML-DSA-65", n);
    bench_parameter_set(ParameterSet::MlDsa87, "ML-DSA-87", n);

    eprintln!("\n========================================");
    eprintln!("Baseline complete.");
    eprintln!("========================================\n");
}
