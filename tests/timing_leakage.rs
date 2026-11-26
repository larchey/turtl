//! dudect-style timing-leakage checks (Welch's t-test on two input classes).
//!
//! Ignored by default because wall-clock measurements are noisy; the
//! adversarial workflow runs them on a quiet runner with:
//!
//! ```text
//! cargo test --release --test timing_leakage -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! Each test interleaves the two classes in random order, drops the slowest
//! samples (interrupts, migrations), and fails if |t| exceeds `T_THRESHOLD`.
//! dudect treats |t| > 4.5 as evidence of a leak; we fail at 10 to stay robust
//! against shared-runner noise and report the statistic either way.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;
use std::time::Instant;
use turtl::kem;

const T_THRESHOLD: f64 = 10.0;

fn samples() -> usize {
    std::env::var("TURTL_TIMING_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000)
}

/// Welch's t statistic between two sample sets, after dropping the slowest 5%
/// of each.
fn welch_t(mut a: Vec<f64>, mut b: Vec<f64>) -> f64 {
    for v in [&mut a, &mut b] {
        v.sort_by(|x, y| x.partial_cmp(y).unwrap());
        let keep = v.len() * 95 / 100;
        v.truncate(keep);
    }
    let stats = |v: &[f64]| {
        let n = v.len() as f64;
        let mean = v.iter().sum::<f64>() / n;
        let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
        (mean, var, n)
    };
    let (ma, va, na) = stats(&a);
    let (mb, vb, nb) = stats(&b);
    (ma - mb) / (va / na + vb / nb).sqrt()
}

/// Time `op(class)` for randomly interleaved classes 0 and 1.
fn measure(mut op: impl FnMut(bool)) -> f64 {
    let mut rng = ChaCha20Rng::seed_from_u64(0xdec0de);
    let (mut a, mut b) = (Vec::new(), Vec::new());
    // warm-up
    for i in 0..200 {
        op(i % 2 == 0);
    }
    for _ in 0..samples() {
        let class: bool = rng.gen();
        let start = Instant::now();
        op(class);
        let ns = start.elapsed().as_nanos() as f64;
        if class {
            a.push(ns)
        } else {
            b.push(ns)
        }
    }
    welch_t(a, b)
}

/// Like [`measure`], but `setup(class)` prepares the input *outside* the timed
/// region, writing both classes into the same buffer so they differ only in
/// data, never in address or cache placement.
fn measure_prepared<S>(
    state: &mut S,
    mut setup: impl FnMut(&mut S, bool),
    mut op: impl FnMut(&S),
) -> f64 {
    let mut rng = ChaCha20Rng::seed_from_u64(0xdec0de);
    let (mut a, mut b) = (Vec::new(), Vec::new());
    for i in 0..200 {
        setup(state, i % 2 == 0);
        op(state);
    }
    for _ in 0..samples() {
        let class: bool = rng.gen();
        setup(state, class);
        let start = Instant::now();
        op(state);
        let ns = start.elapsed().as_nanos() as f64;
        if class {
            a.push(ns)
        } else {
            b.push(ns)
        }
    }
    welch_t(a, b)
}

fn check(name: &str, t: f64) {
    println!("{name}: |t| = {:.2} (threshold {T_THRESHOLD})", t.abs());
    assert!(
        t.abs() < T_THRESHOLD,
        "{name}: timing differs between classes (|t| = {:.2})",
        t.abs()
    );
}

/// Implicit rejection must not be distinguishable by timing: decapsulating a
/// valid ciphertext vs. a tampered one (which yields the rejection key K̄).
#[test]
#[ignore]
fn decaps_valid_vs_invalid_ciphertext() {
    let ps = kem::ParameterSet::MlKem768;
    let kp = kem::KeyPair::from_seeds(&[1; 32], &[2; 32], ps).unwrap();
    let (valid, _) = kem::encapsulate_deterministic(&kp.public_key(), &[3; 32]).unwrap();
    let mut bad = valid.as_bytes().to_vec();
    bad[0] ^= 1;
    let invalid = kem::Ciphertext::new(bad, ps).unwrap();
    let sk = kp.private_key();

    let t = measure(|c| {
        let ct = if c { &valid } else { &invalid };
        black_box(kem::decapsulate(black_box(&sk), black_box(ct)).unwrap());
    });
    check("ML-KEM-768 decaps valid/invalid", t);
}

/// Constant-time slice comparison: equal inputs vs. inputs differing in the
/// first byte (the case an early-exit comparison would leak).
#[test]
#[ignore]
fn ct_eq_equal_vs_first_byte_differs() {
    let a = vec![0x5au8; 1088];
    let mut other = a.clone();

    let t = measure_prepared(
        &mut other,
        |other, equal| {
            other.copy_from_slice(&a);
            if !equal {
                other[0] ^= 0xff;
            }
        },
        |other| {
            black_box(turtl::security::ct_eq(black_box(&a), black_box(other)));
        },
    );
    check("ct_eq equal/first-byte-differs", t);
}

/// Control: the harness must flag a deliberately leaky early-exit comparison,
/// otherwise a passing result above means nothing.
#[test]
#[ignore]
fn harness_detects_early_exit_compare() {
    fn leaky_eq(a: &[u8], b: &[u8]) -> bool {
        a.iter().zip(b).all(|(x, y)| x == y)
    }
    let a = vec![0x5au8; 1088];
    let mut other = a.clone();

    let t = measure_prepared(
        &mut other,
        |other, equal| {
            other.copy_from_slice(&a);
            if !equal {
                other[0] ^= 0xff;
            }
        },
        |other| {
            black_box(leaky_eq(black_box(&a), black_box(other)));
        },
    );
    println!("control (leaky compare): |t| = {:.2}", t.abs());
    assert!(
        t.abs() > T_THRESHOLD,
        "harness failed to detect a known leak"
    );
}

/// Secret-dependent arithmetic in decryption: with one key, decapsulate an
/// all-zero ciphertext (so s·u = 0) vs. random ciphertexts (s·u spans the whole
/// range). Both are implicitly rejected, and everything else in the pipeline is
/// data-independent, so a difference comes from arithmetic on the secret key.
/// This is the KyberSlash shape: variable-time division on secret products.
#[test]
#[ignore]
fn decaps_zero_vs_random_ciphertext() {
    let ps = kem::ParameterSet::MlKem768;
    let kp = kem::KeyPair::from_seeds(&[1; 32], &[2; 32], ps).unwrap();
    let sk = kp.private_key();
    let zero = kem::Ciphertext::new(vec![0u8; ps.ciphertext_size()], ps).unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let random: Vec<kem::Ciphertext> = (0..64)
        .map(|_| {
            let mut b = vec![0u8; ps.ciphertext_size()];
            rng.fill(&mut b[..]);
            kem::Ciphertext::new(b, ps).unwrap()
        })
        .collect();
    let mut i = 0;

    let t = measure(|c| {
        let ct = if c {
            &zero
        } else {
            i = (i + 1) % random.len();
            &random[i]
        };
        black_box(kem::decapsulate(black_box(&sk), black_box(ct)).unwrap());
    });
    check("ML-KEM-768 decaps zero/random ciphertext", t);
}
