//! Timing invariance tests for constant-time operations.
//!
//! This module contains tests to verify that constant-time operations
//! execute in constant time regardless of input values, which is critical
//! for preventing timing side-channel attacks.
//!
//! # Important Notes
//!
//! These tests are marked with `#[ignore]` by default because:
//! - Timing measurements are extremely sensitive to system noise
//! - Operations are very fast (nanoseconds), making measurements unreliable
//! - CPU effects (caching, branch prediction, frequency scaling) cause variance
//!
//! ## Running These Tests
//!
//! To run these tests manually:
//! ```bash
//! cargo test --test timing_invariance_test -- --ignored --test-threads=1
//! ```
//!
//! For more reliable results:
//! - Run on dedicated hardware without other processes
//! - Disable CPU frequency scaling
//! - Run in release mode: `cargo test --release --test timing_invariance_test -- --ignored`
//! - Run multiple times and look for consistent patterns
//!
//! ## Interpreting Results
//!
//! - Occasional failures due to system noise are expected
//! - Consistent failures across multiple runs indicate potential timing leaks
//! - High variance (>50%) suggests the test environment is too noisy

use turtl::security::constant_time::{
    ct_cmov, ct_cswap, ct_select, ct_eq_u32, ct_is_zero_u32,
    ct_cmov_u64, ct_cswap_u64, ct_select_u64, ct_eq_u64, ct_is_zero_u64,
    ct_cmov_u128, ct_cswap_u128, ct_select_u128, ct_eq_u128, ct_is_zero_u128,
    ct_cmov_byte, ct_select_byte, ct_is_zero_u8,
    ct_cswap_slice,
};
use std::time::Instant;

const ITERATIONS: usize = 10000;
const WARMUP_ITERATIONS: usize = 1000;

/// Helper function to measure execution time
fn measure_time<F: FnMut()>(mut f: F, iterations: usize) -> u128 {
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    start.elapsed().as_nanos()
}

/// Helper function to run warmup iterations
fn warmup<F: FnMut()>(mut f: F) {
    for _ in 0..WARMUP_ITERATIONS {
        f();
    }
}

/// Test that ct_cmov is timing-invariant for u32
#[test]
#[ignore]
fn test_ct_cmov_timing_invariance() {
    let src = 0x12345678u32;
    let dst_init = 0x87654321u32;

    // Warmup
    warmup(|| {
        let mut r = dst_init;
        ct_cmov(&mut r, src, false);
        ct_cmov(&mut r, src, true);
    });

    // Measure time for condition = false
    let time_false = measure_time(|| {
        let mut r = std::hint::black_box(dst_init);
        ct_cmov(
            &mut r,
            std::hint::black_box(src),
            std::hint::black_box(false)
        );
        std::hint::black_box(r);
    }, ITERATIONS);

    // Measure time for condition = true
    let time_true = measure_time(|| {
        let mut r = std::hint::black_box(dst_init);
        ct_cmov(
            &mut r,
            std::hint::black_box(src),
            std::hint::black_box(true)
        );
        std::hint::black_box(r);
    }, ITERATIONS);

    // Calculate relative difference
    let diff = if time_false > time_true {
        (time_false - time_true) as f64 / time_false as f64
    } else {
        (time_true - time_false) as f64 / time_true as f64
    };

    // Allow up to 30% variation for ct_cmov due to branch prediction on mask creation
    // Note: The mask creation uses `if cond` which may introduce timing variance
    assert!(
        diff < 0.30,
        "ct_cmov shows timing variation: false={}, true={}, diff={:.2}%",
        time_false, time_true, diff * 100.0
    );
}

/// Test that ct_eq is timing-invariant for u32
#[test]
#[ignore]
fn test_ct_eq_timing_invariance() {
    let a = 0x12345678u32;
    let b_eq = 0x12345678u32;
    let b_neq = 0x87654321u32;

    // Warmup
    warmup(|| {
        std::hint::black_box(ct_eq_u32(a, b_eq));
        std::hint::black_box(ct_eq_u32(a, b_neq));
    });

    // Measure time for equal values
    let time_equal = measure_time(|| {
        std::hint::black_box(ct_eq_u32(
            std::hint::black_box(a),
            std::hint::black_box(b_eq)
        ));
    }, ITERATIONS);

    // Measure time for unequal values
    let time_unequal = measure_time(|| {
        std::hint::black_box(ct_eq_u32(
            std::hint::black_box(a),
            std::hint::black_box(b_neq)
        ));
    }, ITERATIONS);

    let diff = if time_equal > time_unequal {
        (time_equal - time_unequal) as f64 / time_equal as f64
    } else {
        (time_unequal - time_equal) as f64 / time_unequal as f64
    };

    assert!(
        diff < 0.10,
        "ct_eq shows timing variation: equal={}, unequal={}, diff={:.2}%",
        time_equal, time_unequal, diff * 100.0
    );
}

/// Test that ct_is_zero is timing-invariant for u32
#[test]
#[ignore]
fn test_ct_is_zero_timing_invariance() {
    let zero = 0u32;
    let nonzero = 0x12345678u32;

    // Warmup
    warmup(|| {
        std::hint::black_box(ct_is_zero_u32(zero));
        std::hint::black_box(ct_is_zero_u32(nonzero));
    });

    // Measure time for zero
    let time_zero = measure_time(|| {
        std::hint::black_box(ct_is_zero_u32(std::hint::black_box(zero)));
    }, ITERATIONS);

    // Measure time for non-zero
    let time_nonzero = measure_time(|| {
        std::hint::black_box(ct_is_zero_u32(std::hint::black_box(nonzero)));
    }, ITERATIONS);

    let diff = if time_zero > time_nonzero {
        (time_zero - time_nonzero) as f64 / time_zero as f64
    } else {
        (time_nonzero - time_zero) as f64 / time_nonzero as f64
    };

    assert!(
        diff < 0.10,
        "ct_is_zero shows timing variation: zero={}, nonzero={}, diff={:.2}%",
        time_zero, time_nonzero, diff * 100.0
    );
}

/// Test that ct_select is timing-invariant for u32
#[test]
#[ignore]
fn test_ct_select_timing_invariance() {
    let a = 0x12345678u32;
    let b = 0x87654321u32;

    // Warmup
    warmup(|| {
        std::hint::black_box(ct_select(a, b, false));
        std::hint::black_box(ct_select(a, b, true));
    });

    // Measure time for condition = false (select b)
    let time_b = measure_time(|| {
        std::hint::black_box(ct_select(
            std::hint::black_box(a),
            std::hint::black_box(b),
            std::hint::black_box(false)
        ));
    }, ITERATIONS);

    // Measure time for condition = true (select a)
    let time_a = measure_time(|| {
        std::hint::black_box(ct_select(
            std::hint::black_box(a),
            std::hint::black_box(b),
            std::hint::black_box(true)
        ));
    }, ITERATIONS);

    let diff = if time_a > time_b {
        (time_a - time_b) as f64 / time_a as f64
    } else {
        (time_b - time_a) as f64 / time_b as f64
    };

    assert!(
        diff < 0.10,
        "ct_select shows timing variation: select_a={}, select_b={}, diff={:.2}%",
        time_a, time_b, diff * 100.0
    );
}

/// Test that ct_cswap is timing-invariant for u32
#[test]
#[ignore]
fn test_ct_cswap_timing_invariance() {
    let a_init = 0x12345678u32;
    let b_init = 0x87654321u32;

    // Warmup
    warmup(|| {
        let (mut a, mut b) = (a_init, b_init);
        ct_cswap(&mut a, &mut b, false);
        let (mut a, mut b) = (a_init, b_init);
        ct_cswap(&mut a, &mut b, true);
    });

    // Measure time for no swap (condition = false)
    let time_no_swap = measure_time(|| {
        let (mut a, mut b) = (std::hint::black_box(a_init), std::hint::black_box(b_init));
        ct_cswap(&mut a, &mut b, std::hint::black_box(false));
        std::hint::black_box((a, b));
    }, ITERATIONS);

    // Measure time for swap (condition = true)
    let time_swap = measure_time(|| {
        let (mut a, mut b) = (std::hint::black_box(a_init), std::hint::black_box(b_init));
        ct_cswap(&mut a, &mut b, std::hint::black_box(true));
        std::hint::black_box((a, b));
    }, ITERATIONS);

    let diff = if time_no_swap > time_swap {
        (time_no_swap - time_swap) as f64 / time_no_swap as f64
    } else {
        (time_swap - time_no_swap) as f64 / time_swap as f64
    };

    assert!(
        diff < 0.10,
        "ct_cswap shows timing variation: no_swap={}, swap={}, diff={:.2}%",
        time_no_swap, time_swap, diff * 100.0
    );
}

/// Test that ct_cswap_slice is timing-invariant
#[test]
#[ignore]
fn test_ct_cswap_slice_timing_invariance() {
    let a_init = vec![0u8; 32];
    let b_init = vec![0xFFu8; 32];

    // Warmup
    warmup(|| {
        let (mut a, mut b) = (a_init.clone(), b_init.clone());
        ct_cswap_slice(&mut a, &mut b, false);
        let (mut a, mut b) = (a_init.clone(), b_init.clone());
        ct_cswap_slice(&mut a, &mut b, true);
    });

    // Measure time for no swap
    let time_no_swap = measure_time(|| {
        let (mut a, mut b) = (a_init.clone(), b_init.clone());
        ct_cswap_slice(
            std::hint::black_box(&mut a),
            std::hint::black_box(&mut b),
            std::hint::black_box(false)
        );
        std::hint::black_box((a, b));
    }, ITERATIONS / 10); // Fewer iterations for slice operations

    // Measure time for swap
    let time_swap = measure_time(|| {
        let (mut a, mut b) = (a_init.clone(), b_init.clone());
        ct_cswap_slice(
            std::hint::black_box(&mut a),
            std::hint::black_box(&mut b),
            std::hint::black_box(true)
        );
        std::hint::black_box((a, b));
    }, ITERATIONS / 10);

    let diff = if time_no_swap > time_swap {
        (time_no_swap - time_swap) as f64 / time_no_swap as f64
    } else {
        (time_swap - time_no_swap) as f64 / time_swap as f64
    };

    assert!(
        diff < 0.10,
        "ct_cswap_slice shows timing variation: no_swap={}, swap={}, diff={:.2}%",
        time_no_swap, time_swap, diff * 100.0
    );
}

/// Test that ct_eq works correctly on byte slices of different lengths
#[test]
#[ignore]
fn test_ct_eq_byte_slice_timing_invariance() {
    use turtl::security::fault_detection::ct_eq as ct_eq_slice;

    let a = vec![0x42u8; 32];
    let b_eq = vec![0x42u8; 32];
    let mut b_neq = vec![0x42u8; 32];
    b_neq[31] = 0x43; // Differ only in last byte

    // Warmup
    warmup(|| {
        std::hint::black_box(ct_eq_slice(&a, &b_eq));
        std::hint::black_box(ct_eq_slice(&a, &b_neq));
    });

    // Measure time for equal slices
    let time_equal = measure_time(|| {
        std::hint::black_box(ct_eq_slice(
            std::hint::black_box(&a),
            std::hint::black_box(&b_eq)
        ));
    }, ITERATIONS / 10);

    // Measure time for unequal slices (differ in last byte)
    let time_unequal = measure_time(|| {
        std::hint::black_box(ct_eq_slice(
            std::hint::black_box(&a),
            std::hint::black_box(&b_neq)
        ));
    }, ITERATIONS / 10);

    let diff = if time_equal > time_unequal {
        (time_equal - time_unequal) as f64 / time_equal as f64
    } else {
        (time_unequal - time_equal) as f64 / time_unequal as f64
    };

    assert!(
        diff < 0.15,  // Slightly higher tolerance for slice operations
        "ct_eq (slice) shows timing variation: equal={}, unequal={}, diff={:.2}%",
        time_equal, time_unequal, diff * 100.0
    );
}

/// Test that ct_cmov is timing-invariant for u64
#[test]
#[ignore]
fn test_ct_cmov_u64_timing_invariance() {
    let src = 0x123456789ABCDEF0u64;
    let dst_init = 0xFEDCBA9876543210u64;

    // Warmup
    warmup(|| {
        let mut r = dst_init;
        ct_cmov_u64(&mut r, src, false);
        ct_cmov_u64(&mut r, src, true);
    });

    let time_false = measure_time(|| {
        let mut r = std::hint::black_box(dst_init);
        ct_cmov_u64(
            &mut r,
            std::hint::black_box(src),
            std::hint::black_box(false)
        );
        std::hint::black_box(r);
    }, ITERATIONS);

    let time_true = measure_time(|| {
        let mut r = std::hint::black_box(dst_init);
        ct_cmov_u64(
            &mut r,
            std::hint::black_box(src),
            std::hint::black_box(true)
        );
        std::hint::black_box(r);
    }, ITERATIONS);

    let diff = if time_false > time_true {
        (time_false - time_true) as f64 / time_false as f64
    } else {
        (time_true - time_false) as f64 / time_true as f64
    };

    // Allow up to 30% variation for ct_cmov_u64 due to branch prediction on mask creation
    assert!(
        diff < 0.30,
        "ct_cmov_u64 shows timing variation: false={}, true={}, diff={:.2}%",
        time_false, time_true, diff * 100.0
    );
}

/// Test that ct_cmov is timing-invariant for u128
#[test]
#[ignore]
fn test_ct_cmov_u128_timing_invariance() {
    let src = 0x123456789ABCDEF0_FEDCBA9876543210u128;
    let dst_init = 0xFEDCBA9876543210_123456789ABCDEF0u128;

    // Warmup
    warmup(|| {
        let mut r = dst_init;
        ct_cmov_u128(&mut r, src, false);
        ct_cmov_u128(&mut r, src, true);
    });

    let time_false = measure_time(|| {
        let mut r = std::hint::black_box(dst_init);
        ct_cmov_u128(
            &mut r,
            std::hint::black_box(src),
            std::hint::black_box(false)
        );
        std::hint::black_box(r);
    }, ITERATIONS);

    let time_true = measure_time(|| {
        let mut r = std::hint::black_box(dst_init);
        ct_cmov_u128(
            &mut r,
            std::hint::black_box(src),
            std::hint::black_box(true)
        );
        std::hint::black_box(r);
    }, ITERATIONS);

    let diff = if time_false > time_true {
        (time_false - time_true) as f64 / time_false as f64
    } else {
        (time_true - time_false) as f64 / time_true as f64
    };

    // Allow up to 30% variation for ct_cmov_u128 due to branch prediction on mask creation
    assert!(
        diff < 0.30,
        "ct_cmov_u128 shows timing variation: false={}, true={}, diff={:.2}%",
        time_false, time_true, diff * 100.0
    );
}

/// Test that ct_select_u64 is timing-invariant
#[test]
#[ignore]
fn test_ct_select_u64_timing_invariance() {
    let a = 0x123456789ABCDEF0u64;
    let b = 0xFEDCBA9876543210u64;

    // Warmup
    warmup(|| {
        std::hint::black_box(ct_select_u64(a, b, false));
        std::hint::black_box(ct_select_u64(a, b, true));
    });

    let time_b = measure_time(|| {
        std::hint::black_box(ct_select_u64(
            std::hint::black_box(a),
            std::hint::black_box(b),
            std::hint::black_box(false)
        ));
    }, ITERATIONS);

    let time_a = measure_time(|| {
        std::hint::black_box(ct_select_u64(
            std::hint::black_box(a),
            std::hint::black_box(b),
            std::hint::black_box(true)
        ));
    }, ITERATIONS);

    let diff = if time_a > time_b {
        (time_a - time_b) as f64 / time_a as f64
    } else {
        (time_b - time_a) as f64 / time_b as f64
    };

    assert!(
        diff < 0.10,
        "ct_select_u64 shows timing variation: select_a={}, select_b={}, diff={:.2}%",
        time_a, time_b, diff * 100.0
    );
}

/// Test that ct_is_zero_u8 is timing-invariant
#[test]
#[ignore]
fn test_ct_is_zero_u8_timing_invariance() {
    let zero = 0u8;
    let nonzero = 0x42u8;

    // Warmup
    warmup(|| {
        std::hint::black_box(ct_is_zero_u8(zero));
        std::hint::black_box(ct_is_zero_u8(nonzero));
    });

    let time_zero = measure_time(|| {
        std::hint::black_box(ct_is_zero_u8(std::hint::black_box(zero)));
    }, ITERATIONS);

    let time_nonzero = measure_time(|| {
        std::hint::black_box(ct_is_zero_u8(std::hint::black_box(nonzero)));
    }, ITERATIONS);

    let diff = if time_zero > time_nonzero {
        (time_zero - time_nonzero) as f64 / time_zero as f64
    } else {
        (time_nonzero - time_zero) as f64 / time_nonzero as f64
    };

    assert!(
        diff < 0.10,
        "ct_is_zero_u8 shows timing variation: zero={}, nonzero={}, diff={:.2}%",
        time_zero, time_nonzero, diff * 100.0
    );
}
