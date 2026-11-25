//! Constant-time modular reduction.
//!
//! `%` / `rem_euclid` by a modulus that is only known at run time compiles to a
//! hardware divide, whose latency depends on its operands on many CPUs. Doing
//! that on secret coefficients leaks them through timing (cf. KyberSlash). The
//! helpers here use Barrett reduction (a 64x64->128 multiply and shifts) plus
//! mask-based corrections, so there is no divide and no secret-dependent branch.

/// ML-KEM modulus.
pub const Q_KEM: i32 = 3329;
/// ML-DSA modulus.
pub const Q_DSA: i32 = 8_380_417;

/// Barrett constant ⌊2^64 / q⌋ for a (public) modulus `q`.
#[inline]
pub const fn barrett_const(q: i32) -> i128 {
    ((1u128 << 64) / q as u128) as i128
}

const M_KEM: i128 = barrett_const(Q_KEM);
const M_DSA: i128 = barrett_const(Q_DSA);

/// Barrett constant for `q`, without a run-time division for the two moduli
/// this crate uses.
#[inline]
pub fn barrett_for(q: i32) -> i128 {
    match q {
        Q_KEM => M_KEM,
        Q_DSA => M_DSA,
        _ => barrett_const(q),
    }
}

/// `x mod q` in `[0, q)`, in constant time, for any `|x| < 2^62`.
///
/// With `m = ⌊2^64/q⌋`, the estimated quotient is off by at most one in either
/// direction, so `x - quot·q` lies in `[-q, 2q)`; two masked corrections bring
/// it into `[0, q)`.
#[inline(always)]
pub fn ct_mod(x: i64, q: i32, m: i128) -> i32 {
    let q = q as i64;
    let quot = ((x as i128 * m) >> 64) as i64;
    let mut r = x - quot * q; // [-q, 2q)
    r += q & (r >> 63); // [0, 2q)
    r -= q; // [-q, q)
    r += q & (r >> 63); // [0, q)
    r as i32
}

/// Map `x` in `(-q, 2q)` into `[0, q)` without branching.
#[inline(always)]
pub fn ct_normalize_small(x: i32, q: i32) -> i32 {
    let mut r = x;
    r += q & (r >> 31); // (-q, 2q) -> [0, 2q)
    r -= q;
    r += q & (r >> 31); // [0, q)
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    fn check(q: i32, x: i64) {
        assert_eq!(
            ct_mod(x, q, barrett_for(q)) as i64,
            x.rem_euclid(q as i64),
            "q={q} x={x}"
        );
    }

    #[test]
    fn ct_mod_matches_rem_euclid() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        for q in [Q_KEM, Q_DSA] {
            let qq = q as i64;
            for x in [
                0,
                1,
                -1,
                qq - 1,
                qq,
                qq + 1,
                -qq,
                -qq - 1,
                i64::from(i32::MAX),
                i64::from(i32::MIN),
            ] {
                check(q, x);
            }
            for x in [
                qq * qq,
                -qq * qq,
                qq * qq * 4,
                (1i64 << 62) - 1,
                -(1i64 << 62) + 1,
            ] {
                check(q, x);
            }
            for _ in 0..200_000 {
                check(q, rng.gen_range(-(1i64 << 62) + 1..(1i64 << 62)));
                check(q, rng.gen_range(-qq * qq..qq * qq));
            }
        }
    }

    #[test]
    fn ct_normalize_small_matches() {
        for q in [Q_KEM, Q_DSA] {
            for x in [-q + 1, -1, 0, 1, q - 1, q, 2 * q - 1] {
                assert_eq!(ct_normalize_small(x, q), x.rem_euclid(q), "q={q} x={x}");
            }
        }
    }
}
