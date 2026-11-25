//! Adversarial differential tests (stable Rust, runs in normal CI).
//!
//! Drives the oracles in `tests/support/oracles.rs` with seeded, structure-aware
//! mutations of genuine keys, ciphertexts and signatures: bit flips, byte
//! edits, coefficient overflows, truncations and random bytes. The same oracles
//! back the coverage-guided libFuzzer targets in `fuzz/`.
//!
//! Tune with environment variables:
//! - `TURTL_ADV_ITERS` — mutations per oracle and parameter set (default 48)
//! - `TURTL_ADV_SEED`  — RNG seed (default fixed, so CI is reproducible)

#[path = "support/oracles.rs"]
mod oracles;

use fips203::traits::{Encaps as _, KeyGen as _, SerDes as _};
use fips204::traits::{KeyGen as _, SerDes as _};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn iters() -> usize {
    std::env::var("TURTL_ADV_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(48)
}

fn rng(stream: u64) -> ChaCha20Rng {
    let seed = std::env::var("TURTL_ADV_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x7u64 << 40);
    let mut r = ChaCha20Rng::seed_from_u64(seed);
    r.set_stream(stream);
    r
}

/// Structure-aware mutation of a genuine encoding.
fn mutate(rng: &mut ChaCha20Rng, base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    match rng.gen_range(0..8) {
        // single bit flip
        0 => {
            let i = rng.gen_range(0..v.len());
            v[i] ^= 1 << rng.gen_range(0..8);
        }
        // a few random byte edits
        1 => {
            for _ in 0..rng.gen_range(1..8) {
                let i = rng.gen_range(0..v.len());
                v[i] = rng.gen();
            }
        }
        // saturate a 12-bit/packed field (pushes coefficients out of range)
        2 => {
            let i = rng.gen_range(0..v.len().saturating_sub(1));
            v[i] = 0xFF;
            v[i + 1] |= 0x0F;
        }
        // overwrite a run with 0xFF / 0x00
        3 | 4 => {
            let fill = if rng.gen() { 0xFF } else { 0x00 };
            let start = rng.gen_range(0..v.len());
            let end = (start + rng.gen_range(1..64)).min(v.len());
            v[start..end].fill(fill);
        }
        // tail edits (hint / z / t0 regions live at the end)
        5 => {
            let n = v.len();
            for _ in 0..rng.gen_range(1..4) {
                let i = n - 1 - rng.gen_range(0..n.min(96));
                v[i] = rng.gen();
            }
        }
        // fully random bytes of the right length
        6 => rng.fill_bytes(&mut v),
        // wrong length
        _ => {
            if rng.gen() {
                v.truncate(rng.gen_range(0..v.len()));
            } else {
                v.push(rng.gen());
            }
        }
    }
    v
}

fn with_selector(sel: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![sel];
    v.extend_from_slice(body);
    v
}

macro_rules! kem_suite {
    ($name:ident, $refmod:path, $sel:expr) => {
        #[test]
        fn $name() {
            use $refmod as r;
            let mut rng = rng(0x100 + $sel as u64);
            let (ek, dk) = r::KG::keygen_from_seed([0x5a; 32], [0xa5; 32]);
            let (_, ct) = ek.encaps_from_seed(&[0x33; 32]);
            let (ek, dk, ct) = (ek.into_bytes(), dk.into_bytes(), ct.into_bytes());

            for _ in 0..iters() {
                oracles::kem_decaps(&with_selector($sel, &mutate(&mut rng, &ct)));

                let mut m = [0u8; 32];
                rng.fill_bytes(&mut m);
                let mut input = m.to_vec();
                input.extend_from_slice(&mutate(&mut rng, &ek));
                oracles::kem_encaps(&with_selector($sel, &input));

                oracles::kem_dk(&with_selector($sel, &mutate(&mut rng, &dk)));
            }
            // genuine inputs must also agree
            oracles::kem_decaps(&with_selector($sel, &ct));
            oracles::kem_dk(&with_selector($sel, &dk));
        }
    };
}

kem_suite!(adversarial_kem_512, fips203::ml_kem_512, 0u8);
kem_suite!(adversarial_kem_768, fips203::ml_kem_768, 1u8);
kem_suite!(adversarial_kem_1024, fips203::ml_kem_1024, 2u8);

macro_rules! dsa_suite {
    ($name:ident, $refmod:path, $sel:expr) => {
        #[test]
        fn $name() {
            use $refmod as r;
            let mut rng = rng(0x200 + $sel as u64);
            let (pk, sk) = r::KG::keygen_from_seed(&[0x3c; 32]);
            let (pk, sk) = (pk.into_bytes(), sk.into_bytes());

            for i in 0..iters() {
                // sparse edits of a genuine signature (mode 1), with a context
                let ctx_len = if i % 4 == 0 { rng.gen_range(0..8) } else { 0u8 };
                let mut input = vec![$sel, 1, ctx_len];
                input.extend((0..ctx_len).map(|_| rng.gen::<u8>()));
                for _ in 0..rng.gen_range(1..6) {
                    let pos: u16 = rng.gen();
                    input.extend_from_slice(&pos.to_le_bytes());
                    input.push(rng.gen_range(1..=255));
                }
                oracles::dsa_verify(&input);

                // raw random signature bytes (mode 0)
                let mut raw = vec![0u8; r::SIG_LEN];
                rng.fill_bytes(&mut raw);
                let mut input = vec![$sel, 0, 0];
                input.extend_from_slice(&raw);
                oracles::dsa_verify(&input);

                oracles::dsa_pk(&with_selector($sel, &mutate(&mut rng, &pk)));
                oracles::dsa_sk(&with_selector($sel, &mutate(&mut rng, &sk)));
            }
            // unmodified signature and keys must also agree
            oracles::dsa_verify(&[$sel, 1, 0]);
            oracles::dsa_pk(&with_selector($sel, &pk));
            oracles::dsa_sk(&with_selector($sel, &sk));
            let _ = r::PrivateKey::try_from_bytes(sk);
        }
    };
}

dsa_suite!(adversarial_dsa_44, fips204::ml_dsa_44, 0u8);
dsa_suite!(adversarial_dsa_65, fips204::ml_dsa_65, 1u8);
dsa_suite!(adversarial_dsa_87, fips204::ml_dsa_87, 2u8);
