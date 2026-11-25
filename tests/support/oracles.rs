//! Adversarial differential oracles: turtl vs. the `fips203` / `fips204`
//! reference implementations on attacker-controlled bytes.
//!
//! Every oracle takes raw input bytes, interprets the first byte as a parameter
//! set selector, and panics (= finding) whenever turtl and the reference
//! disagree, or turtl panics / returns an error where the standard says the
//! operation must succeed or return `false`.
//!
//! Shared by the libFuzzer targets in `fuzz/fuzz_targets/` (coverage-guided,
//! nightly) and by `tests/adversarial.rs` (seeded random inputs, stable CI).

#![allow(dead_code)]

use fips203::traits::{Decaps as _, Encaps as _, KeyGen as _, SerDes as _};
use fips204::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};
use turtl::{dsa, kem};

const KEM_D: [u8; 32] = [0x5a; 32];
const KEM_Z: [u8; 32] = [0xa5; 32];
const DSA_XI: [u8; 32] = [0x3c; 32];
const FIXED_MSG: &[u8] = b"adversarial oracle message";

/// Split `data` into (selector, rest).
fn split(data: &[u8]) -> Option<(u8, &[u8])> {
    data.split_first().map(|(s, r)| (*s % 3, r))
}

// ---------------------------------------------------------------- ML-KEM ----

macro_rules! kem_oracles {
    ($refmod:path, $ps:expr, $decaps:ident, $encaps:ident, $dk:ident) => {
        /// Decapsulate attacker ciphertexts under a fixed key: turtl must return
        /// exactly the reference's shared secret (including the implicit-rejection
        /// value for invalid ciphertexts).
        fn $decaps(ct: &[u8]) {
            use $refmod as r;
            let turtl_ct = kem::Ciphertext::new(ct.to_vec(), $ps);
            let Ok(ct_arr) = <[u8; r::CT_LEN]>::try_from(ct) else {
                assert!(
                    turtl_ct.is_err(),
                    "turtl accepted a {}-byte ciphertext",
                    ct.len()
                );
                return;
            };
            let turtl_ct = turtl_ct.expect("turtl rejected a correctly sized ciphertext");

            let (_, ref_dk) = r::KG::keygen_from_seed(KEM_D, KEM_Z);
            let ref_ss = ref_dk
                .try_decaps(&r::CipherText::try_from_bytes(ct_arr).unwrap())
                .unwrap()
                .into_bytes();

            let kp = kem::KeyPair::from_seeds(&KEM_D, &KEM_Z, $ps).unwrap();
            let ss = kem::decapsulate(&kp.private_key(), &turtl_ct).expect("decaps errored");
            assert_eq!(
                ss.as_bytes(),
                &ref_ss,
                "decaps shared secret differs from reference"
            );
        }

        /// Attacker-chosen encapsulation key: turtl must accept exactly the keys
        /// the reference accepts, and encapsulate identically to them.
        fn $encaps(data: &[u8]) {
            use $refmod as r;
            if data.len() < 32 {
                return;
            }
            let (m, ek) = data.split_at(32);
            let m: [u8; 32] = m.try_into().unwrap();
            let turtl_pk = kem::PublicKey::new(ek.to_vec(), $ps);
            let Ok(ek_arr) = <[u8; r::EK_LEN]>::try_from(ek) else {
                assert!(turtl_pk.is_err(), "turtl accepted a {}-byte ek", ek.len());
                return;
            };
            let ref_ek = r::EncapsKey::try_from_bytes(ek_arr);
            assert_eq!(
                turtl_pk.is_ok(),
                ref_ek.is_ok(),
                "ek acceptance differs (turtl {:?})",
                turtl_pk.as_ref().err()
            );
            let (Ok(pk), Ok(ref_ek)) = (turtl_pk, ref_ek) else {
                return;
            };

            let (ref_ss, ref_ct) = ref_ek.encaps_from_seed(&m);
            let (ct, ss) = kem::encapsulate_deterministic(&pk, &m).expect("encaps errored");
            assert_eq!(
                ct.as_bytes(),
                &ref_ct.into_bytes()[..],
                "ciphertext differs"
            );
            assert_eq!(ss.as_bytes(), &ref_ss.into_bytes(), "shared secret differs");
        }

        /// Attacker-chosen decapsulation key: acceptance must match the reference,
        /// and an accepted key must decapsulate a fixed ciphertext identically.
        fn $dk(dk: &[u8]) {
            use $refmod as r;
            let turtl_sk = kem::PrivateKey::new(dk.to_vec(), $ps);
            let Ok(dk_arr) = <[u8; r::DK_LEN]>::try_from(dk) else {
                assert!(turtl_sk.is_err(), "turtl accepted a {}-byte dk", dk.len());
                return;
            };
            let ref_dk = r::DecapsKey::try_from_bytes(dk_arr);
            assert_eq!(
                turtl_sk.is_ok(),
                ref_dk.is_ok(),
                "dk acceptance differs (turtl {:?}, ref {:?})",
                turtl_sk.as_ref().err(),
                ref_dk.as_ref().err()
            );
            let (Ok(sk), Ok(ref_dk)) = (turtl_sk, ref_dk) else {
                return;
            };

            // Both implementations refuse to decapsulate with a dk_pke whose
            // coefficients are >= q (the reference errors in ByteDecode_12);
            // they must agree on that, and on the secret otherwise.
            let ct_bytes = [0x11u8; r::CT_LEN];
            let ref_ss = ref_dk
                .try_decaps(&r::CipherText::try_from_bytes(ct_bytes).unwrap())
                .map(|k| k.into_bytes());
            let ct = kem::Ciphertext::new(ct_bytes.to_vec(), $ps).unwrap();
            let ss = kem::decapsulate(&sk, &ct).map(|k| *k.as_bytes());
            match (ss, ref_ss) {
                (Ok(a), Ok(b)) => assert_eq!(a, b, "decaps under attacker dk differs"),
                (Err(_), Err(_)) => {}
                (a, b) => panic!("decaps outcome differs: turtl {a:?}, ref {b:?}"),
            }
        }
    };
}

kem_oracles!(
    fips203::ml_kem_512,
    kem::ParameterSet::MlKem512,
    kem_decaps_512,
    kem_encaps_512,
    kem_dk_512
);
kem_oracles!(
    fips203::ml_kem_768,
    kem::ParameterSet::MlKem768,
    kem_decaps_768,
    kem_encaps_768,
    kem_dk_768
);
kem_oracles!(
    fips203::ml_kem_1024,
    kem::ParameterSet::MlKem1024,
    kem_decaps_1024,
    kem_encaps_1024,
    kem_dk_1024
);

pub fn kem_decaps(data: &[u8]) {
    let Some((sel, rest)) = split(data) else {
        return;
    };
    [kem_decaps_512, kem_decaps_768, kem_decaps_1024][sel as usize](rest)
}

pub fn kem_encaps(data: &[u8]) {
    let Some((sel, rest)) = split(data) else {
        return;
    };
    [kem_encaps_512, kem_encaps_768, kem_encaps_1024][sel as usize](rest)
}

pub fn kem_dk(data: &[u8]) {
    let Some((sel, rest)) = split(data) else {
        return;
    };
    [kem_dk_512, kem_dk_768, kem_dk_1024][sel as usize](rest)
}

// ---------------------------------------------------------------- ML-DSA ----

/// Apply sparse `(position, xor)` edits to `base`.
fn apply_edits(base: &mut [u8], edits: &[u8]) {
    for e in edits.as_chunks::<3>().0 {
        let pos = u16::from_le_bytes([e[0], e[1]]) as usize % base.len();
        base[pos] ^= e[2];
    }
}

macro_rules! dsa_oracles {
    ($refmod:path, $ps:expr, $verify:ident, $pk:ident, $sk:ident) => {
        /// Verify attacker signatures (raw bytes, or sparse edits of a valid
        /// signature to reach deep decode paths): turtl's verdict must equal the
        /// reference's, and a well-sized signature must never produce `Err`.
        fn $verify(data: &[u8]) {
            use $refmod as r;
            let (Some(&mode), Some(&ctx_len)) = (data.first(), data.get(1)) else {
                return;
            };
            let rest = &data[2..];
            let ctx_len = (ctx_len as usize).min(rest.len());
            let (ctx, payload) = rest.split_at(ctx_len);

            let (ref_pk, ref_sk) = r::KG::keygen_from_seed(&DSA_XI);
            let kp = dsa::KeyPair::from_seed(&DSA_XI, $ps).unwrap();

            let sig_bytes: Vec<u8> = if mode & 1 == 0 {
                payload.to_vec()
            } else {
                // Start from a genuine signature over FIXED_MSG with this context.
                let mut sig = ref_sk
                    .try_sign_with_seed(&[0u8; 32], FIXED_MSG, ctx)
                    .map(|s| s.to_vec())
                    .unwrap_or_else(|_| vec![0u8; r::SIG_LEN]);
                apply_edits(&mut sig, payload);
                sig
            };
            let msg: &[u8] = if mode & 1 == 0 { b"" } else { FIXED_MSG };

            let turtl_sig = dsa::Signature::new(sig_bytes.clone(), $ps);
            let Ok(sig_arr) = <[u8; r::SIG_LEN]>::try_from(&sig_bytes[..]) else {
                assert!(
                    turtl_sig.is_err(),
                    "turtl accepted a {}-byte signature",
                    sig_bytes.len()
                );
                return;
            };
            let turtl_sig = turtl_sig.expect("turtl rejected a correctly sized signature");

            let ref_ok = ref_pk.verify(msg, &sig_arr, ctx);
            match dsa::verify(&kp.public_key(), msg, &turtl_sig, ctx) {
                Ok(ok) => assert_eq!(ok, ref_ok, "verify verdict differs from reference"),
                Err(turtl::Error::ContextTooLong) => assert!(ctx.len() > 255),
                Err(e) => panic!("verify returned Err({e:?}) for a well-sized signature"),
            }
        }

        /// Attacker-chosen public key against a genuine signature.
        fn $pk(pk: &[u8]) {
            use $refmod as r;
            let turtl_pk = dsa::PublicKey::new(pk.to_vec(), $ps);
            let Ok(pk_arr) = <[u8; r::PK_LEN]>::try_from(pk) else {
                assert!(
                    turtl_pk.is_err(),
                    "turtl accepted a {}-byte public key",
                    pk.len()
                );
                return;
            };
            let ref_pk = r::PublicKey::try_from_bytes(pk_arr);
            assert_eq!(
                turtl_pk.is_ok(),
                ref_pk.is_ok(),
                "public key acceptance differs"
            );
            let (Ok(turtl_pk), Ok(ref_pk)) = (turtl_pk, ref_pk) else {
                return;
            };

            let (_, ref_sk) = r::KG::keygen_from_seed(&DSA_XI);
            let sig = ref_sk
                .try_sign_with_seed(&[0u8; 32], FIXED_MSG, b"")
                .unwrap();
            let turtl_sig = dsa::Signature::new(sig.to_vec(), $ps).unwrap();
            let ref_ok = ref_pk.verify(FIXED_MSG, &sig, b"");
            let ok = dsa::verify(&turtl_pk, FIXED_MSG, &turtl_sig, b"")
                .expect("verify errored under an accepted public key");
            assert_eq!(ok, ref_ok, "verify verdict under attacker pk differs");
        }

        /// Attacker-chosen private key: acceptance must match the reference, and
        /// an accepted key must sign deterministically to the same bytes.
        fn $sk(sk: &[u8]) {
            use $refmod as r;
            let turtl_sk = dsa::PrivateKey::new(sk.to_vec(), $ps);
            let Ok(sk_arr) = <[u8; r::SK_LEN]>::try_from(sk) else {
                assert!(
                    turtl_sk.is_err(),
                    "turtl accepted a {}-byte private key",
                    sk.len()
                );
                return;
            };
            let ref_sk = r::PrivateKey::try_from_bytes(sk_arr);
            let turtl_sig = turtl_sk
                .as_ref()
                .ok()
                .map(|k| dsa::sign(k, FIXED_MSG, b"", dsa::SigningMode::Deterministic));
            match (ref_sk, turtl_sig) {
                (Ok(ref_sk), Some(Ok(sig))) => {
                    let ref_sig = ref_sk
                        .try_sign_with_seed(&[0u8; 32], FIXED_MSG, b"")
                        .unwrap();
                    assert_eq!(
                        sig.as_bytes(),
                        &ref_sig[..],
                        "signature under attacker sk differs"
                    );
                }
                // turtl deliberately rejects keys with s1/s2 coefficients outside
                // [-eta, eta] at construction; the reference signs with them.
                (Ok(_), None) => assert!(matches!(turtl_sk, Err(turtl::Error::InvalidPrivateKey))),
                (Ok(_), other) => panic!("turtl accepted this sk but signing gave {other:?}"),
                (Err(_), Some(Ok(_))) => {
                    panic!("turtl signed with a private key the reference rejects")
                }
                (Err(_), _) => {}
            }
        }
    };
}

dsa_oracles!(
    fips204::ml_dsa_44,
    dsa::ParameterSet::MlDsa44,
    dsa_verify_44,
    dsa_pk_44,
    dsa_sk_44
);
dsa_oracles!(
    fips204::ml_dsa_65,
    dsa::ParameterSet::MlDsa65,
    dsa_verify_65,
    dsa_pk_65,
    dsa_sk_65
);
dsa_oracles!(
    fips204::ml_dsa_87,
    dsa::ParameterSet::MlDsa87,
    dsa_verify_87,
    dsa_pk_87,
    dsa_sk_87
);

pub fn dsa_verify(data: &[u8]) {
    let Some((sel, rest)) = split(data) else {
        return;
    };
    [dsa_verify_44, dsa_verify_65, dsa_verify_87][sel as usize](rest)
}

pub fn dsa_pk(data: &[u8]) {
    let Some((sel, rest)) = split(data) else {
        return;
    };
    [dsa_pk_44, dsa_pk_65, dsa_pk_87][sel as usize](rest)
}

pub fn dsa_sk(data: &[u8]) {
    let Some((sel, rest)) = split(data) else {
        return;
    };
    [dsa_sk_44, dsa_sk_65, dsa_sk_87][sel as usize](rest)
}
