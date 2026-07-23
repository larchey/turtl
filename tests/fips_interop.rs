//! FIPS 203/204 interoperability regression tests.
//!
//! These cross-validate turtl against the vetted reference implementations
//! (fips203 / fips204) in both directions, for every parameter set. A
//! compliant implementation is byte-compatible with any other, so these are
//! the ground-truth tests for turtl's FIPS conformance.

use fips203::traits::{Decaps as _, Encaps as _, KeyGen as _, SerDes as _};
use fips204::traits::{SerDes as _, Signer as _, Verifier as _};

use turtl::dsa::{self, SigningMode};
use turtl::kem;

/// ref encaps -> turtl decaps, and turtl encaps -> ref decaps.
macro_rules! kem_interop {
    ($name:ident, $refmod:path, $turtl:expr, $pk:expr, $ct:expr) => {
        #[test]
        fn $name() {
            use $refmod as r;

            // ref encaps to turtl's public key -> turtl decapsulates
            let (pk, sk) = kem::key_gen($turtl).unwrap();
            let pk_arr: [u8; $pk] = pk.as_bytes().try_into().unwrap();
            let ek = r::EncapsKey::try_from_bytes(pk_arr).expect("ref rejected turtl ek");
            let (ref_ss, ref_ct) = ek.try_encaps().unwrap();
            let ct = kem::Ciphertext::new(ref_ct.into_bytes().to_vec(), $turtl).unwrap();
            let turtl_ss = kem::decapsulate(&sk, &ct).unwrap();
            assert_eq!(
                turtl_ss.as_bytes(),
                &ref_ss.into_bytes(),
                "ref->turtl ss mismatch"
            );

            // turtl encaps to ref's public key -> ref decapsulates
            let (ek2, dk2) = r::KG::try_keygen().unwrap();
            let pk2 = kem::PublicKey::new(ek2.into_bytes().to_vec(), $turtl).unwrap();
            let (ct2, turtl_ss2) = kem::encapsulate(&pk2).unwrap();
            let ct2_arr: [u8; $ct] = ct2.as_bytes().try_into().unwrap();
            let ref_ct2 = r::CipherText::try_from_bytes(ct2_arr).unwrap();
            let ref_ss2 = dk2.try_decaps(&ref_ct2).unwrap();
            assert_eq!(
                turtl_ss2.as_bytes(),
                &ref_ss2.into_bytes(),
                "turtl->ref ss mismatch"
            );
        }
    };
}

kem_interop!(
    kem_512,
    fips203::ml_kem_512,
    kem::ParameterSet::MlKem512,
    800,
    768
);
kem_interop!(
    kem_768,
    fips203::ml_kem_768,
    kem::ParameterSet::MlKem768,
    1184,
    1088
);
kem_interop!(
    kem_1024,
    fips203::ml_kem_1024,
    kem::ParameterSet::MlKem1024,
    1568,
    1568
);

/// turtl sign -> ref verify, and ref sign -> turtl verify.
macro_rules! dsa_interop {
    ($name:ident, $refmod:path, $turtl:expr, $pk:expr, $sig:expr) => {
        #[test]
        fn $name() {
            use $refmod as r;
            let msg = b"turtl <-> reference interop message";

            // turtl signs -> reference verifies
            let (pk, sk) = dsa::key_gen($turtl).unwrap();
            let sig = dsa::sign(&sk, msg, b"", SigningMode::Deterministic).unwrap();
            let pk_arr: [u8; $pk] = pk.as_bytes().try_into().unwrap();
            let ref_pk = r::PublicKey::try_from_bytes(pk_arr).expect("ref rejected turtl pk");
            let sig_arr: [u8; $sig] = sig.as_bytes().try_into().unwrap();
            assert!(
                ref_pk.verify(msg, &sig_arr, b""),
                "ref failed to verify turtl signature"
            );

            // reference signs -> turtl verifies
            let (rpk, rsk) = r::try_keygen().unwrap();
            let rsig = rsk.try_sign(msg, b"").unwrap();
            let turtl_pk = dsa::PublicKey::new(rpk.into_bytes().to_vec(), $turtl).unwrap();
            let turtl_sig = dsa::Signature::new(rsig.to_vec(), $turtl).unwrap();
            assert!(
                dsa::verify(&turtl_pk, msg, &turtl_sig, b"").unwrap(),
                "turtl failed to verify reference signature"
            );
        }
    };
}

dsa_interop!(
    dsa_44,
    fips204::ml_dsa_44,
    dsa::ParameterSet::MlDsa44,
    1312,
    2420
);
dsa_interop!(
    dsa_65,
    fips204::ml_dsa_65,
    dsa::ParameterSet::MlDsa65,
    1952,
    3309
);
dsa_interop!(
    dsa_87,
    fips204::ml_dsa_87,
    dsa::ParameterSet::MlDsa87,
    2592,
    4627
);

// ---------------------------------------------------------------------------
// Beyond one-shot conformance: robustness and properties that the per-set
// interop macros above do not cover.
// ---------------------------------------------------------------------------

/// ML-KEM implicit rejection: decapsulating a tampered ciphertext must succeed
/// (no error), return a shared secret that differs from the sender's, and be
/// deterministic (same tampered input -> same output).
#[test]
fn kem_implicit_rejection() {
    for p in [
        kem::ParameterSet::MlKem512,
        kem::ParameterSet::MlKem768,
        kem::ParameterSet::MlKem1024,
    ] {
        let (pk, sk) = kem::key_gen(p).unwrap();
        let (ct, sender_ss) = kem::encapsulate(&pk).unwrap();

        let mut bad = ct.as_bytes().to_vec();
        bad[0] ^= 0xFF;
        let bad_ct = kem::Ciphertext::new(bad, p).unwrap();

        let ss1 = kem::decapsulate(&sk, &bad_ct).expect("implicit rejection must not error");
        let ss2 = kem::decapsulate(&sk, &bad_ct).expect("implicit rejection must not error");

        assert_ne!(
            ss1.as_bytes(),
            sender_ss.as_bytes(),
            "tampered ciphertext must not recover the sender's secret"
        );
        assert_eq!(
            ss1.as_bytes(),
            ss2.as_bytes(),
            "implicit rejection must be deterministic"
        );
    }
}

/// Many independent key/sign/verify and encaps/decaps cycles, to catch
/// probabilistic bugs (e.g. in the ML-DSA rejection-sampling loop) that a
/// single run can miss.
#[test]
fn many_iteration_roundtrips() {
    for _ in 0..64 {
        let (pk, sk) = kem::key_gen(kem::ParameterSet::MlKem768).unwrap();
        let (ct, ss1) = kem::encapsulate(&pk).unwrap();
        let ss2 = kem::decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());

        let (dpk, dsk) = dsa::key_gen(dsa::ParameterSet::MlDsa65).unwrap();
        let msg = b"iteration message";
        let sig = dsa::sign(&dsk, msg, b"ctx", SigningMode::Hedged).unwrap();
        assert!(dsa::verify(&dpk, msg, &sig, b"ctx").unwrap());
        assert!(!dsa::verify(&dpk, b"other", &sig, b"ctx").unwrap());
    }
}

/// Pre-hash signing (HashML-DSA) interoperates with the reference on the
/// shared SHAKE128 pre-hash, in both directions.
#[test]
fn dsa_prehash_interop_shake128() {
    use fips204::ml_dsa_44;
    use fips204::traits::{SerDes as _, Signer as _, Verifier as _};
    use fips204::Ph;
    use turtl::dsa::HashFunction;

    let msg = b"prehash interop message";

    // turtl signs (pre-hash) -> reference verifies
    let (pk, sk) = dsa::key_gen(dsa::ParameterSet::MlDsa44).unwrap();
    let sig = dsa::hash_sign(
        &sk,
        msg,
        b"",
        HashFunction::SHAKE128,
        SigningMode::Deterministic,
    )
    .unwrap();
    let ref_pk = ml_dsa_44::PublicKey::try_from_bytes(pk.as_bytes().try_into().unwrap()).unwrap();
    let sig_arr: [u8; 2420] = sig.as_bytes().try_into().unwrap();
    assert!(
        ref_pk.hash_verify(msg, &sig_arr, b"", &Ph::SHAKE128),
        "reference must verify turtl's pre-hash signature"
    );

    // reference signs (pre-hash) -> turtl verifies
    let (rpk, rsk) = ml_dsa_44::try_keygen().unwrap();
    let rsig = rsk.try_hash_sign(msg, b"", &Ph::SHAKE128).unwrap();
    let turtl_pk =
        dsa::PublicKey::new(rpk.into_bytes().to_vec(), dsa::ParameterSet::MlDsa44).unwrap();
    let turtl_sig = dsa::Signature::new(rsig.to_vec(), dsa::ParameterSet::MlDsa44).unwrap();
    assert!(
        dsa::hash_verify(&turtl_pk, msg, &turtl_sig, b"", HashFunction::SHAKE128).unwrap(),
        "turtl must verify the reference's pre-hash signature"
    );
}
