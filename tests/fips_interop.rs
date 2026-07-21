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
            assert_eq!(turtl_ss.as_bytes(), &ref_ss.into_bytes(), "ref->turtl ss mismatch");

            // turtl encaps to ref's public key -> ref decapsulates
            let (ek2, dk2) = r::KG::try_keygen().unwrap();
            let pk2 = kem::PublicKey::new(ek2.into_bytes().to_vec(), $turtl).unwrap();
            let (ct2, turtl_ss2) = kem::encapsulate(&pk2).unwrap();
            let ct2_arr: [u8; $ct] = ct2.as_bytes().try_into().unwrap();
            let ref_ct2 = r::CipherText::try_from_bytes(ct2_arr).unwrap();
            let ref_ss2 = dk2.try_decaps(&ref_ct2).unwrap();
            assert_eq!(turtl_ss2.as_bytes(), &ref_ss2.into_bytes(), "turtl->ref ss mismatch");
        }
    };
}

kem_interop!(kem_512, fips203::ml_kem_512, kem::ParameterSet::MlKem512, 800, 768);
kem_interop!(kem_768, fips203::ml_kem_768, kem::ParameterSet::MlKem768, 1184, 1088);
kem_interop!(kem_1024, fips203::ml_kem_1024, kem::ParameterSet::MlKem1024, 1568, 1568);

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
            assert!(ref_pk.verify(msg, &sig_arr, b""), "ref failed to verify turtl signature");

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

dsa_interop!(dsa_44, fips204::ml_dsa_44, dsa::ParameterSet::MlDsa44, 1312, 2420);
dsa_interop!(dsa_65, fips204::ml_dsa_65, dsa::ParameterSet::MlDsa65, 1952, 3309);
dsa_interop!(dsa_87, fips204::ml_dsa_87, dsa::ParameterSet::MlDsa87, 2592, 4627);
