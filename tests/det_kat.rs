//! Deterministic signing and encapsulation KATs: turtl must reproduce the
//! FIPS reference byte-for-byte when the randomness is fixed. Together with
//! keygen_kat this covers the full deterministic surface (keygen, encaps,
//! sign) against known answers.

use fips203::traits::{Encaps as _, KeyGen as _, SerDes as _};
use fips204::traits::{KeyGen as _, Signer as _};

use turtl::dsa::{self, SigningMode};
use turtl::kem;

/// turtl encapsulate_deterministic(m) must equal the reference's
/// encaps_from_seed(m) — same ciphertext and shared secret — on the same key.
macro_rules! kem_encaps_kat {
    ($name:ident, $refmod:path, $turtl:expr) => {
        #[test]
        fn $name() {
            use $refmod as r;
            let (ek, _dk) = r::KG::keygen_from_seed([0x42u8; 32], [0x17u8; 32]);
            let m = [0x5au8; 32];
            let (ref_ss, ref_ct) = ek.encaps_from_seed(&m);
            let ek_bytes = ek.into_bytes();

            let pk = kem::PublicKey::new(ek_bytes.to_vec(), $turtl).unwrap();
            let (ct, ss) = kem::encapsulate_deterministic(&pk, &m).unwrap();

            assert_eq!(
                ct.as_bytes(),
                ref_ct.into_bytes().as_slice(),
                "ciphertext mismatch"
            );
            assert_eq!(
                ss.as_bytes(),
                &ref_ss.into_bytes(),
                "shared secret mismatch"
            );
        }
    };
}

kem_encaps_kat!(
    kem_512_encaps,
    fips203::ml_kem_512,
    kem::ParameterSet::MlKem512
);
kem_encaps_kat!(
    kem_768_encaps,
    fips203::ml_kem_768,
    kem::ParameterSet::MlKem768
);
kem_encaps_kat!(
    kem_1024_encaps,
    fips203::ml_kem_1024,
    kem::ParameterSet::MlKem1024
);

/// turtl's deterministic signature (rnd = 0) must equal the reference's
/// deterministic signature on the same seed-derived key.
macro_rules! dsa_sign_kat {
    ($name:ident, $refmod:path, $turtl:expr) => {
        #[test]
        fn $name() {
            use $refmod as r;
            let xi = [0x99u8; 32];
            let msg = b"deterministic signature KAT";
            let ctx = b"ctx";

            let (_pk, sk) = r::KG::keygen_from_seed(&xi);
            let ref_sig = sk.try_sign_with_seed(&[0u8; 32], msg, ctx).unwrap();

            let kp = dsa::KeyPair::from_seed(&xi, $turtl).unwrap();
            let sig = dsa::sign(&kp.private_key(), msg, ctx, SigningMode::Deterministic).unwrap();

            assert_eq!(sig.as_bytes(), ref_sig.as_slice(), "signature mismatch");
        }
    };
}

dsa_sign_kat!(dsa_44_sign, fips204::ml_dsa_44, dsa::ParameterSet::MlDsa44);
dsa_sign_kat!(dsa_65_sign, fips204::ml_dsa_65, dsa::ParameterSet::MlDsa65);
dsa_sign_kat!(dsa_87_sign, fips204::ml_dsa_87, dsa::ParameterSet::MlDsa87);
