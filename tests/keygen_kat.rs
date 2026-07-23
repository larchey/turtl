//! Deterministic keygen conformance: turtl's keygen-from-seed must reproduce
//! the FIPS reference implementations byte-for-byte (the property NIST's
//! Known-Answer-Test vectors check).

use fips203::traits::{KeyGen as _, SerDes as _};
use fips204::traits::{KeyGen as _, SerDes as _};

macro_rules! kem_keygen_kat {
    ($name:ident, $refmod:path, $turtl:expr) => {
        #[test]
        fn $name() {
            use $refmod as r;
            let d = [0x42u8; 32];
            let z = [0x17u8; 32];
            let (ek, dk) = r::KG::keygen_from_seed(d, z);
            let kp = turtl::kem::KeyPair::from_seeds(&d, &z, $turtl).unwrap();
            assert_eq!(
                kp.public_key().as_bytes(),
                ek.into_bytes().as_slice(),
                "public key mismatch"
            );
            assert_eq!(
                kp.private_key().as_bytes(),
                dk.into_bytes().as_slice(),
                "private key mismatch"
            );
        }
    };
}

kem_keygen_kat!(
    kem_512_keygen,
    fips203::ml_kem_512,
    turtl::kem::ParameterSet::MlKem512
);
kem_keygen_kat!(
    kem_768_keygen,
    fips203::ml_kem_768,
    turtl::kem::ParameterSet::MlKem768
);
kem_keygen_kat!(
    kem_1024_keygen,
    fips203::ml_kem_1024,
    turtl::kem::ParameterSet::MlKem1024
);

macro_rules! dsa_keygen_kat {
    ($name:ident, $refmod:path, $turtl:expr) => {
        #[test]
        fn $name() {
            use $refmod as r;
            let xi = [0x99u8; 32];
            let (pk, sk) = r::KG::keygen_from_seed(&xi);
            let kp = turtl::dsa::KeyPair::from_seed(&xi, $turtl).unwrap();
            assert_eq!(
                kp.public_key().as_bytes(),
                pk.into_bytes().as_slice(),
                "public key mismatch"
            );
            assert_eq!(
                kp.private_key().as_bytes(),
                sk.into_bytes().as_slice(),
                "private key mismatch"
            );
        }
    };
}

dsa_keygen_kat!(
    dsa_44_keygen,
    fips204::ml_dsa_44,
    turtl::dsa::ParameterSet::MlDsa44
);
dsa_keygen_kat!(
    dsa_65_keygen,
    fips204::ml_dsa_65,
    turtl::dsa::ParameterSet::MlDsa65
);
dsa_keygen_kat!(
    dsa_87_keygen,
    fips204::ml_dsa_87,
    turtl::dsa::ParameterSet::MlDsa87
);
