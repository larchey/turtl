//! Does turtl's keygen-from-seed reproduce the FIPS reference byte-for-byte?

use fips203::traits::{KeyGen as _, SerDes as _};
use fips204::traits::{KeyGen as _, SerDes as _};

fn main() {
    // ---- ML-DSA-44: turtl from_seed vs fips204 keygen_from_seed(xi) ----
    let xi = [0x11u8; 32];
    let (rpk, _rsk) = fips204::ml_dsa_44::KG::keygen_from_seed(&xi);
    let ref_pk = rpk.into_bytes().to_vec();

    let kp = turtl::dsa::KeyPair::from_seed(&xi, turtl::dsa::ParameterSet::MlDsa44).unwrap();
    let turtl_pk = kp.public_key().as_bytes().to_vec();

    println!(
        "ML-DSA-44 keygen-from-seed public key matches reference: {}",
        ref_pk == turtl_pk
    );

    // ---- ML-KEM-512: turtl from_seed vs fips203 keygen_from_seed(d, z) ----
    let d = [0x22u8; 32];
    let z = [0x33u8; 32];
    let (rek, _rdk) = fips203::ml_kem_512::KG::keygen_from_seed(d, z);
    let ref_ek = rek.into_bytes().to_vec();

    // turtl takes a single 32-byte seed; try d as that seed.
    let kkp = turtl::kem::KeyPair::from_seed(&d, turtl::kem::ParameterSet::MlKem512).unwrap();
    let turtl_ek = kkp.public_key().as_bytes().to_vec();

    println!(
        "ML-KEM-512 keygen-from-seed public key matches reference: {}",
        ref_ek == turtl_ek
    );
}
