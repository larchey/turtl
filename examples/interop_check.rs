//! Interoperability cross-check between turtl and the vetted FIPS reference
//! implementations (fips203 / fips204). This is the objective test of whether
//! turtl is FIPS 203/204 compliant: a compliant implementation's public keys,
//! ciphertexts, and signatures are byte-compatible with any other compliant one.

use fips203::ml_kem_512;
use fips203::traits::{Decaps as _, Encaps as _, KeyGen as _, SerDes as _};

use fips204::ml_dsa_44;
use fips204::traits::{SerDes as _, Signer as _, Verifier as _};

use turtl::dsa::{self, ParameterSet as DsaParams, SigningMode};
use turtl::kem::{self, ParameterSet as KemParams};

fn line(name: &str, ok: bool) {
    println!("  [{}] {}", if ok { "PASS" } else { "FAIL" }, name);
}

/// turtl generates a KEM keypair; the reference encapsulates to turtl's public
/// key; turtl decapsulates. If compliant, the shared secrets match.
fn kem_ref_encaps_turtl_decaps() -> bool {
    let (pk, sk) = kem::key_gen(KemParams::MlKem512).unwrap();
    let pk_arr: [u8; 800] = match pk.as_bytes().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let ek = match ml_kem_512::EncapsKey::try_from_bytes(pk_arr) {
        Ok(ek) => ek,
        Err(e) => {
            println!("    reference rejected turtl public key: {e}");
            return false;
        }
    };
    let (ref_ss, ref_ct) = ek.try_encaps().unwrap();
    let ct = kem::Ciphertext::new(ref_ct.into_bytes().to_vec(), KemParams::MlKem512).unwrap();
    let turtl_ss = kem::decapsulate(&sk, &ct).unwrap();
    turtl_ss.as_bytes() == &ref_ss.into_bytes()
}

/// The reference generates a KEM keypair; turtl encapsulates to it; the
/// reference decapsulates. If compliant, the shared secrets match.
fn turtl_encaps_ref_decaps() -> bool {
    let (ek, dk) = ml_kem_512::KG::try_keygen().unwrap();
    let pk = match kem::PublicKey::new(ek.into_bytes().to_vec(), KemParams::MlKem512) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let (ct, turtl_ss) = match kem::encapsulate(&pk) {
        Ok(v) => v,
        Err(e) => {
            println!("    turtl could not encapsulate to reference key: {e:?}");
            return false;
        }
    };
    let ct_arr: [u8; 768] = match ct.as_bytes().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let ref_ct = match ml_kem_512::CipherText::try_from_bytes(ct_arr) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let ref_ss = dk.try_decaps(&ref_ct).unwrap();
    turtl_ss.as_bytes() == &ref_ss.into_bytes()
}

/// turtl signs; the reference verifies with turtl's public key.
fn turtl_sign_ref_verify() -> bool {
    let (pk, sk) = dsa::key_gen(DsaParams::MlDsa44).unwrap();
    let msg = b"interop test message";
    let sig = dsa::sign(&sk, msg, b"", SigningMode::Deterministic).unwrap();

    let pk_arr: [u8; 1312] = match pk.as_bytes().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let ref_pk = match ml_dsa_44::PublicKey::try_from_bytes(pk_arr) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig_arr: [u8; 2420] = match sig.as_bytes().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    ref_pk.verify(msg, &sig_arr, b"")
}

/// The reference signs; turtl verifies with the reference public key.
fn ref_sign_turtl_verify() -> bool {
    let (pk, sk) = ml_dsa_44::try_keygen().unwrap();
    let msg = b"interop test message";
    let sig = sk.try_sign(msg, b"").unwrap();

    let turtl_pk = match dsa::PublicKey::new(pk.into_bytes().to_vec(), DsaParams::MlDsa44) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let turtl_sig = match dsa::Signature::new(sig.to_vec(), DsaParams::MlDsa44) {
        Ok(s) => s,
        Err(_) => return false,
    };
    dsa::verify(&turtl_pk, msg, &turtl_sig, b"").unwrap_or(false)
}

fn main() {
    println!("== ML-KEM-512 interop vs fips203 ==");
    line("ref encaps -> turtl decaps", kem_ref_encaps_turtl_decaps());
    line("turtl encaps -> ref decaps", turtl_encaps_ref_decaps());

    println!("== ML-DSA-44 interop vs fips204 ==");
    line("turtl sign -> ref verify", turtl_sign_ref_verify());
    line("ref sign -> turtl verify", ref_sign_turtl_verify());
}
