//! Exercises the REAL production code path (no #[cfg(test)] stubs).

use turtl::kem::{self, ParameterSet as KemParams};
use turtl::dsa::{self, ParameterSet as DsaParams, SigningMode};

fn kem_roundtrip(p: KemParams) -> bool {
    let (pk, sk) = match kem::key_gen(p) {
        Ok(v) => v,
        Err(e) => { println!("  keygen error: {:?}", e); return false; }
    };
    let (ct, ss1) = match kem::encapsulate(&pk) {
        Ok(v) => v,
        Err(e) => { println!("  encaps error: {:?}", e); return false; }
    };
    let ss2 = match kem::decapsulate(&sk, &ct) {
        Ok(v) => v,
        Err(e) => { println!("  decaps error: {:?}", e); return false; }
    };
    let ok = ss1.as_bytes() == ss2.as_bytes();
    println!("  ss match: {}", ok);
    ok
}

fn dsa_roundtrip(p: DsaParams) -> bool {
    let (pk, sk) = match dsa::key_gen(p) {
        Ok(v) => v,
        Err(e) => { println!("  keygen error: {:?}", e); return false; }
    };
    let msg = b"turtl real-path validation message";
    let sig = match dsa::sign(&sk, msg, b"", SigningMode::Deterministic) {
        Ok(v) => v,
        Err(e) => { println!("  sign error: {:?}", e); return false; }
    };
    let good = match dsa::verify(&pk, msg, &sig, b"") {
        Ok(v) => v,
        Err(e) => { println!("  verify error: {:?}", e); return false; }
    };
    let bad = dsa::verify(&pk, b"tampered", &sig, b"").unwrap_or(false);
    println!("  verify(good)={} verify(tampered)={}", good, bad);
    good && !bad
}

fn main() {
    println!("== ML-KEM ==");
    for p in [KemParams::MlKem512, KemParams::MlKem768, KemParams::MlKem1024] {
        println!("{:?}", p);
        println!("  PASS={}", kem_roundtrip(p));
    }
    println!("== ML-DSA ==");
    for p in [DsaParams::MlDsa44, DsaParams::MlDsa65, DsaParams::MlDsa87] {
        println!("{:?}", p);
        println!("  PASS={}", dsa_roundtrip(p));
    }
}
