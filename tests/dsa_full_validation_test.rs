//! Comprehensive ML-DSA validation across all parameter sets.
//!
//! Tests all ML-DSA parameter sets (44, 65, 87) for:
//! - Keypair generation produces non-empty, distinct keys
//! - Sign produces a non-empty signature
//! - Valid signature verifies correctly
//! - Tampered message fails verification
//! - Tampered signature fails verification
//! - Wrong key fails verification
//! - Empty payload round-trip
//! - Large payload round-trip
//! - Binary payload round-trip
//! - Repeated signing produces verifiable signatures
//! - Deterministic mode produces identical signatures
//! - Hedged mode produces different signatures
//! - Context string affects verification
//! - Multiple sequential sign/verify cycles

use turtl::dsa::{self, ParameterSet, SigningMode};

fn test_full_validation(param: ParameterSet, name: &str) {
    eprintln!("\n=== Testing {} ===", name);

    // Test 1: Keypair generation produces non-empty, distinct keys
    let (pk, sk) = dsa::key_gen(param).expect("keygen failed");
    assert!(!pk.as_bytes().is_empty(), "Public key is empty");
    assert!(!sk.as_bytes().is_empty(), "Private key is empty");
    assert_ne!(
        pk.as_bytes(),
        sk.as_bytes(),
        "Public and private keys are identical"
    );
    eprintln!(
        "[PASS] Keypair generation: pk={}B sk={}B",
        pk.as_bytes().len(),
        sk.as_bytes().len()
    );

    // Test 2: Sign produces a non-empty signature
    let msg = b"PULSE telemetry test payload";
    let sig = dsa::sign(&sk, msg, b"", SigningMode::Hedged).expect("sign failed");
    assert!(!sig.as_bytes().is_empty(), "Signature is empty");
    eprintln!("[PASS] Signing: sig={}B", sig.as_bytes().len());

    // Test 3: Valid signature verifies correctly
    let result = dsa::verify(&pk, msg, &sig, b"").expect("verify failed");
    assert!(result, "Valid signature failed verification");
    eprintln!("[PASS] Verification of valid signature");

    // Test 4: Tampered message fails verification
    let tampered_msg = b"PULSE telemetry test payload TAMPERED";
    let result = dsa::verify(&pk, tampered_msg, &sig, b"").expect("verify failed");
    assert!(
        !result,
        "Tampered message incorrectly verified — CRITICAL FAILURE"
    );
    eprintln!("[PASS] Tampered message rejected");

    // Test 5: Tampered signature fails verification
    let mut tampered_sig_bytes = sig.as_bytes().to_vec();
    // Flip bits in the z portion (after c_tilde)
    let flip_pos = param.lambda() / 4 + 10;
    if flip_pos < tampered_sig_bytes.len() {
        tampered_sig_bytes[flip_pos] ^= 0xFF;
    }
    let tampered_sig = dsa::Signature::new(tampered_sig_bytes, param);
    match tampered_sig {
        Ok(ts) => {
            let result = dsa::verify(&pk, msg, &ts, b"");
            match result {
                Ok(true) => panic!("Tampered signature incorrectly verified — CRITICAL FAILURE"),
                Ok(false) => eprintln!("[PASS] Tampered signature rejected"),
                Err(_) => eprintln!("[PASS] Tampered signature rejected (decode error)"),
            }
        }
        Err(_) => eprintln!("[PASS] Tampered signature rejected (invalid format)"),
    }

    // Test 6: Wrong key fails verification
    let (pk2, _sk2) = dsa::key_gen(param).expect("keygen2 failed");
    let result = dsa::verify(&pk2, msg, &sig, b"").expect("verify failed");
    assert!(
        !result,
        "Wrong public key incorrectly verified — CRITICAL FAILURE"
    );
    eprintln!("[PASS] Wrong key rejected");

    // Test 7: Empty payload round-trip
    let empty_msg: &[u8] = b"";
    let empty_sig = dsa::sign(&sk, empty_msg, b"", SigningMode::Hedged).expect("sign empty failed");
    let result = dsa::verify(&pk, empty_msg, &empty_sig, b"").expect("verify empty failed");
    assert!(result, "Empty payload failed round-trip");
    eprintln!("[PASS] Empty payload round-trip");

    // Test 8: Large payload round-trip (simulate max telemetry packet)
    let large_msg = vec![0x58u8; 65536]; // 64KB
    let large_sig =
        dsa::sign(&sk, &large_msg, b"", SigningMode::Hedged).expect("sign large failed");
    let result = dsa::verify(&pk, &large_msg, &large_sig, b"").expect("verify large failed");
    assert!(result, "Large payload failed round-trip");
    eprintln!("[PASS] Large payload round-trip (64KB)");

    // Test 9: Binary payload (compressed data will be binary)
    let binary_msg: Vec<u8> = (0..1024).map(|i| (i * 37 + 13) as u8).collect();
    let binary_sig =
        dsa::sign(&sk, &binary_msg, b"", SigningMode::Hedged).expect("sign binary failed");
    let result = dsa::verify(&pk, &binary_msg, &binary_sig, b"").expect("verify binary failed");
    assert!(result, "Binary payload failed round-trip");
    eprintln!("[PASS] Binary payload round-trip (1KB)");

    // Test 10: Repeated signing produces verifiable signatures
    let sig_a = dsa::sign(&sk, msg, b"", SigningMode::Hedged).expect("sign a failed");
    let sig_b = dsa::sign(&sk, msg, b"", SigningMode::Hedged).expect("sign b failed");
    assert!(
        dsa::verify(&pk, msg, &sig_a, b"").expect("verify a"),
        "Repeated sign A failed verify"
    );
    assert!(
        dsa::verify(&pk, msg, &sig_b, b"").expect("verify b"),
        "Repeated sign B failed verify"
    );
    eprintln!("[PASS] Repeated signing produces verifiable signatures");

    // Test 11: Deterministic mode produces identical signatures
    let det_sig1 = dsa::sign(&sk, msg, b"", SigningMode::Deterministic).expect("det sign 1 failed");
    let det_sig2 = dsa::sign(&sk, msg, b"", SigningMode::Deterministic).expect("det sign 2 failed");
    assert_eq!(
        det_sig1.as_bytes(),
        det_sig2.as_bytes(),
        "Deterministic signatures differ"
    );
    assert!(
        dsa::verify(&pk, msg, &det_sig1, b"").expect("det verify"),
        "Deterministic sig failed verify"
    );
    eprintln!("[PASS] Deterministic signing is consistent");

    // Test 12: Hedged mode produces different signatures (with high probability)
    let hedge_sig1 = dsa::sign(&sk, msg, b"", SigningMode::Hedged).expect("hedge sign 1 failed");
    let hedge_sig2 = dsa::sign(&sk, msg, b"", SigningMode::Hedged).expect("hedge sign 2 failed");
    // They might rarely be equal, but both must verify
    assert!(
        dsa::verify(&pk, msg, &hedge_sig1, b"").expect("hedge verify 1"),
        "Hedged sig 1 failed"
    );
    assert!(
        dsa::verify(&pk, msg, &hedge_sig2, b"").expect("hedge verify 2"),
        "Hedged sig 2 failed"
    );
    eprintln!(
        "[PASS] Hedged mode: both signatures verify (different={}) ",
        hedge_sig1.as_bytes() != hedge_sig2.as_bytes()
    );

    // Test 13: Context string affects verification
    let ctx_sig =
        dsa::sign(&sk, msg, b"PULSE-context", SigningMode::Hedged).expect("ctx sign failed");
    let result_right = dsa::verify(&pk, msg, &ctx_sig, b"PULSE-context").expect("ctx verify right");
    assert!(result_right, "Correct context should verify");
    let result_wrong = dsa::verify(&pk, msg, &ctx_sig, b"wrong-context").expect("ctx verify wrong");
    assert!(!result_wrong, "Wrong context should fail verification");
    let result_empty = dsa::verify(&pk, msg, &ctx_sig, b"").expect("ctx verify empty");
    assert!(
        !result_empty,
        "Empty context should fail when signed with non-empty context"
    );
    eprintln!("[PASS] Context string correctly affects verification");

    // Test 14: Multiple sequential sign/verify cycles (stress test)
    for i in 0..10 {
        let cycle_msg = format!("telemetry packet #{}", i);
        let cycle_sig = dsa::sign(&sk, cycle_msg.as_bytes(), b"", SigningMode::Hedged)
            .unwrap_or_else(|_| panic!("cycle {} sign failed", i));
        let result = dsa::verify(&pk, cycle_msg.as_bytes(), &cycle_sig, b"")
            .unwrap_or_else(|_| panic!("cycle {} verify failed", i));
        assert!(result, "Cycle {} failed verification", i);
    }
    eprintln!("[PASS] 10 sequential sign/verify cycles");

    eprintln!("=== {} — ALL 14 TESTS PASSED ===\n", name);
}

#[test]
fn test_mldsa44_full_validation() {
    test_full_validation(ParameterSet::MlDsa44, "ML-DSA-44");
}

#[test]
fn test_mldsa65_full_validation() {
    test_full_validation(ParameterSet::MlDsa65, "ML-DSA-65");
}

#[test]
fn test_mldsa87_full_validation() {
    test_full_validation(ParameterSet::MlDsa87, "ML-DSA-87");
}

/// Cross-parameter-set tests: signatures from one set must not verify with another
#[test]
fn test_cross_parameter_set_rejection() {
    let msg = b"cross-parameter test";

    let (pk44, sk44) = dsa::key_gen(ParameterSet::MlDsa44).unwrap();
    let (pk65, _sk65) = dsa::key_gen(ParameterSet::MlDsa65).unwrap();

    let sig44 = dsa::sign(&sk44, msg, b"", SigningMode::Hedged).unwrap();

    // Attempting to verify a DSA-44 signature with a DSA-65 key should fail
    let result = dsa::verify(&pk65, msg, &sig44, b"");
    match result {
        Ok(true) => panic!("Cross-parameter verification should not succeed"),
        Ok(false) => eprintln!("[PASS] Cross-parameter correctly returns false"),
        Err(_) => eprintln!("[PASS] Cross-parameter correctly returns error (parameter mismatch)"),
    }

    // Verify original still works
    assert!(
        dsa::verify(&pk44, msg, &sig44, b"").unwrap(),
        "Original sig should still verify"
    );
    eprintln!("[PASS] Cross-parameter-set rejection");
}

/// Key size validation
#[test]
fn test_key_and_signature_sizes() {
    for (param, pk_size, sk_size, sig_size, name) in [
        (ParameterSet::MlDsa44, 1312, 2560, 2420, "ML-DSA-44"),
        (ParameterSet::MlDsa65, 1952, 4032, 3309, "ML-DSA-65"),
        (ParameterSet::MlDsa87, 2592, 4896, 4627, "ML-DSA-87"),
    ] {
        let (pk, sk) = dsa::key_gen(param).unwrap();
        assert_eq!(
            pk.as_bytes().len(),
            pk_size,
            "{} public key size mismatch",
            name
        );
        assert_eq!(
            sk.as_bytes().len(),
            sk_size,
            "{} private key size mismatch",
            name
        );

        let sig = dsa::sign(&sk, b"test", b"", SigningMode::Hedged).unwrap();
        assert_eq!(
            sig.as_bytes().len(),
            sig_size,
            "{} signature size mismatch",
            name
        );

        eprintln!(
            "[PASS] {} sizes: pk={}B sk={}B sig={}B",
            name, pk_size, sk_size, sig_size
        );
    }
}
