//! Negative test cases for error handling and input validation.
//!
//! This module contains tests that verify the system handles corrupted,
//! invalid, or malformed inputs correctly by returning appropriate errors
//! rather than panicking or producing incorrect results.

use turtl::dsa::{self, KeyPair as DsaKeyPair, ParameterSet as DsaParameterSet, SigningMode};
use turtl::error::Error;
use turtl::kem::ParameterSet as KemParameterSet;

// Test seeds for deterministic key generation
const TEST_SEED_1: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
];

const TEST_SEED_2: [u8; 32] = [
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
];

/// Test KEM with invalid public key sizes
#[test]
fn test_kem_invalid_public_key_size() {
    // ML-KEM-512 expects 800-byte public keys
    let invalid_sizes = [0, 1, 100, 799, 801, 1000];

    for size in invalid_sizes {
        let invalid_pk_bytes = vec![0x42u8; size];
        let result = turtl::kem::PublicKey::new(invalid_pk_bytes, KemParameterSet::MlKem512);

        assert!(result.is_err(), "Size {} should be rejected", size);
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidPublicKey));
        }
    }
}

/// Test KEM with invalid private key sizes
#[test]
fn test_kem_invalid_private_key_size() {
    // ML-KEM-512 expects 1632-byte private keys
    let invalid_sizes = [0, 1, 100, 1631, 1633, 2000];

    for size in invalid_sizes {
        let invalid_sk_bytes = vec![0x42u8; size];
        let result = turtl::kem::PrivateKey::new(invalid_sk_bytes, KemParameterSet::MlKem512);

        assert!(result.is_err(), "Size {} should be rejected", size);
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidPrivateKey));
        }
    }
}

/// Test KEM with invalid ciphertext sizes
#[test]
fn test_kem_invalid_ciphertext_size() {
    // ML-KEM-512 expects 768-byte ciphertexts
    let invalid_sizes = [0, 1, 100, 767, 769, 1000];

    for size in invalid_sizes {
        let invalid_ct_bytes = vec![0x42u8; size];
        let result = turtl::kem::Ciphertext::new(invalid_ct_bytes, KemParameterSet::MlKem512);

        assert!(result.is_err(), "Size {} should be rejected", size);
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidCiphertext));
        }
    }
}

/// Test DSA with invalid public key sizes
#[test]
fn test_dsa_invalid_public_key_size() {
    // ML-DSA-44 expects 1312-byte public keys
    let invalid_sizes = [0, 1, 100, 1311, 1313, 2000];

    for size in invalid_sizes {
        let invalid_pk_bytes = vec![0x42u8; size];
        let result = turtl::dsa::PublicKey::new(invalid_pk_bytes, DsaParameterSet::MlDsa44);

        assert!(result.is_err(), "Size {} should be rejected", size);
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidPublicKey));
        }
    }
}

/// Test DSA with invalid private key sizes
#[test]
fn test_dsa_invalid_private_key_size() {
    // ML-DSA-44 expects 2560-byte private keys
    let invalid_sizes = [0, 1, 100, 2559, 2561, 3000];

    for size in invalid_sizes {
        let invalid_sk_bytes = vec![0x42u8; size];
        let result = turtl::dsa::PrivateKey::new(invalid_sk_bytes, DsaParameterSet::MlDsa44);

        assert!(result.is_err(), "Size {} should be rejected", size);
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidPrivateKey));
        }
    }
}

/// Test DSA with invalid signature sizes
#[test]
fn test_dsa_invalid_signature_size() {
    // ML-DSA-44 expects 2420-byte signatures
    let invalid_sizes = [0, 1, 100, 2419, 2421, 3000];

    for size in invalid_sizes {
        let invalid_sig_bytes = vec![0x42u8; size];
        let result = turtl::dsa::Signature::new(invalid_sig_bytes, DsaParameterSet::MlDsa44);

        assert!(result.is_err(), "Size {} should be rejected", size);
        if let Err(e) = result {
            assert!(matches!(e, Error::InvalidSignature));
        }
    }
}

/// All-zero bytes: a valid encapsulation key encoding (every coefficient is 0),
/// but not a valid decapsulation key (the embedded H(ek) does not match).
#[test]
fn test_all_zero_keys() {
    let zero_pk = vec![0x00u8; 800];
    let zero_sk = vec![0x00u8; 1632];

    assert!(turtl::kem::PublicKey::new(zero_pk, KemParameterSet::MlKem512).is_ok());
    assert!(matches!(
        turtl::kem::PrivateKey::new(zero_sk, KemParameterSet::MlKem512),
        Err(Error::InvalidPrivateKey)
    ));
}

/// All-ones bytes decode to coefficients of 4095 >= q, so the FIPS 203 modulus
/// check rejects the public key; the private key fails the hash check.
#[test]
fn test_all_ones_keys() {
    let ones_pk = vec![0xFFu8; 800];
    let ones_sk = vec![0xFFu8; 1632];

    assert!(matches!(
        turtl::kem::PublicKey::new(ones_pk, KemParameterSet::MlKem512),
        Err(Error::InvalidPublicKey)
    ));
    assert!(matches!(
        turtl::kem::PrivateKey::new(ones_sk, KemParameterSet::MlKem512),
        Err(Error::InvalidPrivateKey)
    ));
}

/// FIPS 203 Section 7.2 modulus check: a single out-of-range coefficient in an
/// otherwise valid public key must be rejected.
#[test]
fn test_kem_public_key_modulus_check() {
    let kp = turtl::kem::KeyPair::from_seeds(&TEST_SEED_1, &TEST_SEED_2, KemParameterSet::MlKem768)
        .unwrap();
    let mut pk = kp.public_key().as_bytes().to_vec();
    // First coefficient := 3329 (= q), encoded in the low 12 bits.
    pk[0] = (3329 & 0xFF) as u8;
    pk[1] = (pk[1] & 0xF0) | ((3329 >> 8) as u8);
    assert!(matches!(
        turtl::kem::PublicKey::new(pk, KemParameterSet::MlKem768),
        Err(Error::InvalidPublicKey)
    ));
}

/// FIPS 203 Section 7.3 hash check: tampering with the embedded public key or
/// its hash inside a private key must be rejected.
#[test]
fn test_kem_private_key_hash_check() {
    let kp = turtl::kem::KeyPair::from_seeds(&TEST_SEED_1, &TEST_SEED_2, KemParameterSet::MlKem768)
        .unwrap();
    let sk = kp.private_key().as_bytes().to_vec();
    let k = 3;
    for idx in [384 * k, 768 * k + 31, 768 * k + 32] {
        let mut bad = sk.clone();
        bad[idx] ^= 0x01;
        assert!(
            matches!(
                turtl::kem::PrivateKey::new(bad, KemParameterSet::MlKem768),
                Err(Error::InvalidPrivateKey)
            ),
            "tampered byte {idx} accepted"
        );
    }
    assert!(turtl::kem::PrivateKey::new(sk, KemParameterSet::MlKem768).is_ok());
}

/// Test mismatched parameter sets
#[test]
fn test_mismatched_parameter_sets() {
    // Create keys with one parameter set
    let pk = turtl::kem::KeyPair::from_seed(&TEST_SEED_1, KemParameterSet::MlKem512)
        .unwrap()
        .public_key();
    let sk = turtl::kem::KeyPair::from_seed(&TEST_SEED_1, KemParameterSet::MlKem768)
        .unwrap()
        .private_key();

    // Trying to use mismatched keys should fail
    let result = turtl::kem::KeyPair::from_keys(pk, sk);
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(matches!(e, Error::InvalidParameterSet));
    }
}

/// Test empty byte arrays
#[test]
fn test_empty_inputs() {
    let empty = vec![];

    // Empty public key
    let result = turtl::kem::PublicKey::new(empty.clone(), KemParameterSet::MlKem512);
    assert!(result.is_err());

    // Empty private key
    let result = turtl::kem::PrivateKey::new(empty.clone(), KemParameterSet::MlKem512);
    assert!(result.is_err());

    // Empty ciphertext
    let result = turtl::kem::Ciphertext::new(empty.clone(), KemParameterSet::MlKem512);
    assert!(result.is_err());
}

/// Test extremely large inputs
#[test]
fn test_oversized_inputs() {
    // Very large inputs (simulating memory exhaustion attacks)
    let huge_bytes = vec![0x42u8; 1_000_000]; // 1MB

    let result = turtl::kem::PublicKey::new(huge_bytes.clone(), KemParameterSet::MlKem512);
    assert!(result.is_err());

    let result = turtl::kem::PrivateKey::new(huge_bytes.clone(), KemParameterSet::MlKem512);
    assert!(result.is_err());

    let result = turtl::kem::Ciphertext::new(huge_bytes, KemParameterSet::MlKem512);
    assert!(result.is_err());
}

/// Test off-by-one errors in size validation
#[test]
fn test_off_by_one_sizes() {
    // Test boundary conditions for ML-KEM-512
    let pk_size = KemParameterSet::MlKem512.public_key_size();
    let _sk_size = KemParameterSet::MlKem512.private_key_size();
    let _ct_size = KemParameterSet::MlKem512.ciphertext_size();

    // One byte too small
    let result = turtl::kem::PublicKey::new(vec![0; pk_size - 1], KemParameterSet::MlKem512);
    assert!(result.is_err());

    // Exact size (should work)
    let result = turtl::kem::PublicKey::new(vec![0; pk_size], KemParameterSet::MlKem512);
    assert!(result.is_ok());

    // One byte too large
    let result = turtl::kem::PublicKey::new(vec![0; pk_size + 1], KemParameterSet::MlKem512);
    assert!(result.is_err());
}

/// Test that valid-sized but random ciphertext can be created
/// (ML-KEM uses implicit rejection, so decapsulation will succeed with wrong shared secret)
#[test]
fn test_random_ciphertext_accepted() {
    // ML-KEM-512 expects 768-byte ciphertexts
    // Create a valid-sized but random ciphertext
    let random_ct_bytes = vec![0x42u8; 768];

    // This should succeed because the size is correct
    let result = turtl::kem::Ciphertext::new(random_ct_bytes, KemParameterSet::MlKem512);
    assert!(result.is_ok(), "Valid-sized ciphertext should be accepted");

    // Note: ML-KEM uses implicit rejection - decapsulation with a random ciphertext
    // will succeed but produce a different (pseudo-random) shared secret rather than
    // failing explicitly. This prevents timing attacks.
}

/// Test signature verification with wrong public key
#[test]
fn test_verify_with_wrong_key() {
    // Generate two different keypairs using deterministic seeds
    let keypair1 = DsaKeyPair::from_seed(&TEST_SEED_1, DsaParameterSet::MlDsa44).unwrap();
    let keypair2 = DsaKeyPair::from_seed(&TEST_SEED_2, DsaParameterSet::MlDsa44).unwrap();

    let _public_key1 = keypair1.public_key();
    let private_key1 = keypair1.private_key();
    let public_key2 = keypair2.public_key();

    let message = b"test message";

    // Sign with key1
    let signature = dsa::sign(&private_key1, message, b"", SigningMode::Deterministic).unwrap();

    // Verify with key2 (should fail)
    let result = dsa::verify(&public_key2, message, &signature, b"").unwrap();
    assert!(!result, "Signature should not verify with wrong key");
}

/// Test signature verification with modified message
#[test]
fn test_verify_modified_message() {
    // Generate keypair using deterministic seed
    let keypair = DsaKeyPair::from_seed(&TEST_SEED_1, DsaParameterSet::MlDsa44).unwrap();
    let public_key = keypair.public_key();
    let private_key = keypair.private_key();

    let message = b"original message";
    let modified = b"modified message";

    // Sign original message
    let signature = dsa::sign(&private_key, message, b"", SigningMode::Deterministic).unwrap();

    // Verify with modified message (should fail)
    let result = dsa::verify(&public_key, modified, &signature, b"").unwrap();
    assert!(!result, "Signature should not verify with modified message");
}

/// Test signature verification with modified context
#[test]
fn test_verify_wrong_context() {
    // Generate keypair using deterministic seed
    let keypair = DsaKeyPair::from_seed(&TEST_SEED_1, DsaParameterSet::MlDsa44).unwrap();
    let public_key = keypair.public_key();
    let private_key = keypair.private_key();

    let message = b"test message";
    let context1 = b"context1";
    let context2 = b"context2";

    // Sign with context1
    let signature = dsa::sign(&private_key, message, context1, SigningMode::Deterministic).unwrap();

    // Verify with context2 (should fail)
    let result = dsa::verify(&public_key, message, &signature, context2).unwrap();
    assert!(!result, "Signature should not verify with wrong context");
}

/// Test signature verification with corrupted signature
#[test]
fn test_verify_corrupted_signature() {
    // Generate keypair using deterministic seed
    let keypair = DsaKeyPair::from_seed(&TEST_SEED_1, DsaParameterSet::MlDsa44).unwrap();
    let public_key = keypair.public_key();
    let private_key = keypair.private_key();

    let message = b"test message";

    // Sign message
    let signature = dsa::sign(&private_key, message, b"", SigningMode::Deterministic).unwrap();

    // Corrupt the signature
    let mut corrupted_bytes = signature.as_bytes().to_vec();
    corrupted_bytes[0] ^= 0xFF;

    let corrupted_sig =
        turtl::dsa::Signature::new(corrupted_bytes, DsaParameterSet::MlDsa44).unwrap();

    // Verification should fail
    let result = dsa::verify(&public_key, message, &corrupted_sig, b"").unwrap();
    assert!(!result, "Corrupted signature should not verify");
}

/// A signature whose hint encoding is malformed is invalid: verify must return
/// `Ok(false)` (FIPS 204 Algorithm 8), not an error.
#[test]
fn test_verify_malformed_hint_returns_false() {
    let keypair = DsaKeyPair::from_seed(&TEST_SEED_1, DsaParameterSet::MlDsa44).unwrap();
    let signature = dsa::sign(
        &keypair.private_key(),
        b"msg",
        b"",
        SigningMode::Deterministic,
    )
    .unwrap();

    // The last k bytes are cumulative hint counts; a count above omega is malformed.
    let mut bytes = signature.as_bytes().to_vec();
    let last = bytes.len() - 1;
    bytes[last] = 0xFF;
    let bad = turtl::dsa::Signature::new(bytes, DsaParameterSet::MlDsa44).unwrap();

    assert!(!dsa::verify(&keypair.public_key(), b"msg", &bad, b"").unwrap());
}

/// Every pre-hash function round-trips through hash_sign / hash_verify, and a
/// signature made under one pre-hash function does not verify under another.
#[test]
fn test_hash_sign_all_prehash_functions() {
    use turtl::dsa::HashFunction;
    let keypair = DsaKeyPair::from_seed(&TEST_SEED_2, DsaParameterSet::MlDsa65).unwrap();
    let all = [
        HashFunction::SHA3_256,
        HashFunction::SHA3_512,
        HashFunction::SHAKE128,
        HashFunction::SHAKE256,
    ];
    for hf in all {
        let sig = dsa::hash_sign(
            &keypair.private_key(),
            b"msg",
            b"ctx",
            hf,
            SigningMode::Deterministic,
        )
        .unwrap();
        for other in all {
            let ok = dsa::hash_verify(&keypair.public_key(), b"msg", &sig, b"ctx", other).unwrap();
            assert_eq!(
                ok,
                hf == other,
                "signed with {hf:?}, verified with {other:?}"
            );
        }
    }
}

/// A private key with s1 coefficients outside [-eta, eta] is malformed and is
/// rejected when the key is constructed.
#[test]
fn test_dsa_malformed_private_key() {
    let kp = DsaKeyPair::from_seed(&TEST_SEED_1, DsaParameterSet::MlDsa44).unwrap();
    let mut sk = kp.private_key().as_bytes().to_vec();
    // s1 starts after rho || K || tr (128 bytes); 3-bit fields, eta = 2.
    // 0xFF packs the value 7, i.e. coefficient eta - 7 = -5.
    sk[128] = 0xFF;
    assert!(matches!(
        turtl::dsa::PrivateKey::new(sk, DsaParameterSet::MlDsa44),
        Err(Error::InvalidPrivateKey)
    ));
}
