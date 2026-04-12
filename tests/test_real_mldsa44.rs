use turtl::dsa::{key_gen, sign, verify, ParameterSet, SigningMode};

#[test]
fn test_mldsa44_sign_verify() {
    println!("\n=== Testing ML-DSA-44 (REAL parameter set) ===");

    let (public_key, private_key) = key_gen(ParameterSet::MlDsa44).unwrap();
    println!("✓ Keys generated");

    let message = b"test message";
    println!("Attempting to sign...");

    let signature = sign(&private_key, message, b"", SigningMode::Deterministic).unwrap();
    println!(
        "✓ Signature generated ({} bytes)",
        signature.as_bytes().len()
    );

    println!("Attempting to verify...");
    let result = verify(&public_key, message, &signature, b"").unwrap();
    println!("Verification result: {}", result);

    assert!(result, "Signature verification must return true");
}
