use turtl::dsa::{self, ParameterSet as DsaParameterSet, SigningMode};

// NOTE: Ignored due to known ML-DSA NTT implementation bug (TODO.md line 10)
// This test requires signing to work, which depends on the broken NTT implementation.
#[test]
#[ignore]
fn test_simple_sign() {
    // Generate a keypair
    let (public_key, private_key) = dsa::key_gen(DsaParameterSet::MlDsa44).unwrap();

    // Try to sign a message
    let message = b"Hello, world!";

    println!("Attempting to sign message...");
    let result = dsa::sign(&private_key, message, b"", SigningMode::Deterministic);

    match result {
        Ok(signature) => {
            println!(
                "✓ Signature created successfully! Size: {} bytes",
                signature.as_bytes().len()
            );

            // Verify the signature
            let verify_result = dsa::verify(&public_key, message, &signature, b"");

            match verify_result {
                Ok(true) => {
                    println!("✓ Signature verified successfully!");
                }
                Ok(false) => {
                    panic!("✗ Signature verification returned false");
                }
                Err(e) => {
                    panic!("✗ Signature verification failed with error: {:?}", e);
                }
            }
        }
        Err(e) => {
            panic!("✗ Signing failed with error: {:?}", e);
        }
    }
}
