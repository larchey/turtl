use turtl::dsa::{self, ParameterSet as DsaParameterSet, SigningMode};

#[test]
fn test_simple_sign() {
    // Generate a keypair
    let (public_key, private_key) = dsa::key_gen(DsaParameterSet::MlDsa44).unwrap();

    // Try to sign a message
    let message = b"Hello, world!";

    println!("Attempting to sign message...");
    let result = dsa::sign(
        &private_key,
        message,
        b"",
        SigningMode::Deterministic,
    );

    match result {
        Ok(signature) => {
            println!("✓ Signature created successfully! Size: {} bytes", signature.as_bytes().len());

            // Verify the signature
            let verify_result = dsa::verify(
                &public_key,
                message,
                &signature,
                b"",
            ).unwrap();

            assert!(verify_result, "Signature should verify");
            println!("✓ Signature verified successfully!");
        }
        Err(e) => {
            panic!("✗ Signing failed with error: {:?}", e);
        }
    }
}
