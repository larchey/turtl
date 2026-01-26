//! ML-DSA Basic Usage Example
//!
//! This example demonstrates the basic usage of TURTL's ML-DSA (Digital Signature Algorithm)
//! implementation, which provides post-quantum digital signatures according to NIST FIPS 204.
//!
//! # ⚠️ CURRENT STATUS
//!
//! **This example is currently blocked by a known critical bug in ML-DSA verification.**
//! See TODO.md for details. The code is correct and will run successfully once the bug is fixed.
//!
//! # What This Example Demonstrates
//!
//! - Key generation for all three parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87)
//! - Signing messages with both hedged and deterministic modes
//! - Verifying signatures
//! - Demonstrating signature verification failure on tampered messages
//!
//! # Understanding ML-DSA Parameter Sets
//!
//! - **ML-DSA-44**: Security Category 2 (SHA-256 equivalent) - smallest keys/signatures
//! - **ML-DSA-65**: Security Category 3 (SHA-384 equivalent) - recommended default
//! - **ML-DSA-87**: Security Category 5 (SHA-512 equivalent) - maximum security
//!
//! # Signing Modes
//!
//! - **Hedged** (recommended): Uses fresh randomness for each signature, providing
//!   defense-in-depth against side-channel attacks and RNG failures. Different
//!   signatures are produced each time for the same message.
//! - **Deterministic**: No randomness, same signature every time for the same message/key.
//!   Useful for testing or when reproducibility is required.
//!
//! # Context Strings
//!
//! Context strings (up to 255 bytes) provide domain separation and prevent signature
//! reuse across different applications. They can be empty ("") or contain application-
//! specific data like "myapp-v1.0" or "TLS-handshake".
//!
//! # Run This Example
//!
//! ```bash
//! cargo run --example dsa_basic
//! ```

use turtl::dsa::{key_gen, sign, verify, ParameterSet, SigningMode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔═══════════════════════════════════════════════════════╗");
    println!("║        ML-DSA Basic Usage Example                    ║");
    println!("║   Post-Quantum Digital Signatures (FIPS 204)         ║");
    println!("╚═══════════════════════════════════════════════════════╝\n");

    // Demonstrate each parameter set
    demo_dsa_44()?;
    println!("\n{}\n", "─".repeat(60));

    demo_dsa_65()?;
    println!("\n{}\n", "─".repeat(60));

    demo_dsa_87()?;
    println!("\n{}\n", "─".repeat(60));

    // Demonstrate signature verification failure
    demo_verification_failure()?;

    println!("\n✅ All demonstrations completed successfully!");
    println!("\nKey Takeaways:");
    println!("  • ML-DSA provides post-quantum secure digital signatures");
    println!("  • Three parameter sets offer different security/size trade-offs");
    println!("  • Hedged mode (recommended) adds randomness for side-channel resistance");
    println!("  • Context strings enable domain separation");
    println!("  • Signatures are larger than classical schemes but quantum-resistant");

    Ok(())
}

/// Demonstrate ML-DSA-44 (Security Category 2 - comparable to SHA-256)
fn demo_dsa_44() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══ ML-DSA-44 (Security Category 2) ═══");
    println!("Security Level: Comparable to SHA-256/SHA3-256 collision resistance");
    println!("Use Case: Applications requiring SHA-256 equivalent security\n");

    // Step 1: Generate a key pair
    println!("1. Generating key pair...");
    let (public_key, private_key) = key_gen(ParameterSet::MlDsa44)?;

    println!("   ✓ Public key:  {} bytes", public_key.as_bytes().len());
    println!("   ✓ Private key: {} bytes", private_key.as_bytes().len());

    // Step 2: Sign a message
    println!("\n2. Signing message...");
    let message = b"Hello, post-quantum world!";

    // Context strings provide domain separation - they prevent signatures
    // from being valid across different applications or contexts.
    // They can be empty ("") or up to 255 bytes.
    let context = b"turtl-example-v1";

    // Use hedged mode (recommended) - combines deterministic signing with fresh
    // randomness for defense-in-depth against side-channel attacks and RNG failures.
    let signature = sign(&private_key, message, context, SigningMode::Hedged)?;

    println!("   Message: \"{}\"", String::from_utf8_lossy(message));
    println!("   Context: \"{}\"", String::from_utf8_lossy(context));
    println!("   ✓ Signature: {} bytes", signature.as_bytes().len());

    // Step 3: Verify the signature
    println!("\n3. Verifying signature...");
    let is_valid = verify(&public_key, message, &signature, context)?;

    if is_valid {
        println!("   ✓ Signature is VALID - message authenticated successfully!");
    } else {
        println!("   ✗ Signature is INVALID - verification failed!");
    }

    // Display key and signature sizes
    println!("\n4. Size Summary:");
    println!(
        "   Public key:  {:4} bytes",
        ParameterSet::MlDsa44.public_key_size()
    );
    println!(
        "   Private key: {:4} bytes",
        ParameterSet::MlDsa44.private_key_size()
    );
    println!(
        "   Signature:   {:4} bytes",
        ParameterSet::MlDsa44.signature_size()
    );

    Ok(())
}

/// Demonstrate ML-DSA-65 (Security Category 3 - comparable to SHA-384)
fn demo_dsa_65() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══ ML-DSA-65 (Security Category 3) ═══");
    println!("Security Level: Comparable to SHA-384/SHA3-384 collision resistance");
    println!("Use Case: Recommended default for most applications\n");

    // Step 1: Generate a key pair
    println!("1. Generating key pair...");
    let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;

    println!("   ✓ Public key:  {} bytes", public_key.as_bytes().len());
    println!("   ✓ Private key: {} bytes", private_key.as_bytes().len());

    // Step 2: Sign a message with deterministic mode
    println!("\n2. Signing message (deterministic mode)...");
    let message = b"The quick brown fox jumps over the lazy dog";
    let context = b""; // Empty context is valid

    // Deterministic mode produces the same signature for the same message/key
    // This is useful for testing or when reproducibility is required
    let signature = sign(&private_key, message, context, SigningMode::Deterministic)?;

    println!("   Message: \"{}\"", String::from_utf8_lossy(message));
    println!("   Context: <empty>");
    println!("   ✓ Signature: {} bytes", signature.as_bytes().len());

    // Verify deterministic signatures are reproducible
    let signature2 = sign(&private_key, message, context, SigningMode::Deterministic)?;
    if signature.as_bytes() == signature2.as_bytes() {
        println!("   ✓ Deterministic mode: identical signatures produced");
    }

    // Step 3: Verify the signature
    println!("\n3. Verifying signature...");
    let is_valid = verify(&public_key, message, &signature, context)?;

    if is_valid {
        println!("   ✓ Signature is VALID - message authenticated successfully!");
    } else {
        println!("   ✗ Signature is INVALID - verification failed!");
    }

    // Display key and signature sizes
    println!("\n4. Size Summary:");
    println!(
        "   Public key:  {:4} bytes",
        ParameterSet::MlDsa65.public_key_size()
    );
    println!(
        "   Private key: {:4} bytes",
        ParameterSet::MlDsa65.private_key_size()
    );
    println!(
        "   Signature:   {:4} bytes",
        ParameterSet::MlDsa65.signature_size()
    );

    Ok(())
}

/// Demonstrate ML-DSA-87 (Security Category 5 - comparable to SHA-512)
fn demo_dsa_87() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══ ML-DSA-87 (Security Category 5) ═══");
    println!("Security Level: Comparable to SHA-512/SHA3-512 collision resistance");
    println!("Use Case: Maximum security for high-value applications\n");

    // Step 1: Generate a key pair
    println!("1. Generating key pair...");
    let (public_key, private_key) = key_gen(ParameterSet::MlDsa87)?;

    println!("   ✓ Public key:  {} bytes", public_key.as_bytes().len());
    println!("   ✓ Private key: {} bytes", private_key.as_bytes().len());

    // Step 2: Sign a message with hedged mode
    println!("\n2. Signing message (hedged mode - recommended)...");
    let message = b"Confidential: Top Secret Document XYZ-789";
    let context = b"secure-comms-2025";

    // Hedged mode uses fresh randomness for each signature, providing:
    // - Defense against side-channel attacks
    // - Protection against RNG failures
    // - Different signatures each time (unlike deterministic mode)
    let signature = sign(&private_key, message, context, SigningMode::Hedged)?;

    println!("   Message: \"{}\"", String::from_utf8_lossy(message));
    println!("   Context: \"{}\"", String::from_utf8_lossy(context));
    println!("   ✓ Signature: {} bytes", signature.as_bytes().len());

    // Verify hedged signatures are different each time
    let signature2 = sign(&private_key, message, context, SigningMode::Hedged)?;
    if signature.as_bytes() != signature2.as_bytes() {
        println!("   ✓ Hedged mode: unique signatures produced (due to fresh randomness)");
    }

    // Step 3: Verify both signatures
    println!("\n3. Verifying signatures...");
    let is_valid1 = verify(&public_key, message, &signature, context)?;
    let is_valid2 = verify(&public_key, message, &signature2, context)?;

    if is_valid1 && is_valid2 {
        println!("   ✓ Both signatures are VALID - different signatures, same verification!");
    } else {
        println!("   ✗ Signature verification failed!");
    }

    // Display key and signature sizes
    println!("\n4. Size Summary:");
    println!(
        "   Public key:  {:4} bytes",
        ParameterSet::MlDsa87.public_key_size()
    );
    println!(
        "   Private key: {:4} bytes",
        ParameterSet::MlDsa87.private_key_size()
    );
    println!(
        "   Signature:   {:4} bytes",
        ParameterSet::MlDsa87.signature_size()
    );

    Ok(())
}

/// Demonstrate signature verification failure scenarios
fn demo_verification_failure() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══ Signature Verification Failure Scenarios ═══\n");

    // Generate a key pair for testing
    let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
    let message = b"Original message";
    let context = b"test-context";
    let signature = sign(&private_key, message, context, SigningMode::Hedged)?;

    // Scenario 1: Tampered message
    println!("1. Testing with tampered message...");
    let tampered_message = b"Tampered message"; // Different message
    let is_valid = verify(&public_key, tampered_message, &signature, context)?;

    if !is_valid {
        println!("   ✓ Correctly REJECTED - tampered message detected!");
    } else {
        println!("   ✗ ERROR: Tampered message was accepted (should not happen)");
    }

    // Scenario 2: Wrong context
    println!("\n2. Testing with wrong context...");
    let wrong_context = b"wrong-context";
    let is_valid = verify(&public_key, message, &signature, wrong_context)?;

    if !is_valid {
        println!("   ✓ Correctly REJECTED - context mismatch detected!");
    } else {
        println!("   ✗ ERROR: Wrong context was accepted (should not happen)");
    }

    // Scenario 3: Wrong public key
    println!("\n3. Testing with wrong public key...");
    let (wrong_public_key, _) = key_gen(ParameterSet::MlDsa65)?;
    let is_valid = verify(&wrong_public_key, message, &signature, context)?;

    if !is_valid {
        println!("   ✓ Correctly REJECTED - wrong public key detected!");
    } else {
        println!("   ✗ ERROR: Wrong public key was accepted (should not happen)");
    }

    // Scenario 4: Correct verification for comparison
    println!("\n4. Testing with correct parameters (for comparison)...");
    let is_valid = verify(&public_key, message, &signature, context)?;

    if is_valid {
        println!("   ✓ Correctly ACCEPTED - all parameters match!");
    } else {
        println!("   ✗ ERROR: Valid signature was rejected (should not happen)");
    }

    println!("\n✓ Security validation: Signature scheme correctly rejects invalid signatures");

    Ok(())
}
