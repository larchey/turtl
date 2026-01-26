//! Hedged vs Deterministic Signing Example
//!
//! This example demonstrates the difference between deterministic and hedged
//! signing modes in ML-DSA (FIPS 204).
//!
//! # Signing Modes
//!
//! ## Deterministic Mode
//! - Same message + same key → **identical signature** every time
//! - No fresh randomness used during signing
//! - Signature is reproducible and verifiable
//! - Vulnerable if RNG was compromised during key generation
//! - Vulnerable to side-channel attacks when signing the same message repeatedly
//!
//! ## Hedged Mode (Recommended)
//! - Same message + same key → **different signatures** each time
//! - Uses fresh randomness combined with deterministic component
//! - Each signature is unique but equally valid
//! - Defense-in-depth against RNG failures and side-channel attacks
//! - Recommended for production use
//!
//! # Security Trade-offs
//!
//! **Deterministic Mode:**
//! - ✓ Reproducible signatures (useful for testing/debugging)
//! - ✓ No dependency on RNG during signing
//! - ✗ Vulnerable to side-channel attacks on repeated signatures
//! - ✗ No protection if signing process is compromised
//!
//! **Hedged Mode:**
//! - ✓ Extra security margin against attacks
//! - ✓ Protection against future RNG vulnerabilities
//! - ✓ Randomized signatures prevent certain side-channel attacks
//! - ✗ Signatures are not reproducible
//! - ✗ Requires working RNG during signing
//!
//! # When to Use Each Mode
//!
//! **Use Deterministic Mode when:**
//! - Testing and debugging (to verify exact signature values)
//! - You need reproducible signatures for compliance/auditing
//! - You have specific requirements for signature determinism
//!
//! **Use Hedged Mode when:**
//! - Production environments (recommended)
//! - Maximum security is required
//! - Protecting against unknown future vulnerabilities
//! - Most general-purpose applications

use turtl::dsa::{key_gen, sign, verify, ParameterSet, SigningMode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║   ML-DSA Hedged vs Deterministic Signing Demonstration        ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    // Run demonstrations
    demo_deterministic()?;
    demo_hedged()?;
    demo_verification()?;

    // Print usage recommendations
    print_usage_guide();

    Ok(())
}

/// Demonstrates deterministic signing mode
///
/// In deterministic mode, the same message signed with the same key will
/// always produce the exact same signature. This is because no randomness
/// is injected during the signing process.
fn demo_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══ Deterministic Signing Mode ═══\n");

    // Generate a key pair using ML-DSA-65 (security category 3)
    let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
    println!("✓ Generated ML-DSA-65 key pair");

    // Message to sign
    let message = b"Important contract: Alice transfers $1000 to Bob";
    let context = b""; // Empty context for this example

    println!("  Message: \"{}\"", String::from_utf8_lossy(message));

    // Sign the same message twice in deterministic mode
    println!("\n  Signing the same message twice...");
    let sig1 = sign(&private_key, message, context, SigningMode::Deterministic)?;
    let sig2 = sign(&private_key, message, context, SigningMode::Deterministic)?;

    // Display signature bytes (first 16 bytes for brevity)
    println!(
        "  Signature 1 (first 16 bytes): {}",
        hex_preview(sig1.as_bytes(), 16)
    );
    println!(
        "  Signature 2 (first 16 bytes): {}",
        hex_preview(sig2.as_bytes(), 16)
    );

    // Verify signatures are identical
    if sig1.as_bytes() == sig2.as_bytes() {
        println!("\n✓ Signatures are IDENTICAL (deterministic behavior)");
        println!("  Same message → same signature (reproducible)");
    } else {
        println!("\n✗ ERROR: Signatures differ (unexpected!)");
    }

    // Verify both signatures are valid
    let valid1 = verify(&public_key, message, &sig1, context)?;
    let valid2 = verify(&public_key, message, &sig2, context)?;

    if valid1 && valid2 {
        println!("✓ Both signatures verify correctly");
    } else {
        println!("✗ Verification failed (sig1: {}, sig2: {})", valid1, valid2);
        return Err("Signature verification failed".into());
    }

    println!();
    Ok(())
}

/// Demonstrates hedged signing mode
///
/// In hedged mode, fresh randomness is added to each signature. Even when
/// signing the same message with the same key, each signature will be
/// different. However, all signatures remain valid and can be verified.
fn demo_hedged() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══ Hedged Signing Mode (Recommended) ═══\n");

    // Generate a key pair using ML-DSA-65 (security category 3)
    let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;
    println!("✓ Generated ML-DSA-65 key pair");

    // Same message as before
    let message = b"Important contract: Alice transfers $1000 to Bob";
    let context = b""; // Empty context for this example

    println!("  Message: \"{}\"", String::from_utf8_lossy(message));

    // Sign the same message twice in hedged mode
    println!("\n  Signing the same message twice...");
    let sig1 = sign(&private_key, message, context, SigningMode::Hedged)?;
    let sig2 = sign(&private_key, message, context, SigningMode::Hedged)?;

    // Display signature bytes (first 16 bytes for brevity)
    println!(
        "  Signature 1 (first 16 bytes): {}",
        hex_preview(sig1.as_bytes(), 16)
    );
    println!(
        "  Signature 2 (first 16 bytes): {}",
        hex_preview(sig2.as_bytes(), 16)
    );

    // Verify signatures are different
    if sig1.as_bytes() != sig2.as_bytes() {
        println!("\n✓ Signatures are DIFFERENT (hedged randomization)");
        println!("  Same message → different signatures (non-deterministic)");
        println!("  Each signature includes fresh randomness for extra security");
    } else {
        println!("\n⚠ WARNING: Signatures are identical (unexpected!)");
    }

    // Verify both signatures are valid despite being different
    let valid1 = verify(&public_key, message, &sig1, context)?;
    let valid2 = verify(&public_key, message, &sig2, context)?;

    if valid1 && valid2 {
        println!("✓ Both signatures verify correctly");
        println!("  Different signatures, but both mathematically valid!");
    } else {
        println!("✗ Verification failed (sig1: {}, sig2: {})", valid1, valid2);
        return Err("Signature verification failed".into());
    }

    println!();
    Ok(())
}

/// Demonstrates that different modes produce valid signatures
///
/// Shows that signatures from both modes are equally valid, just with
/// different properties regarding reproducibility.
fn demo_verification() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══ Cross-Mode Verification ═══\n");

    // Generate a key pair
    let (public_key, private_key) = key_gen(ParameterSet::MlDsa65)?;

    let message = b"Test message for cross-mode verification";
    let context = b"example-app-v1";

    // Sign with both modes
    let det_sig = sign(&private_key, message, context, SigningMode::Deterministic)?;
    let hedged_sig = sign(&private_key, message, context, SigningMode::Hedged)?;

    println!("✓ Signed message with both modes");
    println!("  Context: \"{}\"", String::from_utf8_lossy(context));

    // Verify both signatures
    let det_valid = verify(&public_key, message, &det_sig, context)?;
    let hedged_valid = verify(&public_key, message, &hedged_sig, context)?;

    if det_valid && hedged_valid {
        println!("✓ Both signatures verify correctly");
        println!("  Deterministic: {}, Hedged: {}", det_valid, hedged_valid);
    } else {
        println!("✗ Verification failed");
        println!("  Deterministic: {}, Hedged: {}", det_valid, hedged_valid);
        return Err("Signature verification failed".into());
    }

    // Verify that wrong context fails
    let wrong_context = b"different-context";
    let det_wrong = verify(&public_key, message, &det_sig, wrong_context)?;

    if !det_wrong {
        println!("✓ Signature with wrong context correctly rejected");
    } else {
        println!("⚠ WARNING: Signature verified with wrong context (unexpected!)");
    }

    println!("\nKey insight: Both modes produce valid signatures!");
    println!("The choice depends on your security vs reproducibility needs.\n");

    Ok(())
}

/// Prints comprehensive usage recommendations
fn print_usage_guide() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║                      Usage Recommendations                     ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    println!("📋 DETERMINISTIC SIGNING (SigningMode::Deterministic)\n");
    println!("  Use when:");
    println!("    • Signature reproducibility is important");
    println!("    • Testing and debugging (verify exact signature values)");
    println!("    • Compliance requirements mandate deterministic signatures");
    println!("    • You need to detect if the signing process changes\n");
    println!("  Security considerations:");
    println!("    • Vulnerable if RNG was compromised during key generation");
    println!("    • May leak information through side-channels if signing");
    println!("      the same message repeatedly");
    println!("    • No protection if the signing process is compromised\n");
    println!("  Trade-off: Reproducibility vs security margin\n");

    println!("🛡️  HEDGED SIGNING (SigningMode::Hedged) - RECOMMENDED\n");
    println!("  Use when:");
    println!("    • Production environments (recommended default)");
    println!("    • Maximum security is required");
    println!("    • Protecting against unknown future vulnerabilities");
    println!("    • General-purpose digital signatures\n");
    println!("  Security benefits:");
    println!("    • Defense-in-depth against RNG failures");
    println!("    • Protection against side-channel attacks");
    println!("    • Extra security margin for long-term protection");
    println!("    • Randomized signatures prevent timing analysis\n");
    println!("  Trade-off: Extra security vs non-reproducibility\n");

    println!("💡 BEST PRACTICES\n");
    println!("  1. Use hedged mode for production unless you have a specific");
    println!("     reason to use deterministic mode");
    println!("  2. Always use context strings for domain separation");
    println!("  3. Never reuse keys across different applications");
    println!("  4. Store private keys securely (they are auto-zeroized on drop)");
    println!("  5. Verify signatures before trusting signed messages\n");

    println!("🔒 SECURITY NOTES\n");
    println!("  • Both modes are secure when implemented correctly");
    println!("  • Hedged mode provides additional defense layers");
    println!("  • The choice doesn't affect signature verification");
    println!("  • ML-DSA is quantum-resistant in both modes");
    println!("  • FIPS 204 recommends hedged mode for most applications\n");

    println!("📚 REFERENCES\n");
    println!("  • FIPS 204 Section 5.4 - Signature Generation Modes");
    println!("  • Hedged DSA: https://doi.org/10.1007/978-3-642-40041-4_18");
    println!("  • NIST Post-Quantum Cryptography Standardization\n");
}

/// Helper function to display hex preview of bytes
fn hex_preview(bytes: &[u8], len: usize) -> String {
    let preview_bytes = &bytes[..len.min(bytes.len())];
    preview_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}
