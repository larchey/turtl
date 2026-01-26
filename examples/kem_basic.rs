//! ML-KEM Basic Usage Example
//!
//! This example demonstrates the fundamental operations of the ML-KEM (Module-Lattice-Based
//! Key-Encapsulation Mechanism) algorithm as specified in NIST FIPS 203.
//!
//! ML-KEM is a post-quantum cryptographic algorithm designed to establish shared secrets
//! between two parties over an insecure channel. It provides security against both classical
//! and quantum computer attacks.
//!
//! ## What is a Key Encapsulation Mechanism (KEM)?
//!
//! A KEM is used to securely establish a shared secret between two parties:
//! 1. **Bob** generates a key pair (public key and private key)
//! 2. **Bob** shares his public key with Alice
//! 3. **Alice** uses Bob's public key to encapsulate a random shared secret, producing a ciphertext
//! 4. **Alice** sends the ciphertext to Bob
//! 5. **Bob** uses his private key to decapsulate the ciphertext, recovering the same shared secret
//!
//! ## Parameter Sets
//!
//! ML-KEM defines three parameter sets with different security levels:
//! - **ML-KEM-512**: Security Category 1 (equivalent to AES-128) - Fast, lower security
//! - **ML-KEM-768**: Security Category 3 (equivalent to AES-192) - Balanced security/performance
//! - **ML-KEM-1024**: Security Category 5 (equivalent to AES-256) - Maximum security
//!
//! ## Running this example
//!
//! ```bash
//! cargo run --example kem_basic
//! ```

use turtl::kem::{self, ParameterSet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║         ML-KEM Basic Usage Example               ║");
    println!("║  Post-Quantum Key Encapsulation Mechanism        ║");
    println!("╚═══════════════════════════════════════════════════╝\n");

    println!("This example demonstrates ML-KEM key encapsulation for all three parameter sets.\n");
    println!("Each parameter set offers a different security level and performance trade-off.\n");

    // Demonstrate each parameter set
    demo_kem_512()?;
    println!();
    demo_kem_768()?;
    println!();
    demo_kem_1024()?;

    println!("\n╔═══════════════════════════════════════════════════╗");
    println!("║              Example Complete!                    ║");
    println!("╚═══════════════════════════════════════════════════╝");

    Ok(())
}

/// Demonstrate ML-KEM-512 (Security Category 1)
fn demo_kem_512() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("  ML-KEM-512 (Security Category 1 - AES-128 equivalent)");
    println!("═══════════════════════════════════════════════════════════════");

    let param_set = ParameterSet::MlKem512;

    // Display parameter information
    println!("\nParameter Information:");
    println!("  Security Category:  {}", param_set.security_category());
    println!("  Matrix Dimension:   k = {}", param_set.k());
    println!("  Public Key Size:    {} bytes", param_set.public_key_size());
    println!("  Private Key Size:   {} bytes", param_set.private_key_size());
    println!("  Ciphertext Size:    {} bytes", param_set.ciphertext_size());
    println!("  Shared Secret Size: {} bytes", param_set.shared_secret_size());

    // Step 1: Key Generation (Bob generates a key pair)
    println!("\n[Step 1] Bob generates a key pair...");
    let (public_key, private_key) = kem::key_gen(param_set)?;
    println!("  ✓ Key pair generated successfully");
    println!("    - Public key:  {} bytes", public_key.as_bytes().len());
    println!("    - Private key: {} bytes (kept secret by Bob)", private_key.as_bytes().len());

    // Step 2: Encapsulation (Alice uses Bob's public key)
    println!("\n[Step 2] Alice receives Bob's public key and encapsulates a shared secret...");
    let (ciphertext, alice_shared_secret) = kem::encapsulate(&public_key)?;
    println!("  ✓ Encapsulation successful");
    println!("    - Ciphertext:     {} bytes (Alice sends this to Bob)", ciphertext.as_bytes().len());
    println!("    - Shared secret:  {} bytes (Alice keeps this secret)", alice_shared_secret.as_bytes().len());

    // Step 3: Decapsulation (Bob uses his private key)
    println!("\n[Step 3] Bob receives the ciphertext and decapsulates it...");
    let bob_shared_secret = kem::decapsulate(&private_key, &ciphertext)?;
    println!("  ✓ Decapsulation successful");
    println!("    - Shared secret:  {} bytes (Bob's recovered secret)", bob_shared_secret.as_bytes().len());

    // Step 4: Verification
    println!("\n[Step 4] Verify that both parties have the same shared secret...");
    if alice_shared_secret == bob_shared_secret {
        println!("  ✓ SUCCESS! Alice and Bob have identical shared secrets.");
        println!("    They can now use this secret for symmetric encryption (e.g., AES).");

        // Display first few bytes for demonstration
        let alice_bytes = alice_shared_secret.as_bytes();
        let bob_bytes = bob_shared_secret.as_bytes();
        println!("\n    First 16 bytes of shared secret:");
        print!("    Alice: ");
        for b in &alice_bytes[..16] {
            print!("{:02x}", b);
        }
        println!();
        print!("    Bob:   ");
        for b in &bob_bytes[..16] {
            print!("{:02x}", b);
        }
        println!();
    } else {
        println!("  ✗ ERROR! Shared secrets do not match.");
        return Err("Shared secret mismatch".into());
    }

    Ok(())
}

/// Demonstrate ML-KEM-768 (Security Category 3)
fn demo_kem_768() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("  ML-KEM-768 (Security Category 3 - AES-192 equivalent)");
    println!("═══════════════════════════════════════════════════════════════");

    let param_set = ParameterSet::MlKem768;

    // Display parameter information
    println!("\nParameter Information:");
    println!("  Security Category:  {}", param_set.security_category());
    println!("  Matrix Dimension:   k = {}", param_set.k());
    println!("  Public Key Size:    {} bytes", param_set.public_key_size());
    println!("  Private Key Size:   {} bytes", param_set.private_key_size());
    println!("  Ciphertext Size:    {} bytes", param_set.ciphertext_size());
    println!("  Shared Secret Size: {} bytes", param_set.shared_secret_size());

    // Simplified demonstration for subsequent parameter sets
    println!("\n[Key Exchange Process]");

    // Step 1: Bob generates keys
    println!("  1. Bob generates key pair...");
    let (public_key, private_key) = kem::key_gen(param_set)?;
    println!("     ✓ Generated");

    // Step 2: Alice encapsulates
    println!("  2. Alice encapsulates shared secret using Bob's public key...");
    let (ciphertext, alice_shared_secret) = kem::encapsulate(&public_key)?;
    println!("     ✓ Encapsulated");

    // Step 3: Bob decapsulates
    println!("  3. Bob decapsulates the ciphertext...");
    let bob_shared_secret = kem::decapsulate(&private_key, &ciphertext)?;
    println!("     ✓ Decapsulated");

    // Step 4: Verify
    println!("  4. Verifying shared secrets match...");
    if alice_shared_secret == bob_shared_secret {
        println!("     ✓ SUCCESS! Shared secrets match.");

        // Display first few bytes
        let alice_bytes = alice_shared_secret.as_bytes();
        print!("\n     Shared secret (first 16 bytes): ");
        for b in &alice_bytes[..16] {
            print!("{:02x}", b);
        }
        println!();
    } else {
        println!("     ✗ ERROR! Shared secrets do not match.");
        return Err("Shared secret mismatch".into());
    }

    Ok(())
}

/// Demonstrate ML-KEM-1024 (Security Category 5)
fn demo_kem_1024() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("  ML-KEM-1024 (Security Category 5 - AES-256 equivalent)");
    println!("═══════════════════════════════════════════════════════════════");

    let param_set = ParameterSet::MlKem1024;

    // Display parameter information
    println!("\nParameter Information:");
    println!("  Security Category:  {}", param_set.security_category());
    println!("  Matrix Dimension:   k = {}", param_set.k());
    println!("  Public Key Size:    {} bytes", param_set.public_key_size());
    println!("  Private Key Size:   {} bytes", param_set.private_key_size());
    println!("  Ciphertext Size:    {} bytes", param_set.ciphertext_size());
    println!("  Shared Secret Size: {} bytes", param_set.shared_secret_size());

    // Simplified demonstration
    println!("\n[Key Exchange Process]");

    // Step 1: Bob generates keys
    println!("  1. Bob generates key pair...");
    let (public_key, private_key) = kem::key_gen(param_set)?;
    println!("     ✓ Generated");

    // Step 2: Alice encapsulates
    println!("  2. Alice encapsulates shared secret using Bob's public key...");
    let (ciphertext, alice_shared_secret) = kem::encapsulate(&public_key)?;
    println!("     ✓ Encapsulated");

    // Step 3: Bob decapsulates
    println!("  3. Bob decapsulates the ciphertext...");
    let bob_shared_secret = kem::decapsulate(&private_key, &ciphertext)?;
    println!("     ✓ Decapsulated");

    // Step 4: Verify
    println!("  4. Verifying shared secrets match...");
    if alice_shared_secret == bob_shared_secret {
        println!("     ✓ SUCCESS! Shared secrets match.");

        // Display first few bytes
        let alice_bytes = alice_shared_secret.as_bytes();
        print!("\n     Shared secret (first 16 bytes): ");
        for b in &alice_bytes[..16] {
            print!("{:02x}", b);
        }
        println!();
    } else {
        println!("     ✗ ERROR! Shared secrets do not match.");
        return Err("Shared secret mismatch".into());
    }

    println!("\nNote: ML-KEM-1024 offers the highest security level but also has");
    println!("      larger key sizes and slightly slower performance.");

    Ok(())
}
