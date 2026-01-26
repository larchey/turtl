//! ML-KEM Basic Usage Example
//!
//! This example demonstrates the basic usage of TURTL's ML-KEM (Key Encapsulation Mechanism)
//! implementation, which provides post-quantum key encapsulation according to NIST FIPS 203.
//!
//! # What This Example Demonstrates
//!
//! - Key generation for all three parameter sets (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
//! - Encapsulation (sender generates ciphertext and shared secret from public key)
//! - Decapsulation (receiver recovers shared secret from ciphertext using private key)
//! - Verification that both parties derive the same shared secret
//!
//! # Understanding ML-KEM Parameter Sets
//!
//! - **ML-KEM-512**: Security Category 1 (AES-128 equivalent) - smallest keys/ciphertext
//! - **ML-KEM-768**: Security Category 3 (AES-192 equivalent) - recommended default
//! - **ML-KEM-1024**: Security Category 5 (AES-256 equivalent) - maximum security
//!
//! # How ML-KEM Works
//!
//! ML-KEM is a Key Encapsulation Mechanism (KEM) - a cryptographic primitive for establishing
//! shared secrets between two parties. Unlike traditional key exchange (like Diffie-Hellman),
//! a KEM is asymmetric:
//!
//! 1. **Key Generation** (Receiver): Generate a public/private key pair
//! 2. **Encapsulation** (Sender): Use the public key to generate a random shared secret
//!    and a ciphertext that encapsulates it
//! 3. **Decapsulation** (Receiver): Use the private key to extract the shared secret
//!    from the ciphertext
//!
//! Both parties end up with the same 32-byte shared secret, which can be used as a
//! symmetric encryption key or input to a key derivation function (KDF).
//!
//! # Security Features
//!
//! - **Post-Quantum**: Secure against both classical and quantum computer attacks
//! - **Constant-Time**: Resistant to timing side-channel attacks
//! - **Implicit Rejection**: Invalid ciphertexts produce pseudorandom secrets instead of errors
//! - **Automatic Zeroization**: Sensitive data is securely erased from memory when dropped
//!
//! # Run This Example
//!
//! ```bash
//! cargo run --example kem_basic
//! ```

use turtl::kem::{decapsulate, encapsulate, key_gen, ParameterSet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔═══════════════════════════════════════════════════════╗");
    println!("║        ML-KEM Basic Usage Example                    ║");
    println!("║   Post-Quantum Key Encapsulation (FIPS 203)          ║");
    println!("╚═══════════════════════════════════════════════════════╝\n");

    // Demonstrate each parameter set
    demo_kem_512()?;
    println!("\n{}\n", "─".repeat(60));

    demo_kem_768()?;
    println!("\n{}\n", "─".repeat(60));

    demo_kem_1024()?;
    println!("\n{}\n", "─".repeat(60));

    // Demonstrate key sizes comparison
    demo_size_comparison()?;

    println!("\n✅ All demonstrations completed successfully!");
    println!("\nKey Takeaways:");
    println!("  • ML-KEM enables secure key establishment against quantum attacks");
    println!("  • Three parameter sets offer different security/size trade-offs");
    println!("  • ML-KEM-768 is recommended for most applications");
    println!("  • Shared secrets are always 32 bytes regardless of parameter set");
    println!("  • Keys and ciphertexts are larger than classical schemes but quantum-resistant");

    Ok(())
}

/// Demonstrate ML-KEM-512 (Security Category 1 - comparable to AES-128)
fn demo_kem_512() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══ ML-KEM-512 (Security Category 1) ═══");
    println!("Security Level: Comparable to AES-128 (128-bit security)");
    println!(
        "Use Case: Bandwidth-constrained applications requiring AES-128 equivalent security\n"
    );

    // Step 1: Key Generation (performed by the receiver, Bob)
    println!("1. Key Generation (Bob)...");
    let (public_key, private_key) = key_gen(ParameterSet::MlKem512)?;

    println!("   ✓ Public key:  {} bytes", public_key.as_bytes().len());
    println!("   ✓ Private key: {} bytes", private_key.as_bytes().len());
    println!("   → Bob shares his public key with Alice");

    // Step 2: Encapsulation (performed by the sender, Alice)
    println!("\n2. Encapsulation (Alice)...");
    println!("   → Alice uses Bob's public key to generate a shared secret");
    let (ciphertext, shared_secret_alice) = encapsulate(&public_key)?;

    println!("   ✓ Ciphertext:     {} bytes", ciphertext.as_bytes().len());
    println!(
        "   ✓ Shared secret:  {} bytes",
        shared_secret_alice.as_bytes().len()
    );
    println!("   → Alice sends the ciphertext to Bob (the shared secret stays private)");

    // Step 3: Decapsulation (performed by the receiver, Bob)
    println!("\n3. Decapsulation (Bob)...");
    println!("   → Bob uses his private key to extract the shared secret from the ciphertext");
    let shared_secret_bob = decapsulate(&private_key, &ciphertext)?;

    println!(
        "   ✓ Shared secret:  {} bytes",
        shared_secret_bob.as_bytes().len()
    );

    // Step 4: Verify that both parties have the same shared secret
    println!("\n4. Verification...");
    if shared_secret_alice.as_bytes() == shared_secret_bob.as_bytes() {
        println!("   ✅ Success! Both parties derived the same shared secret");
        println!("   → This shared secret can now be used for symmetric encryption");
    } else {
        println!("   ❌ Error! Shared secrets do not match");
        return Err("Shared secret mismatch".into());
    }

    // Display a snippet of the shared secret (first 8 bytes for demonstration)
    print!("   → Shared secret (first 8 bytes): ");
    for byte in &shared_secret_alice.as_bytes()[..8] {
        print!("{:02x}", byte);
    }
    println!("...");

    Ok(())
}

/// Demonstrate ML-KEM-768 (Security Category 3 - comparable to AES-192)
fn demo_kem_768() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══ ML-KEM-768 (Security Category 3) ═══");
    println!("Security Level: Comparable to AES-192 (192-bit security)");
    println!("Use Case: Recommended default for most applications\n");

    // Step 1: Key Generation (performed by the receiver, Bob)
    println!("1. Key Generation (Bob)...");
    let (public_key, private_key) = key_gen(ParameterSet::MlKem768)?;

    println!("   ✓ Public key:  {} bytes", public_key.as_bytes().len());
    println!("   ✓ Private key: {} bytes", private_key.as_bytes().len());
    println!("   → Bob shares his public key with Alice");

    // Step 2: Encapsulation (performed by the sender, Alice)
    println!("\n2. Encapsulation (Alice)...");
    println!("   → Alice uses Bob's public key to generate a shared secret");
    let (ciphertext, shared_secret_alice) = encapsulate(&public_key)?;

    println!("   ✓ Ciphertext:     {} bytes", ciphertext.as_bytes().len());
    println!(
        "   ✓ Shared secret:  {} bytes",
        shared_secret_alice.as_bytes().len()
    );
    println!("   → Alice sends the ciphertext to Bob (the shared secret stays private)");

    // Step 3: Decapsulation (performed by the receiver, Bob)
    println!("\n3. Decapsulation (Bob)...");
    println!("   → Bob uses his private key to extract the shared secret from the ciphertext");
    let shared_secret_bob = decapsulate(&private_key, &ciphertext)?;

    println!(
        "   ✓ Shared secret:  {} bytes",
        shared_secret_bob.as_bytes().len()
    );

    // Step 4: Verify that both parties have the same shared secret
    println!("\n4. Verification...");
    if shared_secret_alice.as_bytes() == shared_secret_bob.as_bytes() {
        println!("   ✅ Success! Both parties derived the same shared secret");
        println!("   → This shared secret can now be used for symmetric encryption");
    } else {
        println!("   ❌ Error! Shared secrets do not match");
        return Err("Shared secret mismatch".into());
    }

    // Display a snippet of the shared secret (first 8 bytes for demonstration)
    print!("   → Shared secret (first 8 bytes): ");
    for byte in &shared_secret_alice.as_bytes()[..8] {
        print!("{:02x}", byte);
    }
    println!("...");

    Ok(())
}

/// Demonstrate ML-KEM-1024 (Security Category 5 - comparable to AES-256)
fn demo_kem_1024() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══ ML-KEM-1024 (Security Category 5) ═══");
    println!("Security Level: Comparable to AES-256 (256-bit security)");
    println!("Use Case: Maximum security for high-value or long-term protection\n");

    // Step 1: Key Generation (performed by the receiver, Bob)
    println!("1. Key Generation (Bob)...");
    let (public_key, private_key) = key_gen(ParameterSet::MlKem1024)?;

    println!("   ✓ Public key:  {} bytes", public_key.as_bytes().len());
    println!("   ✓ Private key: {} bytes", private_key.as_bytes().len());
    println!("   → Bob shares his public key with Alice");

    // Step 2: Encapsulation (performed by the sender, Alice)
    println!("\n2. Encapsulation (Alice)...");
    println!("   → Alice uses Bob's public key to generate a shared secret");
    let (ciphertext, shared_secret_alice) = encapsulate(&public_key)?;

    println!("   ✓ Ciphertext:     {} bytes", ciphertext.as_bytes().len());
    println!(
        "   ✓ Shared secret:  {} bytes",
        shared_secret_alice.as_bytes().len()
    );
    println!("   → Alice sends the ciphertext to Bob (the shared secret stays private)");

    // Step 3: Decapsulation (performed by the receiver, Bob)
    println!("\n3. Decapsulation (Bob)...");
    println!("   → Bob uses his private key to extract the shared secret from the ciphertext");
    let shared_secret_bob = decapsulate(&private_key, &ciphertext)?;

    println!(
        "   ✓ Shared secret:  {} bytes",
        shared_secret_bob.as_bytes().len()
    );

    // Step 4: Verify that both parties have the same shared secret
    println!("\n4. Verification...");
    if shared_secret_alice.as_bytes() == shared_secret_bob.as_bytes() {
        println!("   ✅ Success! Both parties derived the same shared secret");
        println!("   → This shared secret can now be used for symmetric encryption");
    } else {
        println!("   ❌ Error! Shared secrets do not match");
        return Err("Shared secret mismatch".into());
    }

    // Display a snippet of the shared secret (first 8 bytes for demonstration)
    print!("   → Shared secret (first 8 bytes): ");
    for byte in &shared_secret_alice.as_bytes()[..8] {
        print!("{:02x}", byte);
    }
    println!("...");

    Ok(())
}

/// Demonstrate size comparison across all parameter sets
fn demo_size_comparison() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══ Parameter Set Size Comparison ═══\n");
    println!(
        "{:<15} {:<12} {:<12} {:<12} {:<12}",
        "Parameter Set", "Public Key", "Private Key", "Ciphertext", "Shared Secret"
    );
    println!("{}", "─".repeat(60));

    // ML-KEM-512
    let param_512 = ParameterSet::MlKem512;
    println!(
        "{:<15} {:>10} B {:>10} B {:>10} B {:>11} B",
        "ML-KEM-512",
        param_512.public_key_size(),
        param_512.private_key_size(),
        param_512.ciphertext_size(),
        param_512.shared_secret_size()
    );

    // ML-KEM-768
    let param_768 = ParameterSet::MlKem768;
    println!(
        "{:<15} {:>10} B {:>10} B {:>10} B {:>11} B",
        "ML-KEM-768",
        param_768.public_key_size(),
        param_768.private_key_size(),
        param_768.ciphertext_size(),
        param_768.shared_secret_size()
    );

    // ML-KEM-1024
    let param_1024 = ParameterSet::MlKem1024;
    println!(
        "{:<15} {:>10} B {:>10} B {:>10} B {:>11} B",
        "ML-KEM-1024",
        param_1024.public_key_size(),
        param_1024.private_key_size(),
        param_1024.ciphertext_size(),
        param_1024.shared_secret_size()
    );

    println!("\nComparison with Classical Cryptography:");
    println!("  • RSA-2048 public key:  ~294 bytes");
    println!("  • RSA-2048 private key: ~1704 bytes");
    println!("  • ECDH P-256 public key: ~65 bytes");
    println!("  • ML-KEM offers post-quantum security with larger but still practical sizes");

    Ok(())
}
