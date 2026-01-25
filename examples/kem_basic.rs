//! ML-KEM Basic Usage Example
//!
//! ⚠️  **STATUS: NON-FUNCTIONAL - BLOCKED BY CRITICAL BUG**
//!
//! This example demonstrates the fundamental operations of ML-KEM (Module-Lattice-Based
//! Key-Encapsulation Mechanism) for all three parameter sets defined in FIPS 203.
//!
//! **KNOWN ISSUE:** ML-KEM implementation currently uses wrong modulus (q=8380417 from ML-DSA
//! instead of q=3329). This causes key generation to fail. See ML_KEM_BUG_REPORT.md for details.
//!
//! This example is structurally complete and demonstrates proper API usage. It will work
//! once the underlying k_pke implementation is fixed.
//!
//! # Key Encapsulation Mechanism (KEM) Overview
//!
//! A KEM is used to establish a shared secret between two parties (traditionally called
//! Alice and Bob). The protocol works as follows:
//!
//! 1. **Key Generation (Bob)**: Bob generates a keypair consisting of a public key (pk)
//!    and a private key (sk). He shares the public key with Alice.
//!
//! 2. **Encapsulation (Alice)**: Alice uses Bob's public key to generate a random shared
//!    secret (K) and a ciphertext (ct). She sends the ciphertext to Bob.
//!
//! 3. **Decapsulation (Bob)**: Bob uses his private key and the received ciphertext to
//!    recover the same shared secret (K).
//!
//! Both parties now have the same shared secret which can be used for secure communication.

use turtl::kem::{self, ParameterSet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║           ML-KEM Basic Usage Example                         ║");
    println!("║           FIPS 203 Implementation                            ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    // Demonstrate each parameter set
    demo_kem_512()?;
    println!();
    demo_kem_768()?;
    println!();
    demo_kem_1024()?;

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║  All parameter sets completed successfully!                  ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");

    Ok(())
}

/// Demonstrates ML-KEM-512 (Security Category 1, equivalent to AES-128)
///
/// This is the smallest and fastest parameter set, suitable for applications
/// where security level 1 is sufficient and performance/bandwidth is critical.
fn demo_kem_512() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("  ML-KEM-512 (Security Category 1 - AES-128 equivalent)");
    println!("═══════════════════════════════════════════════════════════════");

    let param_set = ParameterSet::MlKem512;
    print_parameter_info(&param_set);

    // Run the KEM protocol
    run_kem_protocol(param_set)?;

    Ok(())
}

/// Demonstrates ML-KEM-768 (Security Category 3, equivalent to AES-192)
///
/// This is the recommended parameter set for most applications, providing
/// a good balance between security and performance.
fn demo_kem_768() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("  ML-KEM-768 (Security Category 3 - AES-192 equivalent)");
    println!("═══════════════════════════════════════════════════════════════");

    let param_set = ParameterSet::MlKem768;
    print_parameter_info(&param_set);

    // Run the KEM protocol
    run_kem_protocol(param_set)?;

    Ok(())
}

/// Demonstrates ML-KEM-1024 (Security Category 5, equivalent to AES-256)
///
/// This is the highest security parameter set, suitable for applications
/// requiring the maximum security level at the cost of larger keys and ciphertexts.
fn demo_kem_1024() -> Result<(), Box<dyn std::error::Error>> {
    println!("═══════════════════════════════════════════════════════════════");
    println!("  ML-KEM-1024 (Security Category 5 - AES-256 equivalent)");
    println!("═══════════════════════════════════════════════════════════════");

    let param_set = ParameterSet::MlKem1024;
    print_parameter_info(&param_set);

    // Run the KEM protocol
    run_kem_protocol(param_set)?;

    Ok(())
}

/// Display parameter set information
fn print_parameter_info(param_set: &ParameterSet) {
    println!("\n📋 Parameter Set Information:");
    println!("   Security Category:    {}", param_set.security_category());
    println!("   Matrix Dimension (k): {}", param_set.k());
    println!("   Public Key Size:      {} bytes", param_set.public_key_size());
    println!("   Private Key Size:     {} bytes", param_set.private_key_size());
    println!("   Ciphertext Size:      {} bytes", param_set.ciphertext_size());
    println!("   Shared Secret Size:   {} bytes", param_set.shared_secret_size());
    println!();
}

/// Run the complete KEM protocol for a given parameter set
fn run_kem_protocol(param_set: ParameterSet) -> Result<(), Box<dyn std::error::Error>> {
    // ┌───────────────────────────────────────────────────────────────┐
    // │ STEP 1: Key Generation (Bob's side)                          │
    // └───────────────────────────────────────────────────────────────┘
    println!("🔑 Step 1: Key Generation (Bob)");
    println!("   Bob generates a keypair...");

    let (public_key, private_key) = kem::key_gen(param_set)?;

    println!("   ✓ Public key generated:  {} bytes", public_key.as_bytes().len());
    println!("   ✓ Private key generated: {} bytes", private_key.as_bytes().len());
    println!("   → Bob keeps the private key secret");
    println!("   → Bob shares the public key with Alice");
    println!();

    // ┌───────────────────────────────────────────────────────────────┐
    // │ STEP 2: Encapsulation (Alice's side)                         │
    // └───────────────────────────────────────────────────────────────┘
    println!("📦 Step 2: Encapsulation (Alice)");
    println!("   Alice receives Bob's public key...");
    println!("   Alice generates a shared secret and encapsulates it...");

    let (ciphertext, shared_secret_alice) = kem::encapsulate(&public_key)?;

    println!("   ✓ Shared secret generated: {} bytes", shared_secret_alice.as_bytes().len());
    println!("   ✓ Ciphertext created:      {} bytes", ciphertext.as_bytes().len());
    println!("   → Alice keeps the shared secret");
    println!("   → Alice sends the ciphertext to Bob");
    println!();

    // ┌───────────────────────────────────────────────────────────────┐
    // │ STEP 3: Decapsulation (Bob's side)                           │
    // └───────────────────────────────────────────────────────────────┘
    println!("🔓 Step 3: Decapsulation (Bob)");
    println!("   Bob receives Alice's ciphertext...");
    println!("   Bob uses his private key to recover the shared secret...");

    let shared_secret_bob = kem::decapsulate(&private_key, &ciphertext)?;

    println!("   ✓ Shared secret recovered: {} bytes", shared_secret_bob.as_bytes().len());
    println!();

    // ┌───────────────────────────────────────────────────────────────┐
    // │ STEP 4: Verification                                          │
    // └───────────────────────────────────────────────────────────────┘
    println!("✅ Step 4: Verification");
    println!("   Comparing shared secrets...");

    // Verify that both parties have the same shared secret
    if shared_secret_alice == shared_secret_bob {
        println!("   ✓ SUCCESS: Shared secrets match!");
        println!("   → Alice and Bob can now use this shared secret for secure communication");

        // Display first few bytes of the shared secret (for demonstration)
        let secret_preview = &shared_secret_alice.as_bytes()[..8];
        println!("   → Shared secret (first 8 bytes): {:02x?}", secret_preview);
    } else {
        return Err("ERROR: Shared secrets do not match!".into());
    }

    Ok(())
}
