# TURTL Security Documentation

**Version:** 1.0
**Last Updated:** 2026-01-25
**Status:** Pre-Production

## Table of Contents

1. [Threat Model](#1-threat-model)
2. [Security Features](#2-security-features)
3. [Usage Guidelines](#3-usage-guidelines)
4. [Known Limitations](#4-known-limitations)
5. [Security Reporting](#5-security-reporting)
6. [Compliance and Standards](#6-compliance-and-standards)

---

## 1. Threat Model

This section describes the security threats that TURTL is designed to protect against, as well as threats that are explicitly out of scope.

### 1.1 Protected Threats

TURTL implements countermeasures against the following attack vectors:

#### 1.1.1 Quantum Computer Attacks

**Threat:** Quantum computers running Shor's algorithm can efficiently break classical public-key cryptography (RSA, ECC) by solving the integer factorization and discrete logarithm problems in polynomial time.

**Protection:** TURTL implements ML-KEM and ML-DSA, which are based on the hardness of lattice problems (Module Learning With Errors for ML-KEM, Module Short Integer Solution for ML-DSA). These problems are believed to be resistant to quantum attacks.

**Security Levels:**
- **ML-KEM-512 / ML-DSA-44**: NIST Security Category 1-2 (equivalent to 128-bit classical security)
- **ML-KEM-768 / ML-DSA-65**: NIST Security Category 3 (equivalent to 192-bit classical security)
- **ML-KEM-1024 / ML-DSA-87**: NIST Security Category 5 (equivalent to 256-bit classical security)

**References:**
- FIPS 203 Section 9: Security Considerations
- FIPS 204 Section 10: Security Considerations

#### 1.1.2 Classical Cryptanalysis

**Threat:** Attackers may attempt to break the cryptographic schemes through mathematical cryptanalysis, exploiting weaknesses in the underlying algorithms.

**Protection:** TURTL strictly follows NIST FIPS 203 and FIPS 204 specifications, which have undergone extensive peer review and cryptanalysis during the NIST Post-Quantum Cryptography standardization process (2016-2024).

**Cryptanalytic Considerations:**
- **Lattice reduction attacks:** Security parameters are chosen to resist known lattice reduction algorithms (BKZ, sieving)
- **Algebraic attacks:** The modulus q and polynomial degree n are chosen to prevent algebraic vulnerabilities
- **Key recovery attacks:** ML-DSA includes signature rejection sampling to prevent key leakage through signature distribution analysis

#### 1.1.3 Side-Channel Attacks (Software)

**Threat:** Attackers with access to timing information, cache access patterns, or other observable side-channels may extract secret key material.

**Protection:** TURTL implements several software-based side-channel countermeasures:

##### Timing Attack Resistance

All operations that process secret data are implemented in **constant time**, meaning execution time does not depend on secret values.

**Constant-Time Primitives (src/security/constant_time.rs):**
- `ct_cmov()` - Conditional move without branching
- `ct_cswap()` - Conditional swap without branching
- `ct_select()` - Constant-time selection between two values
- `ct_eq_*()` - Constant-time equality comparison
- `ct_is_zero_*()` - Constant-time zero testing

**Critical Constant-Time Operations:**
- ML-KEM decapsulation (implicit rejection)
- ML-DSA signature verification
- Polynomial coefficient comparisons
- Secret-dependent array indexing (replaced with masked operations)

**Limitations:** Constant-time guarantees depend on compiler optimizations not introducing timing variations. See Section 4.2.

##### Cache-Timing Attack Resistance

**Threat:** Attackers may observe cache hit/miss patterns to infer secret data.

**Protection:**
- All array accesses that depend on secrets use constant-time indexing
- No secret-dependent lookups into large tables
- NTT precomputed constants are public data

**Note:** Cache-timing resistance is best-effort. Full protection against cache attacks requires hardware support (e.g., constant-time instruction execution).

#### 1.1.4 Fault Injection Attacks

**Threat:** Attackers with physical access may inject faults (via voltage glitching, clock manipulation, laser attacks, etc.) to induce computational errors that leak secret information.

**Protection:** TURTL implements fault detection countermeasures as recommended by FIPS 203/204:

##### Re-encryption Verification (ML-KEM)

During decapsulation, TURTL re-encrypts the decrypted message and verifies that it matches the original ciphertext:

```rust
// Simplified pseudocode
fn decapsulate(sk: &PrivateKey, ct: &Ciphertext) -> SharedSecret {
    let m = decrypt_internal(sk, ct);  // Decrypt ciphertext
    let ct_prime = encrypt_internal(pk, m);  // Re-encrypt

    if ct != ct_prime {  // Constant-time comparison
        // Fault detected, return implicit rejection value
        return hash(sk.z || ct);
    }

    return hash(m || hash(ct));
}
```

**Purpose:** Detects faults injected during decryption that could leak the secret key.

##### Double-Verification (ML-DSA)

Signature verification computations can be performed twice to detect faults:

```rust
pub fn verify_signature_checks(result1: bool, result2: bool) -> Result<()> {
    if result1 != result2 {
        return Err(Error::FaultDetected);
    }
    Ok(())
}
```

##### Bounds Checking

All polynomial coefficients and intermediate values are validated to be within expected ranges:

```rust
pub fn verify_bounds<T: PartialOrd>(value: T, min: T, max: T) -> Result<()> {
    if value < min || value > max {
        return Err(Error::FaultDetected);
    }
    Ok(())
}
```

**Purpose:** Detects faults that cause coefficients to exceed valid ranges (mod q).

#### 1.1.5 Memory Disclosure Attacks

**Threat:** Attackers may gain access to process memory through:
- Cold boot attacks (physical RAM extraction)
- Memory dumps (core dumps, hibernation files)
- Buffer over-reads (Heartbleed-style vulnerabilities)
- Memory scanning malware

**Protection:** TURTL implements automatic memory zeroization for all sensitive data:

**Zeroized Types:**
- `PrivateKey` (both ML-KEM and ML-DSA)
- `SharedSecret` (ML-KEM)
- `Polynomial` (when containing secret coefficients)
- Intermediate values in signing/decryption

**Implementation:**
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    param: ParameterSet,
    key: Vec<u8>,  // Automatically zeroed when dropped
}
```

**Guarantees:**
- Memory is overwritten with zeros before deallocation
- Prevents secrets from lingering in memory after use
- Protects against use-after-free vulnerabilities exposing secrets

**Limitations:**
- Cannot prevent memory disclosure while secrets are actively in use
- Cannot zero memory that has been swapped to disk (disable swap for high-security applications)
- Compiler optimizations may eliminate zeroization (Rust's `Zeroize` crate uses volatile writes to prevent this)

#### 1.1.6 Invalid Input Attacks

**Threat:** Attackers may provide malformed or malicious inputs to trigger undefined behavior, crashes, or security vulnerabilities.

**Protection:** TURTL validates all public-facing inputs before processing:

**Validation Checks:**
- Public key size matches parameter set
- Private key size matches parameter set
- Ciphertext size matches parameter set
- Signature size matches parameter set
- Context string length ≤ 255 bytes (ML-DSA requirement)
- Polynomial coefficients are in range [0, q)
- Parameter set consistency across operations

**Error Handling:**
All validation failures return explicit errors without processing invalid data:

```rust
pub enum Error {
    InvalidPublicKeySize,
    InvalidPrivateKeySize,
    InvalidCiphertextSize,
    InvalidSignatureSize,
    InvalidContextSize,
    PolynomialCoeffOutOfRange,
    // ... etc
}
```

---

### 1.2 Out-of-Scope Threats

TURTL does **NOT** protect against the following threats:

#### 1.2.1 Physical Attacks on Hardware

**Not Protected:**
- Differential Power Analysis (DPA)
- Simple Power Analysis (SPA)
- Electromagnetic (EM) emissions analysis
- Invasive attacks (chip decapsulation, probing)
- Laser fault injection targeting hardware circuits

**Reason:** These attacks require hardware-level countermeasures (e.g., randomized power consumption, EM shielding, tamper-resistant hardware). Software implementations cannot fully prevent these attacks.

**Recommendation:** For high-security applications requiring hardware attack resistance, deploy TURTL on tamper-resistant hardware (e.g., HSMs, secure enclaves) or use dedicated PQC hardware accelerators.

#### 1.2.2 Malware on the Execution System

**Not Protected:**
- Keyloggers capturing plaintext before encryption
- Memory scrapers reading secrets from RAM
- Process debuggers (ptrace, gdb) inspecting program state
- Rootkits modifying code or data in memory
- Side-loaded libraries (LD_PRELOAD attacks)

**Reason:** If an attacker has code execution on the system, all software-based protections are bypassable.

**Recommendation:** Ensure the execution environment is trusted through:
- Operating system security updates
- Endpoint detection and response (EDR)
- Application whitelisting
- Secure boot and measured boot
- Principle of least privilege

#### 1.2.3 Compromised Random Number Generator

**Not Protected:**
- Weak or predictable PRNG state
- Backdoored RNG (e.g., Dual_EC_DRBG-style backdoors)
- Insufficient entropy at boot time
- RNG state compromise through side-channels

**Reason:** All cryptographic security depends on high-quality randomness. TURTL uses the operating system's RNG (`rand_core::OsRng`), which relies on the OS kernel's entropy sources.

**Recommendation:**
- Ensure OS RNG is properly seeded (especially on embedded systems)
- Use hardware RNGs (RDRAND, RDSEED) when available
- Consider additional entropy sources for key generation
- For ML-DSA, use hedged signing mode to mitigate RNG failures (see Section 3.3)

#### 1.2.4 Implementation Bugs in Dependencies

**Not Protected:**
- Vulnerabilities in the `sha3` crate (SHAKE256, SHA3-256)
- Bugs in the Rust standard library
- Compiler bugs introducing vulnerabilities
- Supply chain attacks on dependencies

**Reason:** TURTL relies on external crates for hash functions and basic functionality. Bugs in these dependencies are outside TURTL's control.

**Recommendation:**
- Keep dependencies up to date
- Use `cargo audit` to check for known vulnerabilities
- Pin dependency versions for production deployments
- Review dependency code for security-critical applications

#### 1.2.5 Cryptographic Algorithm Breaks

**Not Protected:**
- Future advances in lattice reduction algorithms
- Discovery of quantum algorithms that break lattice problems
- Algebraic attacks on the Module-LWE/Module-SIS problems
- Cryptanalytic attacks on SHAKE256 or SHA3-256

**Reason:** TURTL's security relies on the assumed hardness of mathematical problems. Unexpected cryptanalytic breakthroughs could compromise security.

**Recommendation:**
- Monitor NIST announcements and cryptographic research
- Implement crypto agility (ability to switch algorithms)
- Use hybrid classical+PQC schemes during transition period
- Plan for algorithm migration if weaknesses are discovered

#### 1.2.6 Denial-of-Service (DoS) Attacks

**Not Protected:**
- Resource exhaustion through repeated signature verification
- Algorithmic complexity attacks
- Memory exhaustion from large inputs

**Reason:** TURTL is a cryptographic library, not a complete security system. DoS protection is the responsibility of the calling application.

**Recommendation:**
- Implement rate limiting on signature verification
- Validate input sizes before processing
- Use timeouts for cryptographic operations
- Monitor resource consumption

---

## 2. Security Features

This section details the security mechanisms implemented in TURTL.

### 2.1 Constant-Time Operations

#### 2.1.1 What Are Constant-Time Operations?

**Constant-time** operations execute in the same amount of time regardless of the values of secret data. This prevents **timing attacks**, where an attacker measures execution time to infer secrets.

**Example of a Timing Vulnerability:**
```rust
// INSECURE: Timing varies based on secret key
fn compare_keys(key1: &[u8], key2: &[u8]) -> bool {
    for (a, b) in key1.iter().zip(key2.iter()) {
        if a != b {
            return false;  // Early return leaks position of mismatch
        }
    }
    true
}
```

**Constant-Time Fix:**
```rust
// SECURE: Timing independent of key values
fn ct_compare_keys(key1: &[u8], key2: &[u8]) -> bool {
    let mut diff: u8 = 0;
    for (a, b) in key1.iter().zip(key2.iter()) {
        diff |= a ^ b;  // No branching
    }
    diff == 0  // Single comparison at the end
}
```

#### 2.1.2 Why Constant-Time Matters

**Case Study: Timing Attack on RSA**

In the 1990s, Paul Kocher demonstrated that RSA implementations could be broken by measuring decryption times. If decryption is faster when certain key bits are 0, an attacker can recover the entire private key bit-by-bit.

**Post-Quantum Relevance:**

Lattice-based cryptography is equally vulnerable to timing attacks. For example:
- **ML-KEM decapsulation:** If decryption failure is detected early, timing reveals information about the ciphertext's validity
- **ML-DSA verification:** If signature rejection happens quickly, timing may leak which check failed

#### 2.1.3 TURTL's Constant-Time Primitives

TURTL provides the following constant-time operations in `src/security/constant_time.rs`:

| Function | Purpose | Example Use Case |
|----------|---------|------------------|
| `ct_cmov(r, x, cond)` | Conditional move: `r = cond ? x : r` | Implicit rejection in ML-KEM |
| `ct_cswap(a, b, cond)` | Conditional swap: `if cond { swap(a, b) }` | Sorting without timing leaks |
| `ct_select(x, y, cond)` | Select: `return cond ? x : y` | Choosing between two values |
| `ct_eq(a, b)` | Equality test without branching | Key comparison |
| `ct_is_zero(x)` | Zero test without branching | Checking for zero coefficients |

**Implementation Detail:**

These functions use bitwise masking instead of conditional branches:

```rust
pub fn ct_select(x: u32, y: u32, cond: bool) -> u32 {
    let mask = if cond { 0xffffffff } else { 0 };
    (x & mask) | (y & !mask)
}
```

The `if` statement sets a mask, but both branches (`x & mask` and `y & !mask`) are always executed, ensuring constant time.

#### 2.1.4 Constant-Time Operations in TURTL

**ML-KEM Decapsulation (Implicit Rejection):**

Per FIPS 203 Section 7.3, decapsulation must use implicit rejection to achieve IND-CCA2 security:

```rust
// Simplified
let m_prime = decrypt(sk, ct);
let ct_prime = encrypt(pk, m_prime);

let fail = !ct_eq(ct, ct_prime);  // Constant-time comparison

// Constant-time selection between valid and implicit rejection
let shared_secret = if fail {
    hash(sk.z || ct)  // Implicit rejection value
} else {
    hash(m_prime || hash(ct))
};
```

**ML-DSA Signature Verification:**

Verification must not leak which check failed:

```rust
// All checks performed without early returns
let valid_norm = check_norm(z);
let valid_hint = check_hint_weight(h);
let valid_commitment = check_commitment(w1_prime, c_tilde);

// Combined check in constant time
valid_norm && valid_hint && valid_commitment
```

#### 2.1.5 Limitations of Constant-Time Guarantees

**Compiler Optimizations:**

Compilers may optimize away constant-time code patterns. For example:

```rust
let mask = if cond { 0xff } else { 0 };
let result = (x & mask) | (y & !mask);
```

Could be optimized to:
```rust
let result = if cond { x } else { y };  // NOT constant-time!
```

**Mitigation:** TURTL uses `#[inline(never)]` on security-critical functions and relies on the `zeroize` crate's volatile writes to prevent optimization.

**CPU Microarchitecture:**

Modern CPUs use speculative execution, which can introduce timing variations even in constant-time code. TURTL cannot defend against microarchitectural side-channels like Spectre.

**Recommendation:** For maximum security, run TURTL on CPUs with mitigations enabled (e.g., IBRS, STIBP).

**Operating System Interrupts:**

OS interrupts and context switches introduce timing noise. While this noise makes timing attacks harder, it does not provide reliable protection.

---

### 2.2 Memory Zeroization

#### 2.2.1 Automatic Secret Cleanup

All sensitive data types implement the `Zeroize` and `ZeroizeOnDrop` traits:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    param: ParameterSet,
    key: Vec<u8>,
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Automatically called by ZeroizeOnDrop
        self.key.zeroize();  // Overwrites with zeros
    }
}
```

**When Zeroization Occurs:**
- When a `PrivateKey` or `SharedSecret` goes out of scope
- When a `Polynomial` containing secrets is dropped
- During error handling (secrets are not leaked via error paths)

#### 2.2.2 Zeroization Guarantees

**What `Zeroize` Does:**
- Overwrites memory with zeros using volatile writes
- Prevents compiler from optimizing away the write
- Ensures secrets are cleared even in release builds

**What `Zeroize` Does NOT Do:**
- Cannot zero memory that has been swapped to disk
- Cannot zero memory in CPU registers (though they are quickly overwritten)
- Cannot zero memory that has been copied (e.g., during struct moves)

#### 2.2.3 Usage Best Practices

**Minimize Secret Lifetime:**
```rust
// GOOD: Secret exists only during operation
{
    let keypair = KeyPair::generate(ParameterSet::MlKem768)?;
    let (ct, ss) = encapsulate(&keypair.public_key())?;
    use_shared_secret(&ss);
}  // keypair and ss zeroized here

// BAD: Secret persists unnecessarily
let keypair = KeyPair::generate(ParameterSet::MlKem768)?;
// ... many lines of code ...
// keypair still in memory
```

**Disable Swapping for High-Security Applications:**
```bash
# Linux: Disable swap
sudo swapoff -a

# Or use mlock to prevent specific memory from swapping
# (Requires root or CAP_IPC_LOCK)
```

---

### 2.3 Fault Detection Mechanisms

#### 2.3.1 Re-encryption Validation (ML-KEM)

**Location:** `src/security/fault_detection.rs:verify_re_encryption()`

**Purpose:** Detects faults injected during ML-KEM decapsulation.

**How It Works:**
1. Decrypt ciphertext to recover message `m'`
2. Re-encrypt `m'` with public key to get `ct'`
3. Compare `ct'` with original ciphertext `ct` in constant time
4. If mismatch detected, return implicit rejection value instead of shared secret

**Security Property:** Prevents attacks that modify the decryption computation to leak the secret key.

**FIPS 203 Reference:** Section 7.3 (ML-KEM.Decaps)

#### 2.3.2 Double-Checking Critical Operations

**Location:** `src/security/fault_detection.rs:verify_signature_checks()`

**Purpose:** Detects transient faults in ML-DSA signature verification.

**How It Works:**
1. Perform verification computation twice
2. Compare both results in constant time
3. Return error if results differ

**Limitation:** Protects against transient faults (e.g., bit flips) but not permanent faults or malicious code modification.

#### 2.3.3 Bounds Checking

**Location:** `src/security/fault_detection.rs:verify_bounds()`

**Purpose:** Detects faults that cause values to exceed valid ranges.

**Applications:**
- Polynomial coefficient bounds: `0 ≤ coeff < q`
- Norm checks: `||z||_∞ < γ₁ - β`
- Hint weight: `||h|| ≤ ω`

**Example:**
```rust
// Verify polynomial coefficient is in range
for coeff in poly.coeffs.iter() {
    verify_bounds(*coeff, 0, q - 1)?;
}
```

---

### 2.4 No Unsafe Code

TURTL contains **zero unsafe blocks** and enforces this with:

```rust
#![forbid(unsafe_code)]
```

**Benefits:**
- Memory safety guaranteed by Rust's type system
- No buffer overflows, use-after-free, or double-free vulnerabilities
- No undefined behavior from unsafe operations

**Trade-offs:**
- May sacrifice some performance compared to unsafe optimizations
- Cannot use SIMD intrinsics (which require `unsafe`) in current version

**Future Work:** SIMD optimizations may be added behind a feature flag with careful unsafe code review.

---

## 3. Usage Guidelines

This section provides security best practices for using TURTL in your applications.

### 3.1 Secure Key Generation

#### 3.1.1 Importance of Randomness

**Critical:** All security depends on the quality of random key generation. Weak randomness leads to predictable keys and total compromise.

**TURTL's RNG:** Uses `rand_core::OsRng`, which sources entropy from:
- Linux: `/dev/urandom` (getrandom syscall)
- Windows: `BCryptGenRandom` (CNG)
- macOS/iOS: `SecRandomCopyBytes`

#### 3.1.2 Key Generation Best Practices

**Use Default RNG for Production:**
```rust
use turtl::kem::{KeyPair, ParameterSet};

// GOOD: Uses OS RNG (secure)
let keypair = KeyPair::generate(ParameterSet::MlKem768)?;
```

**Custom RNG (Advanced):**
```rust
use rand_core::{CryptoRng, RngCore};

// Only use if you have specific requirements
fn generate_with_custom_rng<R: CryptoRng + RngCore>(rng: &mut R) -> Result<KeyPair> {
    KeyPair::generate_with_rng(ParameterSet::MlKem768, rng)
}
```

**Embedded Systems Considerations:**

Embedded systems may have insufficient entropy at boot:

```rust
// GOOD: Wait for sufficient entropy
#[cfg(target_os = "none")]
fn wait_for_entropy() {
    // Poll entropy counter until sufficient randomness available
    while !has_sufficient_entropy() {
        std::thread::sleep(Duration::from_millis(100));
    }
}
```

#### 3.1.3 When to Regenerate Keys

**ML-KEM (Key Encapsulation):**
- **Ephemeral keys:** Generate new keypair for each session (forward secrecy)
- **Static keys:** Rotate periodically (e.g., every 90 days) or after suspected compromise

**ML-DSA (Signatures):**
- **Long-lived keys:** Can be used for many signatures (years)
- **Rotation triggers:**
  - After a certain number of signatures (implementation-dependent)
  - If RNG compromise is suspected
  - As part of regular key rotation policy

**Hybrid PQC/Classical Schemes:**

During the transition to post-quantum cryptography, use hybrid schemes:

```rust
// Combine ML-KEM with X25519 for defense-in-depth
let mlkem_keypair = KeyPair::generate(ParameterSet::MlKem768)?;
let x25519_keypair = x25519_dalek::StaticSecret::new(&mut OsRng);

// Use both shared secrets
let mlkem_ss = encapsulate(&mlkem_keypair.public_key())?;
let x25519_ss = x25519_keypair.diffie_hellman(&peer_x25519_key);

let combined_secret = kdf([mlkem_ss, x25519_ss]);
```

---

### 3.2 Secure Key Exchange with ML-KEM

#### 3.2.1 When to Use ML-KEM

**Use ML-KEM for:**
- TLS/DTLS handshakes (post-quantum key exchange)
- VPN key establishment
- Secure messaging protocols (Signal, Matrix)
- Key wrapping (encrypting data encryption keys)

**Do NOT use ML-KEM for:**
- Encrypting large amounts of data directly (use a symmetric cipher with KEM-derived key)
- Authentication without signatures (ML-KEM provides key exchange, not authentication)

#### 3.2.2 Ephemeral vs. Static Keys

**Ephemeral Keys (Recommended for Forward Secrecy):**

```rust
// Client and server generate fresh keypairs for each session
let client_keypair = KeyPair::generate(ParameterSet::MlKem768)?;
let server_keypair = KeyPair::generate(ParameterSet::MlKem768)?;

// Client encapsulates to server's public key
let (ciphertext, client_ss) = encapsulate(&server_keypair.public_key())?;

// Server decapsulates to recover shared secret
let server_ss = decapsulate(&server_keypair.private_key(), &ciphertext)?;

assert_eq!(client_ss, server_ss);

// Use shared secret for session keys
let session_key = kdf(shared_secret);
```

**Static Keys (For Persistent Identities):**

Static keys can be used when one or both parties have a long-lived identity:

```rust
// Server has a static keypair (stored securely)
let server_keypair = load_server_keypair()?;

// Client generates ephemeral keypair
let client_keypair = KeyPair::generate(ParameterSet::MlKem768)?;

// Client encapsulates to server's static public key
let (ciphertext, client_ss) = encapsulate(&server_keypair.public_key())?;

// Server decapsulates with static private key
let server_ss = decapsulate(&server_keypair.private_key(), &ciphertext)?;
```

**Forward Secrecy:** Use ephemeral keys to ensure that compromise of a static key does not compromise past sessions.

#### 3.2.3 Parameter Set Selection

| Parameter Set | Security Level | When to Use |
|---------------|----------------|-------------|
| ML-KEM-512 | 128-bit (Category 1) | Constrained devices, bandwidth-limited networks |
| ML-KEM-768 | 192-bit (Category 3) | **Recommended default** for most applications |
| ML-KEM-1024 | 256-bit (Category 5) | High-security applications, long-term protection |

**Recommendation:** Use ML-KEM-768 unless you have specific constraints.

---

### 3.3 Secure Signing with ML-DSA

#### 3.3.1 Deterministic vs. Hedged Signing

ML-DSA supports two signing modes:

**Deterministic Signing (Default):**

```rust
use turtl::dsa::{sign, PrivateKey};

let signature = sign(
    &private_key,
    message,
    context,
    SigningMode::Deterministic
)?;
```

**Properties:**
- Same message + context → same signature (reproducible)
- No RNG required during signing
- Vulnerable to RNG failures during key generation or fault attacks

**Hedged Signing (Recommended):**

```rust
let signature = sign(
    &private_key,
    message,
    context,
    SigningMode::Hedged  // Includes fresh randomness
)?;
```

**Properties:**
- Same message + context → different signatures each time
- Requires RNG during signing
- Protects against RNG failures and certain fault attacks
- **Recommended for production use**

**FIPS 204 Reference:** Section 5.4 (Hedged Signature Generation)

#### 3.3.2 Context String Usage

ML-DSA supports an optional **context string** (up to 255 bytes) to bind signatures to a specific purpose:

```rust
let context = b"TLS 1.3, Server Certificate Verify";

let signature = sign(
    &private_key,
    message,
    context,  // Binds signature to TLS context
    SigningMode::Hedged
)?;

// Verification requires the same context
let valid = verify(
    &public_key,
    message,
    &signature,
    context  // Must match signing context
)?;
```

**Use Cases:**
- Protocol separation (prevent signature reuse across protocols)
- Multi-tenant systems (bind signatures to tenant ID)
- Domain separation (e.g., "Authentication" vs "Document Signing")

**Best Practices:**
- Always use context strings to prevent cross-protocol attacks
- Keep context strings short and descriptive
- Document context values in protocol specifications

#### 3.3.3 Signature Verification Best Practices

**Always Verify Signatures:**

```rust
let is_valid = verify(&public_key, message, &signature, context)?;

if !is_valid {
    return Err(Error::InvalidSignature);
}

// Only process message if signature is valid
process_authenticated_message(message);
```

**Never:**
- Process a message before verifying its signature
- Assume a signature is valid without checking
- Use the same signature for multiple messages

**Defense Against Replay Attacks:**

Signatures alone do not prevent replay attacks. Include timestamps or nonces:

```rust
let message_with_nonce = format!("{}{}", message, nonce);
let signature = sign(&private_key, message_with_nonce.as_bytes(), context, SigningMode::Hedged)?;

// Verifier checks nonce freshness
if !is_nonce_fresh(nonce) {
    return Err(Error::ReplayAttack);
}
```

---

### 3.4 Error Handling

#### 3.4.1 Error Types

TURTL uses a comprehensive error type:

```rust
pub enum Error {
    // Input validation errors
    InvalidPublicKeySize,
    InvalidPrivateKeySize,
    InvalidCiphertextSize,
    InvalidSignatureSize,
    InvalidContextSize,

    // Cryptographic errors
    VerificationFailed,
    DecapsulationFailed,

    // Security errors
    FaultDetected,

    // Internal errors
    InternalError,
}
```

#### 3.4.2 Error Handling Best Practices

**Handle All Errors:**

```rust
// GOOD: Explicit error handling
match keypair.generate(ParameterSet::MlKem768) {
    Ok(kp) => use_keypair(kp),
    Err(e) => {
        log::error!("Key generation failed: {}", e);
        return Err(e);
    }
}

// ACCEPTABLE: Use ? operator for propagation
let keypair = KeyPair::generate(ParameterSet::MlKem768)?;
```

**Never Ignore Errors:**

```rust
// BAD: Silent failure
let _ = verify(&public_key, message, &signature, context);

// GOOD: Check result
let is_valid = verify(&public_key, message, &signature, context)?;
if !is_valid {
    return Err(Error::AuthenticationFailed);
}
```

**Do Not Leak Secret Information in Errors:**

TURTL's error messages are designed to reveal minimal information. Do not add secret-dependent details:

```rust
// BAD: Leaks which byte failed
return Err(format!("Verification failed at byte {}", index));

// GOOD: Generic error
return Err(Error::VerificationFailed);
```

---

### 3.5 Integration with Other Cryptographic Primitives

#### 3.5.1 Key Derivation

Always use a proper KDF to derive symmetric keys from ML-KEM shared secrets:

```rust
use sha3::{Sha3_256, Digest};

let (ciphertext, shared_secret) = encapsulate(&public_key)?;

// Derive multiple keys from shared secret
fn derive_keys(shared_secret: &SharedSecret) -> (Vec<u8>, Vec<u8>) {
    let mut hasher = Sha3_256::new();
    hasher.update(b"encryption");
    hasher.update(shared_secret.as_bytes());
    let enc_key = hasher.finalize().to_vec();

    let mut hasher = Sha3_256::new();
    hasher.update(b"authentication");
    hasher.update(shared_secret.as_bytes());
    let auth_key = hasher.finalize().to_vec();

    (enc_key, auth_key)
}
```

#### 3.5.2 Authenticated Encryption

Combine ML-KEM with authenticated encryption:

```rust
// Key exchange
let (ciphertext, shared_secret) = encapsulate(&recipient_public_key)?;
let (enc_key, auth_key) = derive_keys(&shared_secret);

// Encrypt and authenticate
let nonce = generate_nonce();
let encrypted_data = aes_gcm_encrypt(&enc_key, &nonce, plaintext)?;

// Send: (kem_ciphertext, nonce, encrypted_data)
```

#### 3.5.3 Signature + Encryption (Signcryption)

Provide both authentication and confidentiality:

```rust
// Sign-then-encrypt
let signature = sign(&sender_private_key, message, context, SigningMode::Hedged)?;
let combined = [message, signature.as_bytes()].concat();

let (ciphertext, shared_secret) = encapsulate(&recipient_public_key)?;
let encrypted = encrypt(&shared_secret, &combined)?;

// Send: (kem_ciphertext, encrypted)
```

**Warning:** Encrypt-then-sign and sign-then-encrypt have different security properties. Consult a cryptographer for your specific use case.

---

## 4. Known Limitations

This section honestly describes the limitations of TURTL's security guarantees.

### 4.1 Pre-Production Status

**CRITICAL:** TURTL is currently in pre-production status and has not been audited for production use.

**Known Issues:**
- **ML-DSA Signing Bug (RESOLVED):** The ML-DSA NTT implementation had a critical bug that prevented signature generation. This has been fixed, but thorough validation is ongoing.
- **Limited Interoperability Testing:** Cross-implementation testing with reference implementations is incomplete.
- **No External Audit:** TURTL has not undergone professional cryptographic auditing.

**Recommendation:** Do not use TURTL in production systems until:
1. External cryptographic audit is completed
2. All NIST test vectors pass
3. Interoperability with reference implementations is validated
4. Production status is declared

---

### 4.2 Constant-Time Guarantees Are Not Absolute

**Limitation:** Constant-time code depends on compiler behavior, CPU microarchitecture, and OS scheduling.

**Factors That Can Break Constant-Time:**
1. **Compiler Optimizations:** Compilers may optimize bitwise operations into branches
2. **Speculative Execution:** CPUs may speculatively execute both branches of a conditional
3. **Cache Effects:** Cache line fills may introduce timing variations
4. **Interrupts:** OS interrupts introduce timing noise

**Mitigation:**
- TURTL uses `#[inline(never)]` on critical functions
- Relies on `volatile` writes from the `zeroize` crate
- Code is reviewed for constant-time properties

**Validation:**
- Timing tests in `tests/timing_invariance_test.rs` (statistical validation)
- Future: `ctgrind` (constant-time Valgrind plugin) validation

**Recommendation:** For highest security, use TURTL on hardware with side-channel mitigations enabled.

---

### 4.3 No Hardware Side-Channel Protection

**TURTL does NOT protect against:**
- Power analysis (SPA, DPA)
- Electromagnetic analysis (EMA, DEMA)
- Fault injection via voltage glitching, clock glitching, or laser attacks
- Physical probing of hardware

**Reason:** These require hardware-level countermeasures (randomized power consumption, error detection circuits, shielding).

**Recommendation:** For hardware side-channel resistance, deploy TURTL on:
- Hardware Security Modules (HSMs)
- Trusted Execution Environments (TEEs)
- Tamper-resistant secure elements
- FIPS 140-3 Level 3+ certified hardware

---

### 4.4 Memory Safety Limitations

**Zeroization Cannot Prevent:**
1. **Secrets in CPU registers:** Registers are not explicitly zeroed (but are quickly overwritten)
2. **Secrets in cache:** CPU caches are not explicitly flushed
3. **Secrets swapped to disk:** If memory is swapped, it persists on disk
4. **Spectre/Meltdown attacks:** Secrets may leak through speculative execution

**Recommendation:**
- Disable swap on high-security systems
- Use memory-locking (`mlock`) for private keys
- Keep secrets in scope for minimal time

---

### 4.5 No Protection Against Algorithm-Level Attacks

**TURTL's security depends on:**
- Hardness of the Module-LWE problem (ML-KEM)
- Hardness of the Module-SIS problem (ML-DSA)
- Security of SHAKE256 and SHA3-256

**If these are broken, TURTL is broken.**

**Monitoring:**
- Follow NIST announcements
- Monitor cryptographic research (eprint.iacr.org)
- Subscribe to security mailing lists

**Crypto Agility:**
Design systems to allow algorithm replacement:

```rust
enum KemAlgorithm {
    MlKem768,
    FutureAlgorithm,
}

fn establish_session(algorithm: KemAlgorithm) -> SharedSecret {
    match algorithm {
        KemAlgorithm::MlKem768 => mlkem_exchange(),
        KemAlgorithm::FutureAlgorithm => future_exchange(),
    }
}
```

---

### 4.6 Denial-of-Service Vulnerabilities

**TURTL does not protect against:**
- Repeated signature verification (CPU exhaustion)
- Large signature/ciphertext processing (memory exhaustion)
- Algorithmic complexity attacks

**Recommendation:**
Implement application-level DoS protections:

```rust
// Rate limiting
let rate_limiter = RateLimiter::new(100, Duration::from_secs(60));
if !rate_limiter.check(&peer_ip) {
    return Err(Error::RateLimitExceeded);
}

// Resource limits
if signature.len() > MAX_SIGNATURE_SIZE {
    return Err(Error::SignatureTooLarge);
}
```

---

### 4.7 No Protection Against Side-Loaded Code

**TURTL assumes:**
- Code integrity (no tampering with TURTL's binary)
- No `LD_PRELOAD` attacks
- No hooking of system calls

**Recommendation:**
- Use code signing
- Verify binary integrity at startup
- Use secure boot on embedded systems

---

## 5. Security Reporting

### 5.1 Reporting Vulnerabilities

If you discover a security vulnerability in TURTL, please follow responsible disclosure:

**DO:**
- Report privately to the maintainers
- Provide detailed reproduction steps
- Allow reasonable time for a fix (90 days)

**DO NOT:**
- Publicly disclose the vulnerability before a fix is available
- Exploit the vulnerability for malicious purposes
- Disclose the vulnerability to third parties without permission

### 5.2 Contact Information

**Security Contact:** [To be determined - add maintainer email]

**PGP Key:** [To be determined - add PGP key for encrypted reports]

**Expected Response Time:** Within 48 hours of receiving a report

### 5.3 Coordinated Disclosure Timeline

1. **Day 0:** Vulnerability reported
2. **Day 1-2:** Initial triage and acknowledgment
3. **Day 3-30:** Investigation and fix development
4. **Day 30-60:** Testing and validation of fix
5. **Day 60:** Release of patched version
6. **Day 90:** Public disclosure (if not resolved earlier)

### 5.4 Security Advisory Process

Security advisories will be published:
- In the GitHub Security Advisories section
- On the project website (if applicable)
- Via security mailing list (to be established)

### 5.5 Severity Levels

| Severity | Description | Example |
|----------|-------------|---------|
| **Critical** | Complete compromise of security guarantees | Key recovery attack |
| **High** | Significant security impact | Timing attack leaking key bits |
| **Medium** | Limited security impact | Denial-of-service vulnerability |
| **Low** | Minimal security impact | Information disclosure (non-secret) |

---

## 6. Compliance and Standards

### 6.1 NIST FIPS 203 Compliance (ML-KEM)

**Standard:** FIPS 203 - Module-Lattice-Based Key-Encapsulation Mechanism Standard

**Publication Date:** August 13, 2024

**Compliance Status:** TURTL aims for full compliance with FIPS 203.

**Parameter Sets:**
- **ML-KEM-512:** NIST Security Category 1 (128-bit security)
- **ML-KEM-768:** NIST Security Category 3 (192-bit security)
- **ML-KEM-1024:** NIST Security Category 5 (256-bit security)

**Implemented Algorithms:**
- `ML-KEM.KeyGen()` - Key generation (Section 7.1)
- `ML-KEM.Encaps()` - Encapsulation (Section 7.2)
- `ML-KEM.Decaps()` - Decapsulation with implicit rejection (Section 7.3)

**Security Requirements:**
- ✅ IND-CCA2 security via implicit rejection
- ✅ Decapsulation re-encryption check
- ✅ Proper random sampling (CBD)
- ✅ Constant-time comparison for ciphertext validation

**Validation:**
- Test vectors from FIPS 203 Appendix (ongoing)
- Interoperability testing (planned)

---

### 6.2 NIST FIPS 204 Compliance (ML-DSA)

**Standard:** FIPS 204 - Module-Lattice-Based Digital Signature Standard

**Publication Date:** August 13, 2024

**Compliance Status:** TURTL aims for full compliance with FIPS 204.

**Parameter Sets:**
- **ML-DSA-44:** NIST Security Category 2 (128-bit security)
- **ML-DSA-65:** NIST Security Category 3 (192-bit security)
- **ML-DSA-87:** NIST Security Category 5 (256-bit security)

**Implemented Algorithms:**
- `ML-DSA.KeyGen()` - Key generation (Section 5.1)
- `ML-DSA.Sign()` - Deterministic signing (Section 5.2)
- `ML-DSA.Sign_internal()` - Hedged signing (Section 5.4)
- `ML-DSA.Verify()` - Signature verification (Section 5.3)

**Security Requirements:**
- ✅ EUF-CMA security via rejection sampling
- ✅ Context string support (up to 255 bytes)
- ✅ Hedged signing mode for RNG failure resilience
- ✅ Deterministic signing for reproducibility

**Current Issues:**
- ⚠️ ML-DSA NTT implementation recently fixed (validation ongoing)
- ⚠️ Interoperability testing incomplete

---

### 6.3 Security Levels Explained

NIST defines security categories based on resistance to quantum attacks:

| Category | Classical Bits | Quantum Attacks | Comparable Classical |
|----------|----------------|-----------------|---------------------|
| 1 | ≥128 bits | Block cipher key search | AES-128 |
| 2 | ≥128 bits | Collision search | SHA-256 collision |
| 3 | ≥192 bits | Block cipher key search | AES-192 |
| 4 | ≥192 bits | Collision search | SHA-384 collision |
| 5 | ≥256 bits | Block cipher key search | AES-256 |

**Interpretation:**
- **Category 1:** Sufficient for most applications (equivalent to AES-128)
- **Category 3:** Recommended default (equivalent to AES-192)
- **Category 5:** High-security applications (equivalent to AES-256)

**Quantum Resource Estimates:**

Breaking these security levels would require:
- **Category 1:** ~2^128 quantum operations (infeasible with current technology)
- **Category 3:** ~2^192 quantum operations (infeasible for decades)
- **Category 5:** ~2^256 quantum operations (infeasible for foreseeable future)

---

### 6.4 Conformance Testing

**NIST Known Answer Tests (KATs):**
- ML-KEM: Test vectors from FIPS 203 (ongoing)
- ML-DSA: Test vectors from FIPS 204 (ongoing)

**Interoperability:**
- Testing against liboqs (Open Quantum Safe) - planned
- Testing against pqcrypto (Rust PQC) - planned
- Testing against NIST reference implementations - planned

**Continuous Validation:**
- All test vectors included in CI/CD
- Regression testing on every commit
- Benchmark comparisons to detect performance regressions

---

### 6.5 Cryptographic Algorithm Validation Program (CAVP)

**Note:** TURTL is not currently CAVP validated.

**CAVP Requirements:**
- Official NIST test vectors
- Independent laboratory testing
- Formal validation certificate

**Future:** CAVP validation may be pursued for production use cases requiring FIPS compliance.

---

## 7. References

### 7.1 NIST Standards

- **FIPS 203:** Module-Lattice-Based Key-Encapsulation Mechanism Standard
  https://csrc.nist.gov/pubs/fips/203/final

- **FIPS 204:** Module-Lattice-Based Digital Signature Standard
  https://csrc.nist.gov/pubs/fips/204/final

- **NIST PQC Project:** Post-Quantum Cryptography Standardization
  https://csrc.nist.gov/projects/post-quantum-cryptography

### 7.2 Academic References

- **Kyber:** Original Kyber proposal (basis for ML-KEM)
  https://pq-crystals.org/kyber/

- **Dilithium:** Original Dilithium proposal (basis for ML-DSA)
  https://pq-crystals.org/dilithium/

- **Side-Channel Attacks on Lattice Cryptography:**
  Multiple papers on timing, cache, and power analysis attacks

### 7.3 Implementation References

- **pq-crystals:** Reference implementations
  https://github.com/pq-crystals/

- **liboqs:** Open Quantum Safe library
  https://github.com/open-quantum-safe/liboqs

- **Rust Crypto:** Cryptographic algorithms in Rust
  https://github.com/RustCrypto

### 7.4 Security Resources

- **IACR ePrint:** Cryptography preprint archive
  https://eprint.iacr.org/

- **NIST Cybersecurity Resources:**
  https://www.nist.gov/cybersecurity

---

## 8. Changelog

**Version 1.0 (2026-01-25):**
- Initial comprehensive security documentation
- Threat model defined
- Security features documented
- Usage guidelines provided
- Known limitations disclosed
- Security reporting process established
- NIST compliance status documented

---

## 9. Acknowledgments

TURTL's security design is based on:
- NIST FIPS 203 and FIPS 204 specifications
- Security recommendations from the NIST PQC project
- Community feedback and cryptographic research

**Note:** This document will be updated as TURTL evolves and as new security considerations emerge.

---

**Document Status:** Living Document - Subject to Updates
**Next Review:** 2026-03-25
**Maintainers:** [To be determined]
