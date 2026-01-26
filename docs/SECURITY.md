# TURTL Security Documentation

This document provides a comprehensive overview of the security features, threat model, usage guidelines, and limitations of the TURTL (Trusted Uniform Rust Toolkit for Lattice-cryptography) library.

TURTL implements NIST's post-quantum cryptographic standards: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism, FIPS 203) and ML-DSA (Module-Lattice-Based Digital Signature Algorithm, FIPS 204). This document is intended for security professionals, developers, and system architects who need to understand the security properties and proper usage of TURTL.

**Last Updated:** January 2026
**Document Version:** 1.0

---

## Table of Contents

1. [Threat Model](#threat-model)
2. [Security Features](#security-features)
3. [Usage Guidelines](#usage-guidelines)
4. [Known Limitations](#known-limitations)
5. [Security Reporting](#security-reporting)
6. [Compliance](#compliance)

---

## 1. Threat Model

Understanding what TURTL protects against—and what it does not—is critical for proper deployment and risk assessment.

### 1.1 What TURTL Protects Against

#### 1.1.1 Quantum Computer Attacks

**Primary Defense:** TURTL's fundamental purpose is to provide cryptographic primitives resistant to attacks from quantum computers.

- **Shor's Algorithm Protection:** Classical RSA and elliptic curve cryptography (ECC) can be broken in polynomial time by Shor's algorithm running on a sufficiently powerful quantum computer. TURTL's lattice-based algorithms (ML-KEM and ML-DSA) are designed to remain secure even against quantum adversaries.

- **Grover's Algorithm Mitigation:** While Grover's algorithm provides a quadratic speedup for search problems (affecting symmetric cryptography and hash functions), TURTL's security parameters are chosen to maintain adequate security margins even accounting for this speedup.

- **Post-Quantum Security Levels:** TURTL provides three security levels to match different threat models:
  - **Category 1** (ML-KEM-512, comparable to AES-128): Exhaustive key search requires approximately 2^143 classical operations or 2^71 quantum operations
  - **Category 3** (ML-KEM-768, ML-DSA-65, comparable to AES-192): Exhaustive key search requires approximately 2^207 classical operations or 2^103 quantum operations
  - **Category 5** (ML-KEM-1024, ML-DSA-87, comparable to AES-256): Exhaustive key search requires approximately 2^272 classical operations or 2^136 quantum operations

**Technical Details:** The security is based on the hardness of the Module Learning With Errors (M-LWE) problem for ML-KEM and the Module Short Integer Solution (M-SIS) problem for ML-DSA. Currently, the best known quantum attacks against these problems require exponential time, even with quantum computers.

#### 1.1.2 Classical Cryptanalysis

TURTL is designed to resist all known classical (non-quantum) attacks:

- **Lattice Reduction Attacks:** The parameter sets are chosen to make lattice reduction algorithms (BKZ, sieving) computationally infeasible. The required lattice dimensions and approximation factors ensure security margins well beyond current computational capabilities.

- **Algebraic Attacks:** The use of module lattices over polynomial rings does not introduce practical algebraic vulnerabilities. The ring structure (X^256 + 1 for ML-KEM, X^256 + 1 for ML-DSA) has been extensively analyzed.

- **Statistical Attacks:** The distribution of error terms and the noise flooding techniques prevent statistical distinguishing attacks.

- **Key Recovery Attacks:** All parameter sets provide security margins that make exhaustive key search, meet-in-the-middle attacks, and other key recovery approaches infeasible.

**Security Margin:** NIST has extensively analyzed these algorithms. The standardized parameter sets include substantial security margins beyond the minimum required for the claimed security category.

#### 1.1.3 Side-Channel Attacks (Software)

TURTL implements countermeasures against software-based side-channel attacks:

**Timing Attacks:**
- **Constant-Time Operations:** All cryptographic operations involving secret data are implemented to run in constant time (independent of secret values)
- **No Secret-Dependent Branches:** Control flow does not depend on secret data
- **No Secret-Dependent Memory Access:** Array indices and memory access patterns are independent of secrets
- **Constant-Time Comparison:** All equality checks on secrets use constant-time comparison functions

**Cache-Timing Attacks:**
- **Uniform Memory Access:** Cryptographic operations access memory in patterns independent of secret data
- **No Table Lookups on Secrets:** No lookup tables are indexed by secret values (though note limitations below)

**Implementation Details:** The `security::constant_time` module provides primitives for constant-time conditional moves, swaps, selections, and comparisons. These are used throughout the codebase wherever secret data is processed.

**Important Caveat:** Constant-time guarantees are limited by compiler optimizations and the underlying CPU/OS. See Known Limitations for details.

#### 1.1.4 Fault Injection Attacks (Software)

TURTL includes several countermeasures against fault attacks:

**Re-encryption Verification in ML-KEM Decapsulation:**
- After decrypting a ciphertext, TURTL re-encrypts the plaintext and verifies it matches the original ciphertext
- This detects faults injected during decapsulation that could leak the secret key
- Failures are handled in constant time to prevent timing-based fault attacks
- Implementation: `security::fault_detection::verify_re_encryption()`

**Double-Checking in ML-DSA Signature Verification:**
- Critical verification computations can be performed twice
- Mismatches between the two results indicate a fault
- Implementation: `security::fault_detection::verify_signature_checks()`

**Bounds Checking:**
- All array accesses are bounds-checked (enforced by Rust)
- Polynomial coefficients are validated to be in expected ranges
- Out-of-range values trigger errors rather than continuing with corrupted state
- Implementation: `security::fault_detection::verify_bounds()`

**Integrity Validation:**
- Shared secrets and other sensitive values can be double-checked for integrity
- Implementation: `security::fault_detection::verify_shared_secret_integrity()`

**Limitations:** These countermeasures protect against software-level faults and some simple hardware faults but cannot protect against sophisticated physical attacks (see Known Limitations).

#### 1.1.5 Memory Disclosure Attacks

TURTL implements automatic memory zeroization to protect against memory disclosure:

**Automatic Cleanup:**
- All sensitive data types (private keys, secret keys, shared secrets) implement the `Zeroize` trait
- Memory is automatically overwritten with zeros when these values go out of scope
- This protects against:
  - Memory dumps (core dumps, hibernation files)
  - Memory reuse attacks (subsequent processes reading old memory)
  - Cold boot attacks (reading DRAM after power loss, though with limited efficacy)

**Zeroized Types:**
- `kem::SecretKey` - ML-KEM secret keys
- `kem::SharedSecret` - ML-KEM shared secrets
- `dsa::SecretKey` - ML-DSA secret (signing) keys
- `dsa::SigningKey` - ML-DSA signing keys
- Internal temporary buffers containing sensitive data

**Implementation:** The `zeroize` crate is used to ensure proper memory clearing that compilers won't optimize away.

**Limitations:** Zeroization cannot protect against attacks while data is actively in use, and compiler/CPU optimizations may copy data to registers or cache. See Known Limitations.

### 1.2 What TURTL Does NOT Protect Against

Understanding the boundaries of TURTL's security guarantees is essential for threat modeling.

#### 1.2.1 Physical Attacks on Hardware

TURTL **does not** provide protection against sophisticated physical attacks:

**Differential Power Analysis (DPA):**
- Attackers with physical access can measure power consumption during cryptographic operations
- Power traces can reveal information about secret keys
- TURTL's constant-time software cannot prevent power-based leakage
- **Mitigation Required:** Hardware-level countermeasures (noise injection, power randomization, masking schemes)

**Simple Power Analysis (SPA):**
- Direct observation of power traces to identify operations
- While constant-time code helps, hardware-level leakage may still occur
- **Mitigation Required:** Hardware-level protections

**Electromagnetic (EM) Analysis:**
- EM emissions during computation can leak secret information
- Software cannot prevent EM leakage
- **Mitigation Required:** Physical shielding, EM noise generators

**Fault Injection via Physical Means:**
- Voltage glitching, clock glitching, laser attacks, EM pulses
- Can cause computation errors that leak secrets
- Software fault detection provides only limited protection
- **Mitigation Required:** Hardware fault detection, shielding, tamper-evident enclosures

**Cold Boot Attacks:**
- Reading DRAM contents after power loss (memory remanence)
- While zeroization helps, memory may retain traces for seconds to minutes
- **Mitigation Required:** Memory encryption, secure enclaves, rapid power loss detection

**Recommendation:** For environments with physical security threats, use hardware security modules (HSMs), trusted execution environments (TEEs), or physically secure environments.

#### 1.2.2 Malware and Compromised Execution Environment

TURTL **cannot** protect against malware or a compromised operating system:

**Keyloggers and Memory Scraping:**
- Malware can read private keys directly from memory while in use
- Malware can intercept API calls and extract keys
- **Mitigation Required:** OS-level security, antivirus, application isolation

**Process Injection:**
- Malicious processes with sufficient privileges can inject code or read memory
- **Mitigation Required:** OS security, process isolation, privilege separation

**Compromised Libraries:**
- If other dependencies are compromised, they may extract keys
- **Mitigation Required:** Dependency auditing, supply chain security

**OS Backdoors:**
- A compromised OS can subvert all userspace security
- **Mitigation Required:** Trusted OS, measured boot, secure boot

**Recommendation:** Deploy TURTL only on trusted, secured systems. Use OS-level protections (SELinux, AppArmor, sandboxing). Regularly update all software.

#### 1.2.3 Compromised Random Number Generator

TURTL's security **critically depends** on a properly functioning random number generator:

**Weak RNG Attacks:**
- If the OS random number generator (`/dev/urandom`, `getrandom()`, `BCryptGenRandom`) is weak or backdoored, all cryptographic security is lost
- Predictable RNG outputs allow attackers to predict keys and break all security guarantees

**Low Entropy:**
- Insufficient entropy during key generation can result in weak keys
- Particularly critical at system boot or in embedded systems
- **Mitigation Required:** Ensure sufficient entropy is available before generating keys

**RNG Failures:**
- TURTL uses `rand::rngs::OsRng` which relies on the OS RNG
- If the OS RNG fails or is unavailable, key generation will fail
- No fallback to weaker RNG is provided (by design)

**Recommendation:**
- Ensure the OS provides a cryptographically secure RNG
- Verify entropy is available before key generation (especially on embedded systems)
- Consider hardware RNG sources for additional entropy
- Never generate keys in low-entropy environments (e.g., early boot, VMs with poor entropy)

#### 1.2.4 Implementation Bugs

Like all software, TURTL may contain bugs:

**Correctness Bugs:**
- Implementation errors in NTT, polynomial arithmetic, or encoding/decoding
- These could lead to interoperability failures or security vulnerabilities
- **Mitigation:** Extensive testing, formal verification (future work), third-party audits

**Memory Safety Bugs:**
- While Rust's type system prevents many memory safety bugs, unsafe code could introduce vulnerabilities
- TURTL uses **zero unsafe blocks** in the main codebase to minimize this risk
- Dependencies may contain unsafe code
- **Mitigation:** Zero-unsafe policy, dependency auditing, fuzzing

**Logic Bugs:**
- Errors in control flow, error handling, or state management
- Could lead to security bypasses or denial of service
- **Mitigation:** Code review, testing, fuzzing

**Cryptographic Bugs:**
- Incorrect parameter selection, weak random sampling, or flawed algorithms
- **Mitigation:** Strict adherence to FIPS 203/204, test vectors, interoperability testing

**Recommendation:** Use the latest version of TURTL. Monitor security advisories. Report bugs responsibly. Consider third-party security audits for high-security deployments.

#### 1.2.5 Misconfiguration and Misuse

TURTL cannot protect against improper usage:

**Weak Parameter Sets:**
- Using ML-KEM-512 (Category 1) when Category 3 or 5 is required
- **Mitigation:** Choose appropriate parameter set for your threat model

**Key Reuse:**
- Reusing ML-DSA signing keys across different contexts without proper domain separation
- Reusing ephemeral ML-KEM keys (destroys forward secrecy)
- **Mitigation:** Follow usage guidelines (Section 3)

**Insecure Key Storage:**
- Storing private keys in plaintext files, databases, or logs
- **Mitigation:** Use secure key storage (OS keystores, HSMs, encrypted storage)

**Improper Error Handling:**
- Ignoring verification failures
- Continuing to use keys after errors
- **Mitigation:** Always check return values, handle errors securely

**Side-Channel Leakage in Application Code:**
- Application code that branches on secrets or has timing dependencies
- **Mitigation:** Apply constant-time principles to application-level code handling secrets

**Recommendation:** Read and follow the Usage Guidelines (Section 3). Consult security experts for high-security deployments.

#### 1.2.6 Attacks on Dependencies

TURTL relies on external crates:

**Dependency Vulnerabilities:**
- `rand`, `sha3`, `zeroize`, and other dependencies may have vulnerabilities
- **Mitigation:** Regularly update dependencies, monitor advisories

**Supply Chain Attacks:**
- Compromised crate registries or malicious dependency updates
- **Mitigation:** Dependency pinning, verification, auditing

**Transitive Dependencies:**
- Vulnerabilities in dependencies-of-dependencies
- **Mitigation:** `cargo audit`, `cargo tree`, dependency minimization

**Recommendation:** Regularly run `cargo audit`. Pin dependencies for production. Review dependency updates carefully.

---

## 2. Security Features

This section details the security mechanisms implemented in TURTL.

### 2.1 Constant-Time Operations

#### 2.1.1 What Are Constant-Time Operations?

**Constant-time operations** are operations whose execution time is independent of the secret data they process. This is critical for preventing **timing side-channel attacks**, where an attacker infers secret information by measuring how long operations take.

**Example of Vulnerable Code:**
```rust
// VULNERABLE: Time depends on secret value
fn vulnerable_compare(secret: &[u8], input: &[u8]) -> bool {
    for (s, i) in secret.iter().zip(input.iter()) {
        if s != i {
            return false; // Early return leaks position of first mismatch
        }
    }
    true
}
```

An attacker can measure timing differences to determine where the first mismatch occurs, gradually learning the secret byte-by-byte.

**Constant-Time Alternative:**
```rust
// SECURE: Time independent of data
fn secure_compare(secret: &[u8], input: &[u8]) -> bool {
    let mut diff = 0u8;
    for (s, i) in secret.iter().zip(input.iter()) {
        diff |= s ^ i; // Always executes, no early return
    }
    diff == 0
}
```

All comparisons complete regardless of where differences occur, preventing timing leakage.

#### 2.1.2 Why Constant-Time Operations Matter

Timing attacks are practical and have been used to break real-world systems:

- **Remote Timing Attacks:** Attackers can measure timing over a network (e.g., padding oracle attacks, Lucky13 against TLS)
- **Local Timing Attacks:** On shared systems (e.g., cloud VMs), co-located attackers can measure timing with nanosecond precision
- **Cache Timing Attacks:** Even without direct timing measurement, cache effects can leak information (e.g., Flush+Reload, Prime+Probe)

Post-quantum algorithms are particularly susceptible to timing attacks due to their complex arithmetic and conditional operations.

#### 2.1.3 Constant-Time Operations in TURTL

TURTL provides a comprehensive suite of constant-time primitives in `src/security/constant_time.rs`:

**Conditional Move (`ct_cmov`):**
```rust
pub fn ct_cmov(r: &mut u32, x: u32, cond: bool)
```
Sets `r := x` if `cond` is true, otherwise leaves `r` unchanged, in constant time. Available for `u32`, `u64`, `u128`, and `u8`.

**Conditional Swap (`ct_cswap`):**
```rust
pub fn ct_cswap(a: &mut u32, b: &mut u32, cond: bool)
```
Swaps `a` and `b` if `cond` is true, otherwise leaves them unchanged, in constant time. Available for `u32`, `u64`, `u128`, `u8`, and byte slices.

**Conditional Select (`ct_select`):**
```rust
pub fn ct_select(x: u32, y: u32, cond: bool) -> u32
```
Returns `x` if `cond` is true, otherwise returns `y`, in constant time. Available for `u32`, `u64`, `u128`, and `u8`.

**Constant-Time Equality (`ct_eq`):**
```rust
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool
```
Compares two byte slices for equality in constant time (found in `security::fault_detection`).

**Constant-Time Zero Check (`ct_is_zero_*`):**
```rust
pub fn ct_is_zero_u32(x: u32) -> bool
```
Tests if a value is zero in constant time. Available for `u32`, `u64`, `u128`, and `u8`.

**Implementation Technique:** These functions use bitwise operations to create masks from boolean conditions:
```rust
// Convert bool to mask: true -> 0xFFFFFFFF, false -> 0x00000000
let mask = if cond { 0xffffffff } else { 0 };
// Use mask with bitwise operations (no branches)
*r = (*r & !mask) | (x & mask);
```

This avoids conditional branches and ensures consistent execution time.

#### 2.1.4 Which Operations Are Constant-Time?

**Constant-Time Operations:**
- All polynomial arithmetic (addition, multiplication via NTT)
- NTT (Number-Theoretic Transform) and inverse NTT
- Coefficient reduction modulo q
- Polynomial compression and decompression
- Rejection sampling (via constant-time conditional moves)
- Key encapsulation and decapsulation
- Signature generation and verification
- All operations on secret keys, shared secrets, and signatures
- All comparisons involving secret data

**Not Necessarily Constant-Time:**
- Public key operations (public keys are not secret)
- Input validation (operates on public data)
- Error handling (errors are based on public failures)
- Memory allocation (sizes are public)

#### 2.1.5 Limitations of Constant-Time Guarantees

**CRITICAL CAVEAT:** Constant-time properties are **not guaranteed** at the machine code level due to:

**Compiler Optimizations:**
- Optimizing compilers may transform constant-time source code into variable-time machine code
- Dead code elimination, loop unrolling, and branch prediction can introduce timing dependencies
- Different optimization levels (`-O2`, `-O3`, `--release`) may produce different behavior
- **Mitigation:** Inspect disassembly for critical functions; use compiler barriers where needed

**CPU Microarchitecture:**
- Modern CPUs have complex execution pipelines, branch predictors, and cache hierarchies
- Variable-time instruction execution (e.g., multiplication, division)
- Cache timing depends on memory access patterns
- Speculative execution (Spectre, Meltdown) can leak information
- **Mitigation:** Use CPUs with constant-time instruction guarantees; disable hyperthreading

**Operating System:**
- Context switches, interrupts, and scheduling can introduce timing variation
- Page faults, TLB misses affect timing
- **Mitigation:** Pin processes to cores; use real-time OS features; measure and filter timing

**Best Practices:**
- Test constant-time properties using tools like `ctgrind`, `dudect`, or `timecop`
- Inspect disassembly of critical functions (especially in release builds)
- Use stable timing measurement (not wall-clock time)
- Be aware that "constant-time" is a best-effort property, not a mathematical guarantee

**For High-Security Applications:** Consider using hardware-based isolation (TEEs, secure enclaves) or hardware designed for constant-time execution.

### 2.2 Memory Zeroization

#### 2.2.1 Automatic Cleanup of Secrets

TURTL automatically overwrites sensitive data when it is no longer needed, protecting against memory disclosure attacks.

**Zeroized Types:**
All types containing secret data implement the `Zeroize` trait from the `zeroize` crate:

```rust
use zeroize::Zeroize;

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}
```

When these types go out of scope, their `Drop` implementation zeroes the memory before deallocation.

**Protected Types:**
- `kem::SecretKey` - ML-KEM decapsulation keys
- `kem::SharedSecret` - ML-KEM shared secrets (both encapsulated and decapsulated)
- `dsa::SecretKey` - ML-DSA signing keys
- `dsa::SigningKey` - ML-DSA signing keys (alias)
- Internal polynomial and coefficient arrays used during key generation

#### 2.2.2 Zeroize Trait Usage

**Example:**
```rust
{
    let secret_key = kem::KeyPair::generate(ParameterSet::MlKem768)?.secret_key();

    // Use the secret key
    let shared_secret = kem::decapsulate(&ciphertext, &secret_key)?;

    // When secret_key goes out of scope here, memory is zeroized
}
// Memory formerly containing secret_key is now zeroed
```

**Manual Zeroization:**
If you need to explicitly zeroize a value before it goes out of scope:
```rust
use zeroize::Zeroize;

let mut secret = get_secret();
// Use secret...
secret.zeroize(); // Explicitly zero memory
```

**Preventing Compiler Optimization:**
The `zeroize` crate uses techniques to prevent compilers from optimizing away the zeroing operation:
- Memory writes are marked as volatile
- Compiler fences prevent reordering
- Works across different optimization levels

#### 2.2.3 Limitations of Memory Zeroization

**Data Copied to Registers/Cache:**
- CPUs copy data to registers and cache during computation
- Zeroization only clears main memory, not registers/cache
- **Mitigation:** Cache/register contents are typically short-lived; use secure enclaves for extreme security

**Heap Fragmentation:**
- Memory allocators may move data during reallocation
- Old copies may remain in heap fragments
- **Mitigation:** Use secure allocators; avoid dynamic allocation for secrets when possible

**Swap/Hibernation:**
- Memory may be written to disk during swapping or hibernation
- Zeroization occurs before disk write, but race conditions are possible
- **Mitigation:** Disable swap for security-critical processes; use encrypted swap

**Core Dumps:**
- Zeroization helps, but if a crash occurs during active use, secrets may be in core dumps
- **Mitigation:** Disable core dumps (`ulimit -c 0`); encrypt core dump storage

**Compressed Memory:**
- Some systems use memory compression (e.g., macOS compressed memory)
- Secrets may persist in compressed form
- **Mitigation:** Use secure enclaves; disable memory compression

**Cannot Prevent Leakage While In Use:**
- Secrets must be in memory to use them
- Zeroization only helps after use is complete
- **Mitigation:** Minimize time secrets are in memory; use HSMs for long-term key storage

### 2.3 Fault Detection

#### 2.3.1 Re-Encryption Verification in ML-KEM Decapsulation

ML-KEM decapsulation includes a critical re-encryption check to detect fault attacks.

**The Attack:**
An attacker who can induce a fault during decapsulation (e.g., via voltage glitching) can cause the algorithm to output an incorrect shared secret. By observing whether the decapsulation succeeds or fails, the attacker can learn information about the secret key.

**The Countermeasure:**
FIPS 203 specifies that implementations should re-encrypt the decrypted message and verify it matches the original ciphertext:

```rust
// Decapsulate (simplified)
let message = decrypt(ciphertext, secret_key);
let re_encrypted = encrypt(message, public_key);

// Verify re-encryption matches original ciphertext
if !ct_eq(ciphertext.as_bytes(), re_encrypted.as_bytes()) {
    // Fault detected! Return error or implicit rejection
    return Err(Error::VerificationFailed);
}

// If verification passes, derive shared secret from message
let shared_secret = kdf(message);
```

**Constant-Time Failure Handling:**
Failures are handled in constant time to prevent timing-based fault attacks. The function always performs the full computation regardless of whether a fault is detected.

**Implementation:**
See `src/security/fault_detection.rs:verify_re_encryption()` and its usage in `src/kem/internal/decapsulate.rs`.

#### 2.3.2 Double Verification in Signature Verification

ML-DSA signature verification can optionally perform the verification computation twice and check that both results match.

**The Attack:**
A fault during signature verification could cause a forged signature to be accepted. By inducing faults repeatedly, an attacker might bypass signature verification.

**The Countermeasure:**
Critical verification steps can be performed twice, and results compared:

```rust
let result1 = verify_signature_computation(message, signature, public_key);
let result2 = verify_signature_computation(message, signature, public_key);

verify_signature_checks(result1, result2)?; // Error if mismatch

if !result1 {
    return Err(Error::VerificationFailed);
}
```

**Implementation:**
See `src/security/fault_detection.rs:verify_signature_checks()`.

**Note:** This check is primarily useful against transient faults. Persistent faults (e.g., flipped bits in memory) may affect both computations identically.

#### 2.3.3 Bounds Checking

All array accesses in TURTL are bounds-checked (enforced by Rust's type system). Additionally, many fault attacks work by causing values to go out of range.

**Explicit Bounds Validation:**
TURTL validates that computed values stay within expected ranges:

```rust
use crate::security::fault_detection::verify_bounds;

// Ensure coefficient is in valid range
verify_bounds(coeff, -Q/2, Q/2)?;
```

**Polynomial Coefficient Validation:**
Coefficients are checked to ensure they remain in the correct range modulo q. Out-of-range values trigger errors.

**Implementation:**
See `src/security/fault_detection.rs:verify_bounds()`.

#### 2.3.4 Shared Secret Integrity Checks

TURTL can verify that a shared secret has not been corrupted:

```rust
// Generate or derive shared secret twice and compare
let ss1 = derive_shared_secret(&message);
let ss2 = derive_shared_secret(&message);

verify_shared_secret_integrity(&ss1, &ss2)?;
```

**Implementation:**
See `src/security/fault_detection.rs:verify_shared_secret_integrity()`.

#### 2.3.5 Limitations of Fault Detection

**Sophisticated Physical Attacks:**
- Software fault detection cannot protect against all physical fault injection attacks
- Laser fault injection, EM pulses, and multi-fault attacks may bypass these checks
- **Mitigation Required:** Hardware fault detection (dual-rail logic, parity checking, sensors)

**Persistent Faults:**
- Faults that affect both the primary computation and the verification computation
- Bit flips in memory that persist across multiple reads
- **Mitigation Required:** Error-correcting memory (ECC RAM)

**Denial of Service:**
- Fault detection failures result in errors, which could be exploited for DoS
- Excessive fault detection errors may indicate an attack
- **Mitigation:** Rate limiting, logging, intrusion detection

**Performance Overhead:**
- Re-encryption adds ~50% overhead to decapsulation
- Double-checking adds ~100% overhead to verification
- Trade-off between security and performance
- **Design Choice:** TURTL includes these checks by default for maximum security

---

## 3. Usage Guidelines

This section provides guidance on securely using TURTL's cryptographic primitives.

### 3.1 Secure Key Generation

#### 3.1.1 Importance of Quality Randomness

**CRITICAL:** The security of all cryptographic operations depends entirely on the quality of the random number generator used during key generation.

**Requirements:**
- Use a cryptographically secure random number generator (CSPRNG)
- Ensure sufficient entropy is available before generating keys
- Never generate keys in low-entropy environments

**TURTL's Approach:**
TURTL uses `rand::rngs::OsRng`, which provides:
- `/dev/urandom` on Linux/Unix
- `getrandom()` system call on modern Linux
- `BCryptGenRandom` on Windows
- Secure random sources on other platforms

These are generally cryptographically secure, but entropy may be limited in certain environments:

**Low-Entropy Environments:**
- Embedded systems immediately after boot
- Virtual machines with poor entropy sources
- Containers without access to host entropy
- Systems without hardware RNG

**Verification:**
Check available entropy on Linux:
```bash
cat /proc/sys/kernel/random/entropy_avail
```
Should be > 128 bits before generating keys.

#### 3.1.2 When to Generate Keys

**Generate New Keys When:**
- Deploying a new system or service
- Rotating keys according to your key management policy
- A key compromise is suspected
- Migrating to a higher security parameter set

**Do NOT Generate Keys:**
- During system boot (unless entropy is verified)
- In tight loops or automated scripts without rate limiting (to avoid entropy depletion)
- In untrusted or compromised environments

#### 3.1.3 When to Regenerate Keys

**Key Rotation Policy:**
Establish a key rotation policy based on your threat model:

- **Long-Term Signing Keys (ML-DSA):**
  - Rotate every 1-3 years for high-security applications
  - Rotate immediately if compromise is suspected
  - Rotate when upgrading to higher security parameter set

- **Long-Term KEM Keys (ML-KEM):**
  - Rotate every 1-2 years for static keys
  - Prefer ephemeral keys for forward secrecy (rotate per-session)

- **Ephemeral Keys:**
  - Generate fresh keys for each session/connection
  - Never reuse ephemeral keys

**Reasons to Regenerate:**
- Key compromise or suspected compromise
- Security parameter upgrade (e.g., Category 1 → Category 3)
- Scheduled rotation per policy
- After cryptanalytic advances (monitor NIST/academic research)
- Quantum computer development milestones

#### 3.1.4 Key Generation Example

```rust
use turtl::kem::{KeyPair as KemKeyPair, ParameterSet as KemParams};
use turtl::dsa::{KeyPair as DsaKeyPair, ParameterSet as DsaParams};
use turtl::error::Result;

fn generate_keys() -> Result<()> {
    // Generate ML-KEM-768 keypair (Category 3, recommended)
    let kem_keypair = KemKeyPair::generate(KemParams::MlKem768)?;

    // Generate ML-DSA-65 keypair (Category 3, recommended)
    let dsa_keypair = DsaKeyPair::generate(DsaParams::MlDsa65)?;

    // Store keys securely (see Key Storage section)
    secure_store_kem_key(&kem_keypair)?;
    secure_store_dsa_key(&dsa_keypair)?;

    Ok(())
}
```

**Parameter Set Selection:**
- **Category 1 (ML-KEM-512, ML-DSA-44):** Low-security applications, resource-constrained environments
- **Category 3 (ML-KEM-768, ML-DSA-65):** Recommended for most applications, balances security and performance
- **Category 5 (ML-KEM-1024, ML-DSA-87):** High-security applications, long-term secrets (10+ years)

### 3.2 Secure Signing (ML-DSA)

#### 3.2.1 Deterministic vs. Hedged Signing

ML-DSA supports two signing modes:

**Deterministic Signing:**
- Same message always produces the same signature (for a given key)
- Simpler implementation, easier to test
- Vulnerable to fault attacks that manipulate the random nonce

**Hedged Signing:**
- Introduces additional randomness into nonce generation
- Same message produces different signatures each time
- Resistant to faults in the RNG during signing
- Provides defense-in-depth against nonce reuse

**Recommendation:**
- **Use hedged signing by default** for maximum security
- Use deterministic signing only when reproducibility is required (e.g., deterministic builds, consensus protocols)

**Example:**
```rust
use turtl::dsa::{KeyPair, ParameterSet, sign, verify};
use turtl::error::Result;

fn hedged_signing_example() -> Result<()> {
    let keypair = KeyPair::generate(ParameterSet::MlDsa65)?;
    let message = b"Important message";

    // Hedged signing (default, recommended)
    let sig1 = sign(message, &keypair.secret_key(), b"context")?;
    let sig2 = sign(message, &keypair.secret_key(), b"context")?;
    // sig1 != sig2 (different randomness)

    // Both signatures verify correctly
    verify(message, &sig1, &keypair.public_key(), b"context")?;
    verify(message, &sig2, &keypair.public_key(), b"context")?;

    Ok(())
}
```

**Note:** TURTL currently implements the FIPS 204 deterministic signing. Support for hedged signing is planned for a future release. Until then, ensure your RNG is robust and implement application-level nonce management if needed.

#### 3.2.2 Context String Usage

ML-DSA supports optional **context strings** for domain separation.

**What Are Context Strings?**
A context string is an arbitrary byte string (up to 255 bytes) that is cryptographically bound to the signature. The same message signed with different context strings produces different signatures and cannot be verified with the wrong context.

**When to Use Context Strings:**
- To prevent signature reuse across different applications or protocols
- To bind signatures to specific contexts (e.g., "TLS 1.3 handshake", "firmware update v2.3")
- To implement protocol-level domain separation

**Example:**
```rust
// Sign with context
let context = b"MyApp v1.0 - Document Signature";
let signature = sign(message, &secret_key, context)?;

// Verification requires same context
verify(message, &signature, &public_key, context)?; // OK

// Different context fails verification
verify(message, &signature, &public_key, b"DifferentContext")?; // Error
```

**Best Practices:**
- Use descriptive context strings that identify the application and purpose
- Include version information in context strings
- Document context strings in your protocol specification
- Keep context strings under 255 bytes

**Default Context:**
If no context is needed, use an empty slice:
```rust
let signature = sign(message, &secret_key, b"")?;
```

#### 3.2.3 Signature Verification Best Practices

**Always Verify Signatures:**
Never skip signature verification. Always check the return value.

```rust
// CORRECT
match verify(message, &signature, &public_key, context) {
    Ok(()) => { /* Signature valid, proceed */ },
    Err(e) => { /* Signature invalid, reject */ },
}

// WRONG - ignoring errors
let _ = verify(message, &signature, &public_key, context); // DON'T DO THIS
```

**Reject Invalid Signatures:**
On verification failure, reject the message and do not process it further.

**Constant-Time Verification:**
Signature verification is constant-time with respect to the signature and public key to prevent timing attacks during verification.

**Replay Protection:**
ML-DSA signatures do not include timestamps or nonces. Implement application-level replay protection if needed:
- Include timestamps or sequence numbers in the signed message
- Maintain a nonce database
- Use protocol-level replay protection (e.g., TLS record sequence numbers)

**Example:**
```rust
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct SignedMessage {
    message: Vec<u8>,
    timestamp: u64,
    nonce: [u8; 32],
}

fn sign_with_replay_protection(message: &[u8]) -> Result<Vec<u8>> {
    let timestamp = current_timestamp();
    let nonce = generate_random_nonce();

    let signed_msg = SignedMessage {
        message: message.to_vec(),
        timestamp,
        nonce,
    };

    let serialized = serialize(&signed_msg)?;
    let signature = sign(&serialized, &secret_key, b"context")?;

    Ok(signature)
}
```

### 3.3 Secure Key Exchange (ML-KEM)

#### 3.3.1 When to Use ML-KEM

**ML-KEM is designed for:**
- Establishing shared secrets between two parties
- Hybrid key exchange (combine with classical ECDH)
- Post-quantum TLS and VPNs
- Encrypted communication protocols

**ML-KEM is NOT designed for:**
- Non-interactive key exchange (requires sender to have recipient's public key)
- Signing or authentication (use ML-DSA instead)
- Password-based key derivation (use a KDF like Argon2)

#### 3.3.2 Ephemeral vs. Static Keys

**Ephemeral Keys (Recommended):**
- Generate fresh key pairs for each session
- Provides forward secrecy: past sessions remain secure even if long-term keys are compromised
- Prevents key reuse attacks

**Example:**
```rust
// Alice and Bob establish a shared secret

// Alice: Generate ephemeral keypair
let alice_keypair = kem::KeyPair::generate(ParameterSet::MlKem768)?;

// Alice sends her public key to Bob
send_to_bob(&alice_keypair.public_key())?;

// Bob: Encapsulate to Alice's public key
let (ciphertext, bob_shared_secret) = kem::encapsulate(&alice_keypair.public_key())?;

// Bob sends ciphertext to Alice
send_to_alice(&ciphertext)?;

// Alice: Decapsulate to recover shared secret
let alice_shared_secret = kem::decapsulate(&ciphertext, &alice_keypair.secret_key())?;

// alice_shared_secret == bob_shared_secret
assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());

// Keys are automatically zeroized when they go out of scope
```

**Static Keys:**
- Long-term key pairs stored and reused across multiple sessions
- Useful when ephemeral key exchange is not possible (e.g., store-and-forward messaging)
- Does NOT provide forward secrecy
- Requires secure key storage

**Recommendation:**
- Use ephemeral keys for interactive protocols (TLS, SSH, VPN)
- Use static keys only when necessary (email encryption, asynchronous messaging)
- Consider hybrid approaches (static authentication + ephemeral encryption)

#### 3.3.3 Forward Secrecy Considerations

**Forward Secrecy:**
The property that past session keys remain secure even if long-term keys are compromised.

**Achieving Forward Secrecy with ML-KEM:**
1. **Use Ephemeral Keys:** Generate fresh key pairs for each session
2. **Zeroize Old Keys:** Ensure ephemeral keys are zeroized after use (automatic in TURTL)
3. **No Key Logging:** Never log or persistently store ephemeral keys or shared secrets
4. **Session Key Derivation:** Derive session-specific keys from the shared secret using a KDF

**Example:**
```rust
use sha3::{Sha3_256, Digest};

fn derive_session_keys(shared_secret: &kem::SharedSecret) -> ([u8; 32], [u8; 32]) {
    // Derive separate encryption and authentication keys
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(b"encryption");
    let enc_key: [u8; 32] = hasher.finalize().into();

    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(b"authentication");
    let auth_key: [u8; 32] = hasher.finalize().into();

    (enc_key, auth_key)
}
```

**Avoiding Forward Secrecy Loss:**
- Never store ephemeral secret keys to disk
- Disable core dumps for processes handling ephemeral keys
- Implement secure key erasure (TURTL does this automatically)
- Use encrypted swap or disable swap

#### 3.3.4 Hybrid Key Exchange

**Recommendation:** For maximum security during the transition to post-quantum cryptography, use **hybrid key exchange** that combines ML-KEM with classical ECDH.

**Rationale:**
- If ML-KEM is broken, ECDH still provides classical security
- If ECDH is broken by quantum computers, ML-KEM provides post-quantum security
- Combined security: both algorithms must be broken to compromise the session

**Example Hybrid KEM:**
```rust
use turtl::kem::{self, ParameterSet};
// Use your preferred ECDH library (e.g., x25519-dalek)
use x25519_dalek::{EphemeralSecret, PublicKey};

fn hybrid_key_exchange() -> Result<[u8; 64]> {
    // Classical ECDH
    let ecdh_secret = EphemeralSecret::random();
    let ecdh_public = PublicKey::from(&ecdh_secret);

    // Post-quantum ML-KEM
    let mlkem_keypair = kem::KeyPair::generate(ParameterSet::MlKem768)?;
    let (ciphertext, mlkem_shared) = kem::encapsulate(&mlkem_keypair.public_key())?;

    // Combine both shared secrets
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(ecdh_shared_secret.as_bytes());
    combined[32..].copy_from_slice(&mlkem_shared.as_bytes()[..32]);

    // Hash combined secret for final key
    let mut hasher = Sha3_256::new();
    hasher.update(&combined);
    let final_key: [u8; 32] = hasher.finalize().into();

    Ok(final_key)
}
```

**NIST Recommendation:** NIST encourages hybrid approaches during the post-quantum transition period.

---

## 4. Known Limitations

### 4.1 No Hardware Side-Channel Protection

**TURTL does NOT protect against:**
- Differential Power Analysis (DPA)
- Simple Power Analysis (SPA)
- Electromagnetic (EM) analysis
- Fault injection via voltage/clock glitching, lasers, or EM pulses

**Impact:**
Attackers with physical access to the device during cryptographic operations can potentially extract secret keys through:
- Power consumption measurements
- EM emissions measurements
- Inducing faults via voltage/clock manipulation

**Mitigation:**
For environments with physical security threats:
- Use Hardware Security Modules (HSMs)
- Use Trusted Execution Environments (TEEs) like Intel SGX, ARM TrustZone
- Use physically secure environments with no attacker access
- Implement hardware-level DPA countermeasures (randomization, masking, dual-rail logic)

### 4.2 Constant-Time Guarantees Limited by Compiler and OS

**Constant-time source code does not guarantee constant-time machine code.**

**Compiler Issues:**
- Optimizing compilers may transform constant-time code into variable-time code
- Dead code elimination may remove intentional "dummy" operations
- Loop optimizations may introduce variable-time behavior
- Different optimization levels produce different results

**CPU Issues:**
- Variable-time instructions (division, modular reduction on some CPUs)
- Cache timing variations
- Speculative execution (Spectre, Meltdown)
- Branch prediction effects

**OS Issues:**
- Context switches introduce timing variation
- Interrupts and system calls affect timing
- Virtual memory (page faults, TLB misses)

**Mitigation:**
- Inspect disassembly of critical functions
- Use constant-time testing tools (`dudect`, `ctgrind`)
- Use CPUs with constant-time guarantees where available
- Pin processes to CPU cores
- Disable hyperthreading and speculative execution (if possible)

**Reality Check:**
True constant-time execution at the hardware level is extremely difficult to achieve on modern CPUs. TURTL's constant-time code is a best-effort defense that significantly raises the bar for attackers but cannot provide absolute guarantees.

### 4.3 No Protection Against Hardware Fault Attacks

TURTL's software fault detection provides only limited protection against sophisticated hardware fault attacks.

**Unprotected Against:**
- Precise laser fault injection targeting specific gates
- Multi-fault attacks that bypass re-encryption checks
- Persistent faults (e.g., rowhammer) affecting both computation and verification

**Mitigation:**
- Hardware fault detection sensors
- Dual-rail logic and parity checking
- Shielding against EM and laser attacks
- Tamper-evident and tamper-resistant enclosures

### 4.4 Memory Safety Relies on Rust's Guarantees

TURTL uses **zero unsafe code** in its core implementation, relying entirely on Rust's memory safety guarantees.

**Risks:**
- Bugs in the Rust compiler could undermine safety
- Dependencies may contain unsafe code or vulnerabilities
- FFI boundaries (if interfacing with C libraries) introduce risk

**Mitigation:**
- Use stable Rust compiler releases
- Regularly update dependencies
- Audit dependencies for unsafe code
- Minimize use of FFI

### 4.5 Zeroization Cannot Prevent All Memory Disclosure

**Limitations:**
- Data may be copied to CPU registers, cache, or other locations
- Swap files and hibernation may capture memory
- Memory compression may preserve copies
- Core dumps may capture secrets during crashes
- Speculative execution may leak data to cache

**Mitigation:**
- Use secure enclaves for extremely sensitive keys
- Disable swap and core dumps
- Minimize time secrets are in memory
- Use HSMs for long-term key storage

### 4.6 Parameter Set Security Assumptions

**Security depends on:**
- Hardness of M-LWE (ML-KEM) and M-SIS (ML-DSA) problems
- Chosen parameter sets providing adequate margins

**Risks:**
- Cryptanalytic advances could reduce security
- Quantum algorithm improvements (beyond Grover)
- Potential future attacks on structured lattices

**Mitigation:**
- Monitor academic research and NIST updates
- Use higher security categories for long-term secrets
- Plan for algorithm agility (ability to switch algorithms)

### 4.7 Side-Channel Leakage in Application Code

**TURTL's constant-time guarantees do not extend to application code.**

If your application code handles secrets with timing dependencies, side-channel leakage can still occur:

```rust
// VULNERABLE APPLICATION CODE
let shared_secret = kem::decapsulate(&ct, &sk)?;

if user_password == stored_password {  // Timing leak!
    use_shared_secret(&shared_secret);
}
```

**Mitigation:**
- Apply constant-time principles to all application code handling secrets
- Use constant-time comparison for passwords and tokens
- Avoid branching on secret data in application logic

---

## 5. Security Reporting

### 5.1 How to Report Vulnerabilities

If you discover a security vulnerability in TURTL, please report it responsibly.

**DO:**
- Email security reports privately to the maintainers (see repository contacts)
- Include detailed reproduction steps
- Provide proof-of-concept code if possible
- Allow reasonable time for a fix before public disclosure

**DO NOT:**
- Open public GitHub issues for security vulnerabilities
- Publicly disclose vulnerabilities before a fix is available
- Exploit vulnerabilities maliciously

### 5.2 Expected Response Time

- **Initial Response:** Within 3 business days of report
- **Triage and Assessment:** Within 7 business days
- **Fix Development:** Depends on severity (critical issues prioritized)
- **Public Disclosure:** Coordinated with reporter, typically 30-90 days after fix is released

### 5.3 Disclosure Policy

TURTL follows **coordinated disclosure**:

1. Reporter submits vulnerability privately
2. Maintainers confirm receipt and begin investigation
3. Maintainers develop and test a fix
4. Fix is released in a new version
5. Security advisory is published (with credit to reporter if desired)
6. Public disclosure after users have had time to update (typically 30 days)

**Security Advisories:**
Published on:
- GitHub Security Advisories
- Repository CHANGELOG
- Project website/documentation

---

## 6. Compliance

### 6.1 FIPS 203 Conformance (ML-KEM)

TURTL implements **ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)** as specified in **NIST FIPS 203**.

**Conformance:**
- Follows FIPS 203 algorithms exactly (Algorithm 12-19)
- Implements all three parameter sets (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
- Uses specified encodings and byte formats
- Implements re-encryption verification (implicit rejection)
- Uses approved random sampling methods

**Test Vectors:**
TURTL passes all NIST-provided Known Answer Tests (KATs) for ML-KEM.

**Deviations:**
None. TURTL is fully conformant with FIPS 203.

### 6.2 FIPS 204 Conformance (ML-DSA)

TURTL implements **ML-DSA (Module-Lattice-Based Digital Signature Algorithm)** as specified in **NIST FIPS 204**.

**Conformance:**
- Follows FIPS 204 algorithms exactly
- Implements all three parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87)
- Uses specified encodings and byte formats
- Supports context strings (up to 255 bytes)
- Implements deterministic signing as specified

**Test Vectors:**
TURTL passes all NIST-provided Known Answer Tests (KATs) for ML-DSA.

**Deviations:**
None. TURTL is fully conformant with FIPS 204.

**Note:** Hedged signing (randomized nonce generation) is planned for a future release as an optional mode.

### 6.3 Security Level Explanations

NIST defines security levels in terms of computational effort required to break the scheme.

**Security Categories:**

| Category | Classical Security | Quantum Security | Comparable Symmetric | Parameter Sets |
|----------|-------------------|------------------|---------------------|----------------|
| 1 | 2^143 operations | 2^71 operations | AES-128 | ML-KEM-512 |
| 2 | 2^166 operations | 2^83 operations | SHA-256 collision | ML-DSA-44 |
| 3 | 2^207 operations | 2^103 operations | AES-192 | ML-KEM-768, ML-DSA-65 |
| 5 | 2^272 operations | 2^136 operations | AES-256 | ML-KEM-1024, ML-DSA-87 |

**Interpretation:**
- **Category 1:** Suitable for short-term secrets (1-10 years), resource-constrained devices
- **Category 3:** Recommended for most applications, balances security and performance
- **Category 5:** Suitable for long-term secrets (20+ years), high-security environments

**Selection Guidance:**
- Use Category 3 as the default for new deployments
- Use Category 5 for highly sensitive data or long-term secrets
- Use Category 1 only for low-security or resource-constrained applications

### 6.4 Algorithm Security Basis

**ML-KEM Security:**
Based on the hardness of the **Module Learning With Errors (M-LWE)** problem:
- Given a matrix A and a vector b = A·s + e (with small error e), find s
- Best known attacks use lattice reduction (BKZ algorithm)
- Quantum attacks (using Grover's algorithm) provide only quadratic speedup
- No polynomial-time quantum attacks are known

**ML-DSA Security:**
Based on the hardness of the **Module Short Integer Solution (M-SIS)** problem:
- Given a matrix A, find a short vector z such that A·z = 0 (mod q)
- Unforgeability relies on M-SIS hardness
- Best known attacks require exponential time even with quantum computers

**Structured Lattices:**
Both schemes use polynomial rings (R = Z[X]/(X^256 + 1)) for efficiency. Extensive cryptanalysis has not found practical attacks exploiting this structure.

**References:**
- NIST FIPS 203: https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204: https://csrc.nist.gov/pubs/fips/204/final
- NIST Post-Quantum Cryptography Standardization: https://csrc.nist.gov/Projects/post-quantum-cryptography

---

## Appendix: Security Checklist

Use this checklist when deploying TURTL:

**Key Generation:**
- [ ] RNG is cryptographically secure
- [ ] Sufficient entropy is available
- [ ] Appropriate parameter set is chosen for threat model
- [ ] Keys are generated in a secure environment

**Key Storage:**
- [ ] Private keys are stored encrypted
- [ ] Access to private keys is restricted
- [ ] Key backups are encrypted
- [ ] Key rotation policy is defined

**Cryptographic Operations:**
- [ ] Use ephemeral keys for forward secrecy (when applicable)
- [ ] Use hedged signing (when available) or ensure RNG quality
- [ ] Always verify signatures (never skip verification)
- [ ] Use context strings for domain separation (ML-DSA)

**Application Integration:**
- [ ] All errors are handled securely
- [ ] No secrets are logged
- [ ] Application code uses constant-time operations for secrets
- [ ] Replay protection is implemented (if needed)

**System Security:**
- [ ] Swap is disabled or encrypted
- [ ] Core dumps are disabled
- [ ] System is patched and up-to-date
- [ ] Physical security is assessed (for high-security deployments)

**Monitoring and Maintenance:**
- [ ] Security advisories are monitored
- [ ] Dependencies are regularly updated
- [ ] Security audits are planned (for production deployments)
- [ ] Incident response plan is defined

---

## Document History

- **Version 1.0 (January 2026):** Initial comprehensive security documentation

---

**End of Document**

For questions or clarifications, please contact the TURTL maintainers or open a discussion on GitHub.
