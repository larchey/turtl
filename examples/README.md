# TURTL Examples

This directory contains practical examples demonstrating how to use TURTL's post-quantum cryptographic implementations.

## Available Examples

### `dsa_basic.rs` - ML-DSA Digital Signatures ⚠️

**Status:** Currently blocked by a known verification bug (see TODO.md)

Demonstrates the complete ML-DSA digital signature workflow:
- Key generation for all parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87)
- Message signing with hedged and deterministic modes
- Signature verification
- Verification failure scenarios (tampered messages, wrong keys, wrong context)

**Run:**
```bash
cargo run --example dsa_basic
```

**Key Concepts Covered:**
- Parameter set selection based on security requirements
- Hedged vs deterministic signing modes
- Context strings for domain separation
- Proper error handling
- Size comparisons across parameter sets

---

### `kem_basic.rs` - ML-KEM Key Encapsulation ✅

**Status:** Fully functional

Demonstrates the complete ML-KEM key encapsulation workflow:
- Key generation for all parameter sets (ML-KEM-512, ML-KEM-768, ML-KEM-1024)
- Encapsulation (sender generates ciphertext and shared secret)
- Decapsulation (receiver recovers shared secret from ciphertext)
- Verification that both parties derive the same shared secret

**Run:**
```bash
cargo run --example kem_basic
```

**Key Concepts Covered:**
- Parameter set selection based on security requirements
- Two-party key establishment (Alice and Bob scenario)
- Shared secret generation and verification
- Size comparisons across parameter sets
- Post-quantum key encapsulation mechanism

---

### `hedged_signing.rs` - ML-DSA Hedged Signing

**Status:** Functional (depends on ML-DSA verification)

Advanced example demonstrating hedged signing mode with multiple signatures of the same message.

**Run:**
```bash
cargo run --example hedged_signing
```

---

## ML-DSA (Digital Signature Algorithm)

ML-DSA is NIST's post-quantum digital signature standard (FIPS 204), based on the Module-LWE problem.

### Parameter Sets

| Parameter Set | Security Category | Public Key | Private Key | Signature | Use Case |
|--------------|-------------------|------------|-------------|-----------|----------|
| ML-DSA-44 | 2 (SHA-256) | 1,312 bytes | 2,560 bytes | 2,420 bytes | Constrained environments |
| ML-DSA-65 | 3 (SHA-384) | 1,952 bytes | 4,032 bytes | 3,309 bytes | **Recommended default** |
| ML-DSA-87 | 5 (SHA-512) | 2,592 bytes | 4,896 bytes | 4,627 bytes | Maximum security |

### Signing Modes

**Hedged Mode (Recommended):**
- Uses fresh randomness for each signature
- Provides defense-in-depth against side-channel attacks
- Protects against RNG failures
- Different signatures produced each time for the same message

**Deterministic Mode:**
- No randomness used
- Same signature every time for the same message/key pair
- Useful for testing and when reproducibility is required
- May be vulnerable to side-channel attacks if the same message is signed repeatedly

### Context Strings

Context strings (up to 255 bytes) provide:
- **Domain separation:** Prevent signatures from being valid across different applications
- **Additional authenticated data:** Bind extra context to the signature
- **Protocol flexibility:** Empty string ("") is valid if not needed

Example contexts:
- `b"myapp-v1.0"` - Application and version
- `b"TLS-1.3-handshake"` - Protocol-specific context
- `b""` - Empty context (valid but less secure)

---

## ML-KEM (Key Encapsulation Mechanism)

ML-KEM is NIST's post-quantum key encapsulation standard (FIPS 203), based on the Module-LWE problem.

**See `kem_basic.rs` for a complete working example.**

### Parameter Sets

| Parameter Set | Security Category | Public Key | Private Key | Ciphertext | Use Case |
|--------------|-------------------|------------|-------------|------------|----------|
| ML-KEM-512 | 1 (AES-128) | 800 bytes | 1,632 bytes | 768 bytes | Lightweight |
| ML-KEM-768 | 3 (AES-192) | 1,184 bytes | 2,400 bytes | 1,088 bytes | **Recommended default** |
| ML-KEM-1024 | 5 (AES-256) | 1,568 bytes | 3,168 bytes | 1,568 bytes | Maximum security |

---

## Building Examples

Build all examples:
```bash
cargo build --examples
```

Build a specific example:
```bash
cargo build --example dsa_basic
```

Run a specific example:
```bash
cargo run --example dsa_basic
```

Run with release optimizations:
```bash
cargo run --example dsa_basic --release
```

---

## Example Code Structure

All examples follow a consistent structure:

1. **Imports** - Minimal necessary imports from TURTL
2. **Main function** - Overall demonstration flow
3. **Helper functions** - Each demonstrates a specific aspect
4. **Error handling** - Proper Result types with `?` operator
5. **Clear output** - Formatted output showing what's happening
6. **Comments** - Explanations of each step and security considerations

---

## Security Considerations

When using these examples as a reference for your own code:

1. **Parameter Set Selection:**
   - Consider your security requirements (Category 2, 3, or 5)
   - Balance security vs. key/signature sizes
   - Default to ML-DSA-65 or ML-KEM-768 unless you have specific needs

2. **Signing Mode (ML-DSA):**
   - **Use hedged mode in production** for side-channel resistance
   - Only use deterministic mode when you need reproducible signatures

3. **Context Strings (ML-DSA):**
   - Use non-empty context strings when possible
   - Include application name and version for domain separation
   - Keep context strings consistent within your application

4. **Key Management:**
   - Private keys are automatically zeroized when dropped
   - Store private keys securely (encrypted at rest)
   - Never transmit private keys in plaintext
   - Generate fresh keys for each use case

5. **Error Handling:**
   - Always handle errors properly (don't unwrap in production)
   - Provide appropriate error messages to users
   - Log errors securely without leaking sensitive information

---

## Learning Path

If you're new to post-quantum cryptography:

1. Start with `kem_basic.rs` to understand key encapsulation
   - Simpler concept than signatures
   - See how two parties establish a shared secret
2. Move to `dsa_basic.rs` to understand digital signatures
   - More complex with signing modes and contexts
3. Try modifying the examples:
   - Change parameter sets
   - For ML-DSA: try different signing modes and context strings
   - For ML-KEM: observe how shared secrets change each time
4. Read the FIPS specifications:
   - [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
   - [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
5. Review `PROJECT_DESIGN.md` for architecture details
6. Check `SECURITY.md` for security considerations

---

## Contributing Examples

We welcome additional examples! Good candidates:

- Integration with web frameworks (Actix, Axum, Rocket)
- Key serialization and storage patterns
- Hybrid classical + post-quantum schemes
- Performance optimization techniques
- Cross-language interoperability demonstrations
- Real-world application patterns (TLS, secure messaging, etc.)

See `CONTRIBUTING.md` for guidelines.

---

## Troubleshooting

### Example won't compile

```bash
# Clean and rebuild
cargo clean
cargo build --examples
```

### Example runs but fails at runtime

Check `TODO.md` for known issues. Some features may be temporarily disabled during development.

### Performance is slow in debug mode

Use release mode for realistic performance:
```bash
cargo run --example dsa_basic --release
```

---

## Additional Resources

- [TURTL Documentation](../README.md)
- [API Documentation](https://docs.rs/turtl) (when published)
- [Security Guide](../SECURITY.md)
- [Project Design](../PROJECT_DESIGN.md)
- [Task Breakdown](../TASK_BREAKDOWN.md)

---

**Questions?** Open an issue or check the existing documentation.
