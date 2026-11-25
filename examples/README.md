# Examples

Run any example with `cargo run --release --example <name>`.

| Example          | Shows                                                                                         |
|------------------|-----------------------------------------------------------------------------------------------|
| `kem_basic`      | ML-KEM key generation, encapsulation and decapsulation for all three parameter sets            |
| `dsa_basic`      | ML-DSA key generation, signing and verification, and the cases that must fail (tampered message, wrong key, wrong context) |
| `hedged_signing` | Hedged vs. deterministic ML-DSA signing, and context strings                                   |

## Choosing parameters

| Use case                          | ML-KEM       | ML-DSA     |
|-----------------------------------|--------------|------------|
| Default                           | ML-KEM-768   | ML-DSA-65  |
| Constrained bandwidth or storage  | ML-KEM-512   | ML-DSA-44  |
| Highest security category         | ML-KEM-1024  | ML-DSA-87  |

## Guidance

- Use `SigningMode::Hedged` (fresh randomness mixed into each signature) unless you specifically
  need reproducible signatures. Deterministic signing is for testing and known-answer checks.
- Use a context string to separate signatures made for different purposes with the same key.
- Treat the 32-byte ML-KEM shared secret as key material: derive working keys from it (for
  example with `kem::shell::Shell`) rather than using it directly in several places.
- Private keys and shared secrets are zeroized when dropped; copies you make with `as_bytes()`
  are yours to protect.

See [SECURITY.md](../SECURITY.md) for the security status and
[docs/IMPLEMENTATION.md](../docs/IMPLEMENTATION.md) for where each FIPS algorithm lives.
