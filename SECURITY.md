# Security Policy

## Reporting a vulnerability

Report security issues privately through GitHub's
[security advisory form](https://github.com/larchey/turtl/security/advisories/new), not in a
public issue. Include the affected version, a description, and a reproducer if you have one.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Assurance

### Conformance

turtl is checked against the `fips203` and `fips204` reference implementations (dev-dependencies)
for every parameter set:

- **Known-answer tests** (`tests/keygen_kat.rs`, `tests/det_kat.rs`): key generation from seeds,
  deterministic encapsulation and deterministic signing reproduce the reference byte for byte.
- **Interoperability** (`tests/fips_interop.rs`): each implementation encapsulates to and
  verifies signatures from the other, including SHAKE128 HashML-DSA.
- **Adversarial differential testing** (`tests/adversarial.rs`, `fuzz/`): attacker-controlled
  ciphertexts, keys and signatures must get the same result from turtl as from the reference.
  See [ADVERSARIAL.md](ADVERSARIAL.md).

### Dependencies

Runtime dependencies are `sha3`, `rand` (OS RNG) and `zeroize`. CI runs `cargo audit` against the
RustSec advisory database and builds with `--locked`.

### Input validation

- `kem::PublicKey::new`: length and the FIPS 203 §7.2 modulus check.
- `kem::PrivateKey::new`: length and the FIPS 203 §7.3 hash check.
- `dsa::PrivateKey::new`: length and s1/s2 coefficients within [-η, η].
- `dsa::verify` / `hash_verify` return `Ok(false)` for any malformed or invalid signature.
- Context strings longer than 255 bytes are rejected with `Error::ContextTooLong`.

### Side channels

- Modular reduction on secret data is a branch-free Barrett reduction (`common/reduce.rs`). There is
  no hardware divide on secrets.
- Branch-free on secret data: the NTT, polynomial arithmetic, ML-KEM Compress and message
  encoding, implicit-rejection selection, ML-DSA `Decompose`, `Power2Round`, `MakeHint` and
  infinity norms.
- `tests/timing_leakage.rs` runs dudect-style Welch t-tests on ML-KEM decapsulation (valid vs.
  invalid ciphertext, fixed vs. random ciphertext) and on `ct_eq`, with a deliberately leaky
  control that the harness must detect. The nightly adversarial workflow runs them.

### Memory hygiene

- Private keys, shared secrets, keygen seeds, expanded seeds (`σ`, `K`, `ρ'`), the decrypted
  message, sampling buffers and every `Polynomial` are zeroized on drop.
- Secret types print `<redacted>` under `Debug`; `SharedSecret` equality is constant-time.
- `#![forbid(unsafe_code)]`.

## Limitations

- **No independent audit yet.** turtl has been cross-checked against reference implementations
  and adversarially tested, but not reviewed by a third-party cryptographer. Systems with a
  formal assurance requirement should wait for, or commission, an audit.
- **Timing evidence, not proof.** Wall-clock t-tests and code review show no secret-dependent
  timing in the paths above. There is no formal verification and no power/EM countermeasures
  (masking, shuffling); turtl is not intended for devices exposed to physical attackers.
- **ML-DSA signing leaks its iteration count**, as the FIPS 204 algorithm and its reference
  implementation do. Rejection sampling (`ExpandS`, `SampleInBall`) runs a data-dependent number
  of times on hash outputs.
- **SHA3 / SHAKE256 pre-hash interop.** The reference crate implements only the SHAKE128
  pre-hash, so the other HashML-DSA variants are checked against the FIPS 204 encoding rules
  (`prehash_message_layout` test) rather than against a second implementation.
- **`std` only.** The crate uses the OS RNG and heap allocation.
- Byte buffers returned to the caller (for example `PrivateKey::as_bytes` copies the caller
  makes, or keys derived with `Shell`) are the caller's responsibility to zeroize.
