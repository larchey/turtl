# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-25

First release.

### Algorithms

- **ML-KEM (FIPS 203)**: ML-KEM-512/768/1024 key generation, encapsulation and decapsulation,
  with deterministic entry points (`KeyPair::from_seeds`, `encapsulate_deterministic`) for
  known-answer testing, and the FIPS 203 key input checks.
- **ML-DSA (FIPS 204)**: ML-DSA-44/65/87 key generation, signing and verification; pure and
  pre-hash (HashML-DSA with SHA3-256, SHA3-512, SHAKE128, SHAKE256); hedged and deterministic
  signing; context strings up to 255 bytes. Private keys are range-checked on construction.
- Helpers: `kem::shell::Shell` (SHAKE256 key derivation from a shared secret) and
  `dsa::stamp::Stamp` (a signer bound to a key, mode and context).

### Conformance

- Byte-for-byte agreement with the `fips203` / `fips204` reference implementations for key
  generation, deterministic encapsulation and deterministic signing, plus two-way
  interoperability, for every parameter set.

### Security

- Private keys, shared secrets, seeds and intermediate secrets are zeroized on drop; secret
  types print `<redacted>` under `Debug`; shared-secret equality is constant-time.
- Secret-dependent arithmetic is branch-free and division-free (Barrett reduction). ML-KEM
  decapsulation passes dudect-style fixed-vs-random timing tests.
- `#![forbid(unsafe_code)]`.

### Testing

- Known-answer, interoperability, negative and NTT correctness tests.
- Adversarial testing: differential oracles against the reference implementations driven by
  seeded mutations (`tests/adversarial.rs`) and by libFuzzer (`fuzz/`), timing-leakage tests
  (`tests/timing_leakage.rs`), and a nightly workflow. See `ADVERSARIAL.md`.
