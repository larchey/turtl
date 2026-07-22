# TURTL — Security & FIPS Conformance Status

**Last updated:** 2026-07-22

This document records the state of turtl's ML-KEM (FIPS 203) and ML-DSA (FIPS 204)
implementations: what has been verified, and the known limitations that remain before
turtl should be relied on in production.

## Verified

Conformance is checked against the vetted reference implementations `fips203` and `fips204`
(used as dev-dependencies) — a compliant implementation is byte-compatible with any other.

- **Interoperability** (`tests/fips_interop.rs`, all 6 parameter sets): the reference
  encapsulates to turtl's keys and decapsulates turtl's ciphertexts; turtl and the reference
  verify each other's signatures. Both directions, both algorithms.
- **Deterministic keygen** (`tests/keygen_kat.rs`, all 6 parameter sets): turtl's
  keygen-from-seed reproduces the reference's public **and** private keys byte-for-byte — the
  property NIST's Known-Answer-Test vectors check.
- **NTT correctness**: ML-KEM base-case (negacyclic) multiplication and ML-DSA pointwise
  multiplication both match schoolbook polynomial multiplication.
- The full test suite runs the real production code path (no `#[cfg(test)]` algorithm stubs).

## Known limitations (do not treat as production-ready yet)

1. **Side-channel / constant-time.** The primitives in `security::constant_time` are branchless,
   but the higher-level algorithms still contain secret-dependent control flow and non-constant-time
   arithmetic (rejection-sampling loops, `Decompose`, infinity-norm early-exit checks, and `%`/`/`
   on secret coefficients in compression). turtl is **not** hardened against timing/power
   side-channels. A `dudect`-style timing harness and a `subtle`-based rewrite of the secret-dependent
   paths are needed.
2. **Zeroization is incomplete.** Key/ciphertext byte buffers are zeroized on drop, but many
   intermediate secrets (expanded seeds, sampled `s`/`e`/`y`, decoded private-key polynomials) are
   not.
3. **No independent audit.** Correctness is cross-checked against a reference, but the implementation
   has not had a professional cryptographic review. Do not use it to protect real data until it has.
4. **Signature KATs.** Deterministic signing is not yet asserted byte-for-byte against reference
   vectors (interop exercises sign/verify end-to-end, which covers correctness but not exact-byte
   reproduction).
5. **`no_std`.** Despite the `no-std` category, the crate uses `alloc` (`Vec`/`String`/`format!`)
   without feature-gating and is not currently `no_std`-buildable.

## History

This file previously held a pre-remediation review that found turtl was self-consistent but not
FIPS-interoperable (wrong ML-KEM NTT multiplication, reversed key layout, biased `SampleInBall`,
ML-KEM-style matrix sampling in ML-DSA, and a test suite built on stubs). Those correctness issues
have been fixed and are covered by the tests above; see the git history for the individual changes.
