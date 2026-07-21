# TURTL Security Review — Pre-v1 Assessment

**Date:** 2026-07-21
**Scope:** Full manual review of `turtl` crate (`src/`), ML-KEM (FIPS 203) and ML-DSA (FIPS 204) implementations.
**Reviewer:** Manual code audit (no automated tooling relied upon).

## Verdict

**Not ready for v1. Do not release or publish as a security-providing library in its current state.**

TURTL presents itself as a FIPS 203/204 post-quantum library with constant-time operation,
zeroization, and fault-attack countermeasures. The review found that **none of those three
security claims hold as implemented**, that the algorithms **deviate from the standards in ways
that break interoperability**, and — most importantly — that **the test suite validates none of
this**, because the real algorithms are replaced by deterministic stubs under `#[cfg(test)]` and
the "NIST test vectors" are admittedly fake.

The green CI checkmark is therefore meaningless as evidence of correctness or security. Getting to
a trustworthy v1 is not a bug-fix exercise; it requires re-validating the entire implementation
against real Known-Answer-Tests (KATs) and re-doing the side-channel and countermeasure work.

Severity legend: **[CRIT]** disqualifying · **[HIGH]** must fix before v1 · **[MED]** should fix ·
**[LOW]** cleanup.

---

## CRITICAL

### C1 — The test suite does not exercise the real cryptography  `[CRIT]`
There are **50** `#[cfg(test)]` blocks in `src/`, and many replace the actual algorithm with a
deterministic placeholder:

- `src/dsa/verify.rs:19-34` — for `ParameterSet::TestSmall`, `verify()` returns `Ok(true)` for
  essentially every input (with two hardcoded string special-cases that return `false`). The DSA
  verification tests validate a stub, not ML-DSA.
- `src/dsa/sign.rs:19-53` — `sign()` returns a SHA3-256 hash padded to 100 bytes for `TestSmall`.
  Not a signature.
- `src/dsa/internal/mod.rs:16-37` — keygen uses a hardcoded fixed seed for `TestSmall`.
- `src/common/sample.rs` — every sampler (`sample_ntt`, `sample_cbd`, `sample_bounded_poly`,
  `sample_uniform_poly`, `SampleInBall::sample`) has a `#[cfg(test)]` branch returning trivial
  deterministic patterns instead of sampling.

Consequence: `cargo test` passing tells you nothing about whether ML-KEM/ML-DSA are correct or
secure. This must be removed. Tests must run the same code path as production.

### C2 — There are no real Known-Answer-Tests  `[CRIT]`
`tests/kem_test_vectors.rs` states in-file: *"Simplified vectors for testing — these are just
examples, not real NIST test vectors"* and `test_ml_kem_all_roundtrip` / 
`test_ml_kem_512_deterministic_encaps_decaps` deliberately **do not call** `encapsulate` /
`decapsulate` (*"Not actually testing the roundtrip since we're having issues with test vectors"*).
They only assert on parameter constants.

Consequence: the implementation has never been shown to (a) round-trip its own output, let alone
(b) interoperate with any reference implementation. For a crypto library this is the single most
important missing artifact. Fix: import the NIST ACVP / FIPS 203/204 KAT vectors and assert exact
byte equality of keys, ciphertexts, signatures, and shared secrets on the real code path.

### C3 — ML-KEM key generation does not follow FIPS 203 (interop break)  `[CRIT]`
`src/kem/internal/mod.rs:36-71`, `ml_kem_keygen_internal`:
- It derives `(ρ, ρ', K)` as `SHAKE256(seed ‖ k ‖ 0x00, 128)` split into `rho[32] ‖ rhoprime[64]
  ‖ key[32]`. FIPS 203 KeyGen_internal uses `(ρ, σ) ← G(d ‖ k)` where **G = SHA3-512** (64 bytes),
  `σ` is **32 bytes**, and the implicit-rejection value `z` is an **independent 32-byte input**,
  not derived from the same hash.
- Using SHAKE256 instead of G, a 64-byte `ρ'`, an extra `0x00` domain byte, and a derived `z`
  are all non-standard. This structure looks like ML-DSA's expansion grafted onto ML-KEM.

Consequence: keys/ciphertexts will not interoperate with any FIPS 203 implementation, and the
security proof (which assumes `z` independent and `G` as specified) does not transfer. Same class
of concern should be re-checked for the ML-DSA keygen expansion.

### C4 — "Constant-time" module is not constant-time  `[CRIT]`
`src/security/constant_time.rs`: every helper derives its mask with
`let mask = if cond { 0xffff... } else { 0 };` (e.g. lines 23, 42, 61, 80, 99, …). Selecting a mask
with a branch on the secret condition defeats the purpose; the compiler is free to emit a branch.
`ct_eq_u32/64/128` (lines 302-346) reduce to `diff == 0`, a boolean comparison, not a folded
constant-time result. `ct_is_zero_*` return `(z >> n) == 1` likewise.

The correct pattern derives the mask arithmetically without a branch (e.g.
`0u32.wrapping_sub(cond as u32)`), and equality returns a masked word the caller consumes without
branching — or simply uses the `subtle` crate. As written, the module gives false assurance.

### C5 — Secret-dependent branching and variable-time arithmetic throughout  `[CRIT]`
Even if C4 were fixed, the actual algorithms branch on and divide by secret data:
- Secret sampling rejection loops (`sample_bounded_poly` `dsa/internal/mod.rs:681`, `expand_s`)
  have data-dependent iteration counts and `break`s.
- `decompose_coefficient` (`dsa/internal/mod.rs:941`) and the KEM `compress`/`decompress`
  (`kem/internal/k_pke.rs:765-803`) use `%` and `/` on secret coefficients — variable-time on many
  targets.
- The signing norm checks (`infinity_norm_centered … break`, lines 222-271) branch on secret
  intermediate values.

Consequence: the library is exposed to timing side-channels on secret key material. Claiming
"all cryptographic operations are implemented to run in constant time" (`kem/mod.rs:33`) is
inaccurate.

### C6 — `SampleInBall` is biased and non-interoperable  `[CRIT / HIGH]`
`dsa/internal/mod.rs:777-826`: positions are chosen with
`j = (u16 from 2 bytes) % (i + 1)` (line 810), which introduces modulo bias. FIPS 204 SampleInBall
uses **rejection** (draw one byte, reject if `> i`). The sign-bit handling (32 bytes squeezed,
indexed `i % len`) also deviates from the spec's first-8-bytes convention. Result: the challenge
distribution is biased (weakens EUF-CMA margins) **and** the output is not interoperable with
reference ML-DSA.

---

## HIGH

### H1 — Fault-detection countermeasures are non-functional theater  `[HIGH]`
- `security/fault_detection.rs:96` `verify_shared_secret_integrity(ss1, ss2)` is called in
  `kem/internal/mod.rs:203-204` as `verify_…(&shared_secret, &shared_secret.clone())` — comparing a
  value to a copy of itself. Always equal; detects nothing.
- `kem/internal/mod.rs:195` computes `_verification_result` and immediately discards it.
- DSA "double verification" (`dsa/verify.rs:56-73`, `120-141`) runs the identical deterministic
  function twice and compares. A deterministic recomputation catches only transient single faults
  and doubles the timing surface; it is not the FIPS-recommended countermeasure and gives false
  assurance.

These should either be implemented as real countermeasures or removed and not advertised.

### H2 — Silent coefficient clamping corrupts keys/signatures  `[HIGH]`
`encode_poly_signed` (`dsa/internal/mod.rs:1651-1665`) clamps any out-of-range coefficient to the
min/max of the field and prints a warning to stderr, rather than returning an error. Encoding
secret-key or signature coefficients that are out of range should be a hard failure — clamping
silently produces a malformed, invalid, or subtly weakened artifact and hides the underlying bug.

### H3 — Unbounded rejection loops on attacker-influenced input (DoS)  `[HIGH]`
- `reject_sample_ntt` (`kem/internal/k_pke.rs:432`, `dsa/internal/mod.rs:613`) loops
  `while j < 256` with no iteration cap.
- `sample_uniform_poly` (`dsa/internal/mod.rs:855`) loops `while !valid_coeff` with no cap.

`expand_a` runs `reject_sample_ntt` on `ρ` taken directly from an untrusted public key during
verification, so a crafted/adversarial input that fails to yield 256 in-range coefficients causes an
unbounded loop. Add a bounded iteration count and return an error on exhaustion.

### H4 — Library prints to stderr and is not actually `no_std`  `[HIGH]`
`Cargo.toml` advertises `categories = ["no-std"]` and a `no_std` story, but the code uses `Vec`,
`String`, `format!`, and **`eprintln!`** (e.g. `dsa/internal/mod.rs:315-318`, `1655`, `1662`;
debug prints in decode paths) with no `alloc`/`std` feature gating. It will not build `no_std`, and
a cryptographic library must never print to stderr in production (information leak + noise). Remove
all `eprintln!`/`println!` from `src/` and gate `alloc` usage properly or drop the `no_std` claim.

---

## MEDIUM

- **M1 — Dead, dangerous sampler module.** `src/common/sample.rs` is unused in production (only its
  own tests reference `RejectionSampler`/`SampleInBall`), and its `sample_bounded_poly` uses a
  broken acceptance bound `< 15 - 5 + 2*eta + 1` with mapping `b - eta`, producing coefficients far
  outside `[-eta, eta]`. Delete the file so it can't be wired in by mistake.
- **M2 — `sample_uniform_poly` distribution.** The mask-and-shift acceptance in
  `dsa/internal/mod.rs:842-880` is close to uniform for power-of-two `γ1` but is not the FIPS 204
  `ExpandMask` construction; validate against KATs once C2 is in place.
- **M3 — 25 `.unwrap()` calls in `src/`.** Audit each; a panic in a crypto routine on
  attacker-supplied input is a DoS. `SHAKE*Context::squeeze` `.as_mut().unwrap()` and slice indexing
  in samplers are the ones to check first.
- **M4 — KEM decaps length branch.** `kem/internal/mod.rs:132-139` early-returns `false` on length
  mismatch before the constant-time compare. Harmless for well-formed ciphertext (length is checked
  at construction) but tighten for defense in depth.

## LOW / HYGIENE

- **L1 — Duplicate manifest.** Both `cargo.toml` and `Cargo.toml` exist (case-sensitive FS = two
  files). Remove the stale lowercase `cargo.toml`.
- **L2 — Doc claims vs. reality.** Module docs assert constant-time, automatic zeroization, and
  fault detection as facts (`kem/mod.rs:29-38`). Until C4/C5/H1 are resolved, these are misleading;
  soften or remove.
- **L3 — Zeroization gaps.** Key/ciphertext byte `Vec`s are zeroized on drop, but many intermediate
  secrets (expanded seeds, `sigma`/`rhoprime`, sampled polynomials `s`, `e`, `y`, `cs1`, decoded
  private-key `Vec`s in `decode_private_key`) are plain heap values never zeroized. Sweep the secret
  intermediates.

---

## Recommended path to a trustworthy v1

1. **Rip out all `#[cfg(test)]` algorithm stubs** (C1) and delete `common/sample.rs` (M1). Make
   tests run the production path only.
2. **Wire in real NIST KATs** (C2) for ML-KEM-512/768/1024 and ML-DSA-44/65/87 — assert exact bytes
   for keygen (deterministic from seed), encaps/decaps, sign (deterministic mode)/verify. Nothing
   else below matters until this is green on the real path.
3. **Fix the standards deviations** the KATs will expose — starting with KEM keygen expansion (C3)
   and `SampleInBall` (C6).
4. **Redo constant-time properly** (C4/C5): adopt `subtle`, remove secret-dependent branches and
   `%`/`/` on secrets, and add a `dudect`-style timing test to CI.
5. **Either implement real fault countermeasures or delete them** (H1); stop clamping (H2); bound
   all rejection loops (H3); purge `eprintln!` and fix/withdraw the `no_std` claim (H4).
6. Independent third-party review before anything is labeled production-ready.

Until at least steps 1–4 are complete, this crate should carry a prominent "experimental, not for
production use" notice, and `turtl-pki` (which builds real TLS certs on top of it) should not be
used to protect anything.
