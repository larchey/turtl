# Adversarial testing

`.github/workflows/adversarial.yml` attacks turtl nightly, on demand, and on PRs that touch
`src/`. Any finding fails the run.

| Job          | What it does                                                                                      | Code                       |
|--------------|---------------------------------------------------------------------------------------------------|----------------------------|
| differential | Seeded, structure-aware mutations of genuine keys/ciphertexts/signatures, checked against `fips203`/`fips204` | `tests/adversarial.rs`     |
| fuzz         | Coverage-guided libFuzzer on the same oracles, one job per target                                 | `fuzz/fuzz_targets/*`      |
| timing       | dudect-style Welch t-tests on decapsulation and `ct_eq`, plus a known-leaky control                | `tests/timing_leakage.rs`  |

## Oracles (`tests/support/oracles.rs`)

Each oracle reads its first input byte as the parameter-set selector and panics on a finding.

- `kem_decaps`: attacker ciphertexts under a fixed key. The shared secret must equal the
  reference's, including the implicit-rejection value.
- `kem_encaps`: attacker encapsulation keys. turtl must accept exactly the keys the reference
  accepts (FIPS 203 modulus check) and encapsulate identically.
- `kem_dk`: attacker decapsulation keys. Acceptance (hash check) and decapsulation must match.
- `dsa_verify`: raw signature bytes, or sparse edits of a genuine signature. The verdict must
  match the reference, and a well-sized signature must never produce `Err`.
- `dsa_pk`, `dsa_sk`: attacker public/private keys. Behaviour must match the reference.
  turtl deliberately rejects private keys with s1/s2 out of range, which the reference signs with.

## Reproducing a finding

```sh
# differential: the failing run prints its seed
TURTL_ADV_SEED=<seed> TURTL_ADV_ITERS=<n> cargo test --release --test adversarial

# fuzz (needs nightly and a C++ compiler); download the crash artifact from the run
cd fuzz && cargo +nightly fuzz run <target> artifacts/<target>/<crash-file>

# timing
cargo test --release --test timing_leakage -- --ignored --test-threads=1 --nocapture
```

## Findings

Weaknesses this harness found during development, both fixed before release:

1. **Secret-dependent timing in ML-KEM decapsulation** (timing job,
   `decaps_zero_vs_random_ciphertext`). Welch's t was about 94; dudect treats anything above 4.5
   as a leak. Causes: `%` by a run-time modulus (a hardware divide) on secret coefficients in the
   NTT and `Polynomial`, and a branch on every bit of the decrypted message m′. Fixed with a
   branch-free Barrett reduction (`src/common/reduce.rs`) and branch-free bit packing; t is now
   about 1–3.
2. **Malformed ML-DSA private keys were accepted** (differential job, `dsa_sk`). Keys with s1/s2
   coefficients outside [-η, η] were accepted by `dsa::PrivateKey::new`, and every `sign` then
   failed. The constructor now validates the encoding.
