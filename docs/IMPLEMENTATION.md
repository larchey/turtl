# TURTL Implementation Notes

Where each part of FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) lives in the code. For what is and
isn't verified, see [SECURITY.md](../SECURITY.md).

## ML-KEM (FIPS 203)

| Spec                                   | Code                                                   |
|----------------------------------------|--------------------------------------------------------|
| ML-KEM.KeyGen_internal (Alg. 16)       | `kem/internal/mod.rs::ml_kem_keygen_internal`          |
| ML-KEM.Encaps_internal (Alg. 17)       | `kem/internal/mod.rs::ml_kem_encaps_internal`          |
| ML-KEM.Decaps_internal (Alg. 18)       | `kem/internal/mod.rs::ml_kem_decaps_internal`          |
| K-PKE.KeyGen / Encrypt / Decrypt       | `kem/internal/k_pke.rs`                                |
| SampleNTT, SamplePolyCBD               | `k_pke.rs::reject_sample_ntt`, `sample_cbd`            |
| ByteEncode/Decode, Compress/Decompress | `k_pke.rs`                                             |
| Input checks (§7.2, §7.3)              | `kem::PublicKey::new`, `kem::PrivateKey::new`          |
| NTT, base-case multiply (q = 3329)     | `common/ntt.rs` (`NTTType::MLKEM`)                     |

Decapsulation selects between `K'` and the implicit-rejection key `K̄` with
`security::constant_time` (no branch on the re-encryption comparison).

`kem::shell::Shell` is a turtl-specific convenience KDF over the shared secret
(SHAKE256 with a length-prefixed label); it is not part of FIPS 203.

## ML-DSA (FIPS 204)

| Spec                                   | Code                                                   |
|----------------------------------------|--------------------------------------------------------|
| ML-DSA.KeyGen_internal (Alg. 6)        | `dsa/internal/mod.rs::ml_dsa_keygen_internal`          |
| ML-DSA.Sign_internal (Alg. 7)          | `dsa/internal/mod.rs::ml_dsa_sign_internal`            |
| ML-DSA.Verify_internal (Alg. 8)        | `dsa/internal/mod.rs::ml_dsa_verify_internal`          |
| HashML-DSA message framing (Alg. 4/5)  | `dsa/internal/mod.rs::prehash_message`                 |
| ExpandA / ExpandS / ExpandMask         | `expand_a`, `expand_s`, `expand_mask`                  |
| SampleInBall (Alg. 29)                 | `sample_in_ball`                                       |
| Power2Round, Decompose, Make/UseHint   | same file                                              |
| NTT, pointwise multiply (q = 8380417)  | `common/ntt.rs` (`NTTType::MLDSA`)                     |

Pure signing builds `M' = 0 || |ctx| || ctx || M` in `dsa/sign.rs` / `dsa/verify.rs`.
`dsa::stamp::Stamp` is a convenience wrapper that holds a private key, mode and context.

## Shared

- `common/reduce.rs`: branch-free Barrett reduction used for all arithmetic on secret data.
- `common/poly.rs`: `Polynomial` (256 `i32` coefficients, zeroized on drop).
- `common/hash.rs`: SHA3-256/512 and SHAKE128/256 wrappers, plus incremental SHAKE contexts.
- `security/constant_time.rs`: branchless select/move/swap and slice equality.
