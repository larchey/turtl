//! ML-DSA verification implementation.
//!
//! This module implements the verification algorithms for ML-DSA.

use super::internal::{ml_dsa_hash_verify_internal, ml_dsa_verify_internal, pure_message};
use super::{HashFunction, PublicKey, Signature};
use crate::error::{Error, Result};

/// Verify a signature using ML-DSA
pub fn verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
    context: &[u8],
) -> Result<bool> {
    // Check that the parameter sets match
    if public_key.parameter_set() != signature.parameter_set() {
        return Err(Error::InvalidParameterSet);
    }

    let formatted_message = pure_message(message, context)?;

    ml_dsa_verify_internal(
        public_key.as_bytes(),
        &formatted_message,
        signature.as_bytes(),
        public_key.parameter_set(),
    )
}

/// Verify a signature with pre-hashing using ML-DSA
pub fn hash_verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
    context: &[u8],
    hash_function: HashFunction,
) -> Result<bool> {
    // Check that the parameter sets match
    if public_key.parameter_set() != signature.parameter_set() {
        return Err(Error::InvalidParameterSet);
    }

    ml_dsa_hash_verify_internal(
        public_key.as_bytes(),
        message,
        signature.as_bytes(),
        context,
        hash_function,
        public_key.parameter_set(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsa::{key_gen, sign, ParameterSet, SigningMode};

    #[test]
    fn test_verify_valid_signature() -> Result<()> {
        // Generate a key pair with test parameter set
        let (public_key, private_key) = key_gen(ParameterSet::MlDsa44)?;

        // Test message
        let message = b"TURTL test message";
        let context = b"";

        // Sign the message
        let signature = sign(&private_key, message, context, SigningMode::Hedged)?;

        // Verify the signature
        let is_valid = verify(&public_key, message, &signature, context)?;

        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_verify_invalid_signature() -> Result<()> {
        // Generate a key pair with test parameter set
        let (public_key, private_key) = key_gen(ParameterSet::MlDsa44)?;

        // Test message
        let message = b"TURTL test message";
        let wrong_message = b"TURTL wrong message";
        let context = b"";

        // Sign the message
        let signature = sign(&private_key, message, context, SigningMode::Hedged)?;

        // Verify with wrong message
        let is_valid = verify(&public_key, wrong_message, &signature, context)?;

        assert!(!is_valid);
        Ok(())
    }
}
