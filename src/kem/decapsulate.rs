//! ML-KEM decapsulation implementation.
//! 
//! This module implements the decapsulation algorithm for ML-KEM.

use crate::error::{Error, Result};
use super::{PrivateKey, Ciphertext, SharedSecret};
use super::internal::{decapsulate_internal};

/// Decapsulate a shared secret using a private key and ciphertext
pub fn decapsulate(private_key: &PrivateKey, ciphertext: &Ciphertext) -> Result<SharedSecret> {
    // Check that the parameter sets match
    if private_key.parameter_set() != ciphertext.parameter_set() {
        return Err(Error::InvalidParameterSet);
    }
    
    decapsulate_internal(private_key, ciphertext)
}