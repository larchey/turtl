//! ML-KEM encapsulation implementation.
//! 
//! This module implements the encapsulation algorithm for ML-KEM.

use crate::error::{Error, Result};
use super::{PublicKey, Ciphertext, SharedSecret};
use super::internal::{encapsulate_internal};

/// Encapsulate a shared secret using a public key
pub fn encapsulate(public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
    encapsulate_internal(public_key)
}