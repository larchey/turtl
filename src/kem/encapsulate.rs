//! ML-KEM encapsulation implementation.
//!
//! This module implements the encapsulation algorithm for ML-KEM.

use super::internal::encapsulate_internal;
use super::{Ciphertext, PublicKey, SharedSecret};
use crate::error::Result;

/// Encapsulate a shared secret using a public key
pub fn encapsulate(public_key: &PublicKey) -> Result<(Ciphertext, SharedSecret)> {
    encapsulate_internal(public_key)
}
