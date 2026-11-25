//! ML-KEM decapsulation implementation.
//!
//! This module implements the decapsulation algorithm for ML-KEM.

use super::internal::decapsulate_internal;
use super::{Ciphertext, PrivateKey, SharedSecret};
use crate::error::Result;

/// Decapsulate a shared secret using a private key and ciphertext
pub fn decapsulate(private_key: &PrivateKey, ciphertext: &Ciphertext) -> Result<SharedSecret> {
    decapsulate_internal(private_key, ciphertext)
}
