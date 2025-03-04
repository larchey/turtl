//! Common functionality shared between ML-KEM and ML-DSA implementations.
//! 
//! This module contains shared utilities including:
//! - Number-Theoretic Transform (NTT) operations
//! - Polynomial arithmetic
//! - Ring arithmetic
//! - Random sampling functions
//! - Encoding/decoding utilities
//! - Hash function wrappers

pub mod ntt;
pub mod poly;
pub mod ring;
pub mod sample;
pub mod coding;
pub mod hash;