//! Security-focused utilities for the TURTL library.
//! 
//! This module contains security-related functionality for protecting against
//! various attacks, including side-channel attacks (timing, power analysis) and
//! fault injection attacks.
//! 
//! The components in this module are designed to ensure that the cryptographic
//! operations in TURTL remain secure even in the presence of sophisticated
//! physical attacks on the implementation.

pub mod constant_time;
pub mod fault_detection;

// Re-export commonly used items for convenience
pub use constant_time::{ct_select, ct_cmov, ct_cswap};
pub use fault_detection::{ct_eq, verify_re_encryption, verify_bounds};