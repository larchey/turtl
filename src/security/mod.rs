//! Security-focused utilities for the TURTL library.
//!
//! [`constant_time`] holds branchless helpers (conditional move/swap/select and
//! equality) used where the algorithms touch secret data.

pub mod constant_time;

// Re-export commonly used items for convenience
pub use constant_time::{ct_cmov, ct_cswap, ct_eq, ct_select};
