//! Differential fuzzing support for turtl. The oracles live with the test
//! suite (`tests/support/oracles.rs`) so the stable adversarial tests and the
//! fuzz targets share one implementation. See `../ADVERSARIAL.md`.
#[path = "../../tests/support/oracles.rs"]
pub mod oracles;
