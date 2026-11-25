//! Secret types must not leak their contents through `Debug`.

/// Debug output of secret types must not reveal key or secret bytes.
#[test]
fn test_secret_debug_is_redacted() {
    let kp =
        turtl::kem::KeyPair::from_seed(&[7u8; 32], turtl::kem::ParameterSet::MlKem512).unwrap();
    let (_, ss) = turtl::kem::encapsulate(&kp.public_key()).unwrap();
    let dsa_kp =
        turtl::dsa::KeyPair::from_seed(&[7u8; 32], turtl::dsa::ParameterSet::MlDsa44).unwrap();

    for s in [
        format!("{:?}", kp.private_key()),
        format!("{:?}", ss),
        format!("{:?}", dsa_kp.private_key()),
    ] {
        assert!(s.contains("redacted"), "{s}");
        assert!(s.len() < 200, "debug output looks like it dumps bytes: {s}");
    }
}
