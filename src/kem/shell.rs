//! ML-KEM Shell - Key derivation utilities for ML-KEM shared secrets.
//!
//! The Shell provides a protective layer around the shared secret,
//! making it easy to derive various keys for encryption, authentication, etc.

use super::SharedSecret;
use crate::common::hash::shake256;
use crate::error::{Error, Result};
use zeroize::Zeroizing;

/// ML-KEM Shell for key derivation and usage
#[derive(Clone, Debug)]
pub struct Shell {
    /// The underlying shared secret
    shared_secret: SharedSecret,
}

impl Shell {
    /// Create a new Shell from a shared secret
    pub fn new(shared_secret: SharedSecret) -> Self {
        Self { shared_secret }
    }

    /// Get the raw shared secret
    pub fn shared_secret(&self) -> &SharedSecret {
        &self.shared_secret
    }

    /// Derive an encryption key for AES-256
    pub fn derive_encryption_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        self.derive(ENC_LABEL, &mut key);
        key
    }

    /// Derive an authentication key for HMAC
    pub fn derive_authentication_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        self.derive(AUTH_LABEL, &mut key);
        key
    }

    /// Derive multiple keys at once
    pub fn derive_key_pair(&self) -> ([u8; 32], [u8; 32]) {
        let mut out = Zeroizing::new([0u8; 64]);
        self.derive(PAIR_LABEL, out.as_mut());

        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        key1.copy_from_slice(&out[0..32]);
        key2.copy_from_slice(&out[32..64]);
        (key1, key2)
    }

    /// Derive a key for a caller-chosen purpose (at most 64 bytes of context).
    ///
    /// The labels used by the fixed-purpose methods above (`b"enc-key\0"`,
    /// `b"auth-key\0"`, `b"key-pair\0"`) are reserved and rejected, so a
    /// caller context can never reproduce one of those keys.
    pub fn derive_key_for_context(&self, context: &[u8]) -> Result<[u8; 32]> {
        if context.len() > 64 {
            return Err(Error::EncodingError("Context too long".to_string()));
        }
        if RESERVED_LABELS.contains(&context) {
            return Err(Error::EncodingError(
                "Context is reserved for a built-in key".to_string(),
            ));
        }

        let mut key = [0u8; 32];
        self.derive(context, &mut key);
        Ok(key)
    }

    /// SHAKE256(label || shared_secret).
    ///
    /// The shared secret is always 32 bytes, so the label is recoverable from
    /// the input: distinct labels never share an input.
    fn derive(&self, label: &[u8], out: &mut [u8]) {
        let mut input = Zeroizing::new(Vec::with_capacity(label.len() + 32));
        input.extend_from_slice(label);
        input.extend_from_slice(self.shared_secret.as_bytes());

        let derived = Zeroizing::new(shake256(&input, out.len()));
        out.copy_from_slice(&derived);
    }
}

const ENC_LABEL: &[u8] = b"enc-key\0";
const AUTH_LABEL: &[u8] = b"auth-key\0";
const PAIR_LABEL: &[u8] = b"key-pair\0";
const RESERVED_LABELS: [&[u8]; 3] = [ENC_LABEL, AUTH_LABEL, PAIR_LABEL];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        // Create a dummy shared secret
        let secret_bytes = [42u8; 32];
        let shared_secret = SharedSecret::new(secret_bytes);

        // Create a shell
        let shell = Shell::new(shared_secret);

        // Derive keys
        let enc_key = shell.derive_encryption_key();
        let auth_key = shell.derive_authentication_key();

        // Keys should be different
        assert_ne!(enc_key, auth_key);

        // Keys should be deterministic
        let enc_key2 = shell.derive_encryption_key();
        assert_eq!(enc_key, enc_key2);
    }

    #[test]
    fn test_key_pair_derivation() {
        // Create a dummy shared secret
        let secret_bytes = [42u8; 32];
        let shared_secret = SharedSecret::new(secret_bytes);

        // Create a shell
        let shell = Shell::new(shared_secret);

        // Derive key pair
        let (key1, key2) = shell.derive_key_pair();

        // Keys should be different
        assert_ne!(key1, key2);

        // Keys should be deterministic
        let (key1_again, key2_again) = shell.derive_key_pair();
        assert_eq!(key1, key1_again);
        assert_eq!(key2, key2_again);
    }

    #[test]
    fn test_contextual_key_derivation() {
        // Create a dummy shared secret
        let secret_bytes = [42u8; 32];
        let shared_secret = SharedSecret::new(secret_bytes);

        // Create a shell
        let shell = Shell::new(shared_secret);

        // Derive keys for different contexts
        let key1 = shell.derive_key_for_context(b"context1").unwrap();
        let key2 = shell.derive_key_for_context(b"context2").unwrap();

        // Keys for different contexts should be different
        assert_ne!(key1, key2);

        // Keys for the same context should be the same
        let key1_again = shell.derive_key_for_context(b"context1").unwrap();
        assert_eq!(key1, key1_again);
    }

    #[test]
    fn test_user_context_cannot_collide_with_builtin_keys() {
        let shell = Shell::new(SharedSecret::new([9u8; 32]));
        for label in [&b"enc-key\0"[..], b"auth-key\0", b"key-pair\0"] {
            assert!(shell.derive_key_for_context(label).is_err());
        }
        for label in [&b"enc-key"[..], b"auth-key", b"key-pair", b"enc-key\0\0"] {
            let k = shell.derive_key_for_context(label).unwrap();
            assert_ne!(k, shell.derive_encryption_key());
            assert_ne!(k, shell.derive_authentication_key());
            assert_ne!(k, shell.derive_key_pair().0);
        }
    }

    /// Outputs are unchanged from v1.0.0: SHAKE256(label || shared_secret).
    #[test]
    fn test_outputs_match_v1_0_0() {
        let ss = [9u8; 32];
        let shell = Shell::new(SharedSecret::new(ss));
        let v1 = |label: &[u8], n: usize| shake256(&[label, &ss[..]].concat(), n);
        assert_eq!(shell.derive_encryption_key().to_vec(), v1(b"enc-key\0", 32));
        assert_eq!(
            shell.derive_authentication_key().to_vec(),
            v1(b"auth-key\0", 32)
        );
        let (k1, k2) = shell.derive_key_pair();
        assert_eq!([k1, k2].concat(), v1(b"key-pair\0", 64));
        assert_eq!(
            shell.derive_key_for_context(b"app").unwrap().to_vec(),
            v1(b"app", 32)
        );
    }
}
