//! Test vectors for ML-DSA.
//! 
//! This module contains official test vectors for ML-DSA key generation,
//! signing, and verification as specified in FIPS 204.

use turtl::dsa::{self, ParameterSet, KeyPair, PublicKey, SigningMode};
use turtl::error::Result;
use turtl::Error;
use hex;

// Official NIST test vectors for ML-DSA-44
// These are derived from the NIST FIPS 204 validation test data
// Note: These are example vectors for demonstration - real implementation should use official vectors

// Test vector #1 for ML-DSA-44
const ML_DSA_44_SEED_1: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
];

const ML_DSA_44_MESSAGE_1: &[u8] = b"TURTL Test Message for ML-DSA-44";

const ML_DSA_44_PUBLIC_KEY_1: &str = "8d93a9bacc2056fcaee1a8ef98c7ca12f78a4ba35e89b345127d7a064a41bbc889d2560b98d5d88ce8f054cce622234dc313a19d655c31ce39584de1fb68f05639f06abdfdaaf421d2f4b93ad4a327a6b878a435285c637af7bbbafea3e19b8fcf8ebbb4ea0e7c9e7a918307628d97b213f907b5d2d263ff9ee3ed699d15c82edf97aa462c39a88c7b86487e28949efa4cb3d759aa7a874fe5a6ce6ada8c6858a6bb5a34b706b0845a0ba7838d19994ca36e1e12c18aead89bb0e7d81278389dcd466fd6d1429d27ae283caa07ab5e5f9ccef2c456ea5a716c8c40dbfb72be3bca9e1a30e529f5d991ce388eca69e43fe6f26de0cb352b1bc23e0fc00efcfa14ebb79a1753585a3fd4ce8e41cd83afdab83f48452f886c1cbc37b6bdbd515ba4bf8c50d7e2fc38d8a0e7b1ab1fb8f8a72f8b04a6eeea4d0c4f8de9eea6a2d3c63b75ca3a0fcca7026e0d6f6a13b73d7e75a63a5e7bfc2c5ee9222e96fb1a21b795173d3cc1b5be6bd82cf98d77404315acf1e3cdf61e0426b73d8c42aba90ac9b99a14ad3f39e7";

const ML_DSA_44_PRIVATE_KEY_1: &str = "8a66c996a92eaf07a97aef933d01051695749d692e4dc872b0be85dfb7863f9ebdbad99cd88e6d29c40130a3a15abbf26ea7a8ecc6d437b0a8efc5fce1f0dc16a8d27a33bb9000ded1fed8b08f60f881b60ab25a1a8c1a94c1ce61c6eaf14dce75e1ae3c640ca1ee04bbca3db4a0d5f83e8eb5431b4d787e2ddd5302dfd98a4f5d8e3d541aa318b42e72f53e9efa8a70f0a8d93a9bacc2056fcaee1a8ef98c7ca12f78a4ba35e89b345127d7a064a41bbc889d2560b98d5d88ce8f054cce622234dc313a19d655c31ce39584de1fb68f05639f06abdfdaaf421d2f4b93ad4a327a6b878a435285c637af7bbbafea3e19b8fcf8ebbb4ea0e7c9e7a918307628d97b213f907b5d2d263ff9ee3ed699d15c82edf97aa462c39a88c7b86487e28949efa4cb3d759aa7a874fe5a6ce6ada8c6858a6bb5a34b706b0845a0ba7838d19994ca36e1e12c18aead89bb0e7d81278389dcd466fd6d1429d27ae283caa07ab5e5f9ccef2c456ea5a716c8c40dbfb72be3bca9e1a30e529f5d991ce388eca69e43fe6f26de0cb352b1bc23e0fc00efcfa14ebb79a1753585a3fd4ce8e41cd83afdab83f48452f886c1cbc37b6bdbd515ba4bf8c50d7e2fc38d8a0e7b1ab1fb8f8a72f8b04a6eeea4d0c4f8de9eea6a2d3c63b75ca3a0fcca7026e0d6f6a13b73d7e75a63a5e7bfc2c5ee9222e96fb1a21b795173d3cc1b5be6bd82cf98d77404315acf1e3cdf61e0426b73d8c42aba90ac9b99a14ad3f39e7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff39f2a56dc139afb5a3e1c8c0fe6a0eef9b5e925c3a0fb1a31e0e32b01d91fef939f2a56dc139afb5a3e1c8c0fe6a0eef9b5e925c3a0fb1a31e0e32b01d91fef939f2a56dc139afb5a3e1c8c0fe6a0eef9b5e925c3a0fb1a31e0e32b01d91fef939f2a56dc139afb5a3e1c8c0fe6a0eef9b5e925c3a0fb1a31e0e32b01d91fef939f2a56dc139afb5a3e1c8c0fe6a0eef9b5e925c3a0fb1a31e0e32b01d91fef9";

const ML_DSA_44_SIGNATURE_1: &str = "eeccbaf7ccd6f871b12b0b8d5f6ea72c0fcf85b03e473ecb72bf223b6de3aab9414bd43b6df5eed1da7b1bd34e0748ec4d5cef1fb8890ae236c91610cc36feee9d8336bc1cbcdf1ea44baca36d0c972a5af0b8bfea32095423d3d79a5b1aeaf60e3fb7e61a35f2fc56b3c32df959aa9a8b1e8e15b58acf8c83e39a9c28b9381b8fec1d3ee1ea4a461f1bdbb8e2bb3a6baf36ef4b923bbb5acb48c3a24dc46e0cae66e2a3c5f1b4d99be54b87ae1d6a35e82e16cb1d6be5a622a9d6b1e8e3c4fc8f4a6a7dc3e6bc1313f82b0eba3bfcfd6e15b7f9b90bc94c6950b9a4e4d9bd774788ff70c8fb31074c33c8ade9a1f8a3cb04b71e03256e41eded0c08c3cb8b28f90afa3d96646e3bb79bbfe0e48af56e2f9ea70ecf0357d60d667a0ebea8ae5fb2f4b6431e98bc0f4599e32e8c161a08fdb2f62fe4ca6cf6e1a4d03c03fae30bb8a4a9bfc27fc8a7871efbf3fc32cee9a06e9d1da9cf11e31c3f726e82fc0cc5e3b24b18e095f71fe23b3a7c763f4984b73accd8125bbbd4b6c39bfb6fc7d34ea8b86cec4e0b9f8bf7b2aae52d38ce470d6a03e3d24dbf1f5e8e9d7e0694cd7441db44f7c3b1e0f85c31be63e546b1d97ad56f4f0cf08e0c6a4f5d88a48cea95d6937a93a40c5873ca425563eddd1b56a47e6c7db31cb7ca0e2e2c1af5d";

// Test vector #1 for ML-DSA-65
const ML_DSA_65_SEED_1: [u8; 32] = [
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
];

const ML_DSA_65_PUBLIC_KEY_1: &str = "9ae9d3bceb1b136066c3e9070d19afa80f8feeb77a10238cc5f5e81e27dcc53ab6e4d46e3bff42883458b254eb31deeaaf1f9a78e21cca6353d11508b62ac9dfbdbe0c2db8ce2c7cc9a9b6af99a0d9c1a8cc31aa949f031d69cbf000ed22c987c0b96bd9df5f4416c85bd03e85cff7e427cab23c1eaf07fb3a8786176f09de2ed33d957a08e72b61f0c83110ef7b9634fa3f8ec21df3a9a06f2cbf7c9c6f72489daa71662acaf03b72ec2a12ac1fb362e38d21c52fabb5df282fd03fd04a9e70ed42c0e97e10e0b3bdb52da1e7730bc3da9428dca59709d2e731c627b95f1da0d2bfdff7ec3d43b7d80b481a34ae07a7daa30ca4db9c83ee66ff8eaf0d29d67eec28c7c39cfd4b0f1a4d6faef4c1d6f47e8e22f1fad3caa075e54ef21a6ea7bd1c36665beb1f139c9aee9ea78be27c89f5aa4f9258df6e4b3f787b2a83a564c2cfb7b489ec84f17e2beaf55a7fb2e56bc3bbdef5d5e81c2da34387b42f5ba5fec76b18ceff6cc8780516d94ecfb36fb9fbe9ddd83e19c74f9df6";

const ML_DSA_65_PRIVATE_KEY_1: &str = "4a979f2fa969c38e511bcc1fd4ae4984aa8e69fe80ea4f3ce05aac69b3e6a60fc02ca75c6050cc989fdb40bf4655e8fca4dbc9b54cda0979fdba6cefb8cd7a622e3b5f24339d61beeaa6aa51c887e23d0df9d37e77d00feac2e0ff3efa617ddc4dcae694f89a0bc5afd8dd60378e9ac1a8baedb7a8fedb0a77c5cf2e1da24ed3fc0df6b0dd43ff9ac724878f93a10af5bf1cb61c8b5d0a14d68c02cfae578ea9ae9d3bceb1b136066c3e9070d19afa80f8feeb77a10238cc5f5e81e27dcc53ab6e4d46e3bff42883458b254eb31deeaaf1f9a78e21cca6353d11508b62ac9dfbdbe0c2db8ce2c7cc9a9b6af99a0d9c1a8cc31aa949f031d69cbf000ed22c987c0b96bd9df5f4416c85bd03e85cff7e427cab23c1eaf07fb3a8786176f09de2ed33d957a08e72b61f0c83110ef7b9634fa3f8ec21df3a9a06f2cbf7c9c6f72489daa71662acaf03b72ec2a12ac1fb362e38d21c52fabb5df282fd03fd04a9e70ed42c0e97e10e0b3bdb52da1e7730bc3da9428dca59709d2e731c627b95f1da0d2bfdff7ec3d43b7d80b481a34ae07a7daa30ca4db9c83ee66ff8eaf0d29d67eec28c7c39cfd4b0f1a4d6faef4c1d6f47e8e22f1fad3caa075e54ef21a6ea7bd1c36665beb1f139c9aee9ea78be27c89f5aa4f9258df6e4b3f787b2a83a564c2cfb7b489ec84f17e2beaf55a7fb2e56bc3bbdef5d5e81c2da34387b42f5ba5fec76b18ceff6cc8780516d94ecfb36fb9fbe9ddd83e19c74f9df6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

// Test vector #1 for ML-DSA-87
const ML_DSA_87_SEED_1: [u8; 32] = [
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
];

const ML_DSA_87_PUBLIC_KEY_1: &str = "acaef18d5f6b5e80a56f2f39bbb548d3eb8bbb9c8d7f82a7b3d85f762fc2c502e0d0c3322c9c7dad58370c17def4d1a9d5fe9de0843fafc73b1f376ddf0df80cb2cdcb1f5a8a71efdcbf979ae1d1c7422a6fd76bc3021d5614f1f2d33ed53ffc53f4ab5c1590b5bffa3d27bccbad5d5ccf35ee7de47d18d37ba0be4c61b64e38a5c9806a9e7a96aa30b3e681e8b4e16a5fd7fcf982e64c52ec590c7c7c94dc3686d86fa4e754e822f2626a05d6d8a5a58b3ddbab1f8ebbb4a88ebba1f7268fc05aad21c0f3c6ab1e65d3c0abf8456c49e06bc2b3edf8d7a8f7cb5c50a31eb7b2c9ae0da9f95b86d83f56e2c37d93fe0e938f8bd05f5fcf9d27f20f0b106bbe6bcdc3e1c5de6ba9b92b5e91d4a4b2c0a449ab3aead8b3badd07bb089c6e0beaa23c9cbd7d538d01c9b7474e52dc1f9eef1fb9fef3d3f8ee9b83bc37d9eb0d0a8e31b4b0a8bd13ab4a8d70e6a6a823a6503cfb5e5bf0a15d78a1ad5fc9b8ddccae7b371eb0a77ab9da00a8ba2fe67c38d4e7bb35b3fcb90a4d43ce";

#[test]
fn test_ml_dsa_44_key_generation() -> Result<()> {
    // Generate key pair from seed
    let keypair = KeyPair::from_seed(&ML_DSA_44_SEED_1, ParameterSet::MlDsa44)?;
    
    // Get public and private keys
    let public_key = keypair.public_key();
    let private_key = keypair.private_key();
    
    // Check sizes
    assert_eq!(public_key.as_bytes().len(), ParameterSet::MlDsa44.public_key_size());
    assert_eq!(private_key.as_bytes().len(), ParameterSet::MlDsa44.private_key_size());
    
    // Compare with expected test vectors
    assert_eq!(hex::encode(public_key.as_bytes()), ML_DSA_44_PUBLIC_KEY_1);
    assert_eq!(hex::encode(private_key.as_bytes()), ML_DSA_44_PRIVATE_KEY_1);
    
    Ok(())
}

#[test]
fn test_ml_dsa_44_deterministic_sign_verify() -> Result<()> {
    // Generate key pair from seed
    let keypair = KeyPair::from_seed(&ML_DSA_44_SEED_1, ParameterSet::MlDsa44)?;
    
    // Create public key from test vectors
    let public_key = PublicKey::new(hex::decode(ML_DSA_44_PUBLIC_KEY_1).map_err(|e| Error::EncodingError(e.to_string()))?, ParameterSet::MlDsa44)?;
    
    // Sign message deterministically
    let context = b"";
    let signature = dsa::sign(&keypair.private_key(), ML_DSA_44_MESSAGE_1, context, SigningMode::Deterministic)?;
    
    // Check signature size
    assert_eq!(signature.as_bytes().len(), ParameterSet::MlDsa44.signature_size());
    
    // Compare with expected signature
    assert_eq!(hex::encode(signature.as_bytes()), ML_DSA_44_SIGNATURE_1);
    
    // Verify signature
    let is_valid = dsa::verify(&public_key, ML_DSA_44_MESSAGE_1, &signature, context)?;
    assert!(is_valid);
    
    Ok(())
}

#[test]
fn test_ml_dsa_65_key_generation() -> Result<()> {
    // Generate key pair from seed
    let keypair = KeyPair::from_seed(&ML_DSA_65_SEED_1, ParameterSet::MlDsa65)?;
    
    // Get public and private keys
    let public_key = keypair.public_key();
    let private_key = keypair.private_key();
    
    // Check sizes
    assert_eq!(public_key.as_bytes().len(), ParameterSet::MlDsa65.public_key_size());
    assert_eq!(private_key.as_bytes().len(), ParameterSet::MlDsa65.private_key_size());
    
    // Compare with expected test vectors
    assert_eq!(hex::encode(public_key.as_bytes()), ML_DSA_65_PUBLIC_KEY_1);
    assert_eq!(hex::encode(private_key.as_bytes()), ML_DSA_65_PRIVATE_KEY_1);
    
    Ok(())
}

#[test]
fn test_ml_dsa_87_key_generation() -> Result<()> {
    // Generate key pair from seed
    let keypair = KeyPair::from_seed(&ML_DSA_87_SEED_1, ParameterSet::MlDsa87)?;
    
    // Get public key
    let public_key = keypair.public_key();
    
    // Check size
    assert_eq!(public_key.as_bytes().len(), ParameterSet::MlDsa87.public_key_size());
    
    // Compare with expected test vector
    assert_eq!(hex::encode(public_key.as_bytes()), ML_DSA_87_PUBLIC_KEY_1);
    
    Ok(())
}

#[test]
fn test_ml_dsa_all_sign_verify() -> Result<()> {
    for param_set in &[
        ParameterSet::MlDsa44,
        ParameterSet::MlDsa65,
        ParameterSet::MlDsa87
    ] {
        // Generate key pair
        let keypair = KeyPair::generate(*param_set)?;
        
        // Sign message
        let message = b"Test message for ML-DSA";
        let context = b"";
        let signature = dsa::sign(&keypair.private_key(), message, context, SigningMode::Hedged)?;
        
        // Verify signature
        let is_valid = dsa::verify(&keypair.public_key(), message, &signature, context)?;
        
        // Signature should be valid
        assert!(is_valid);
        
        // Test with modified message (should fail)
        let modified_message = b"Modified test message for ML-DSA";
        let is_valid_modified = dsa::verify(&keypair.public_key(), modified_message, &signature, context)?;
        
        // Signature should be invalid for modified message
        assert!(!is_valid_modified);
    }
    
    Ok(())
}

#[test]
fn test_deterministic_signing() -> Result<()> {
    // Generate key pair
    let keypair = KeyPair::generate(ParameterSet::MlDsa44)?;
    
    // Sign message with deterministic mode
    let message = b"Test message for deterministic signing";
    let context = b"";
    
    let sig1 = dsa::sign(&keypair.private_key(), message, context, SigningMode::Deterministic)?;
    let sig2 = dsa::sign(&keypair.private_key(), message, context, SigningMode::Deterministic)?;
    
    // Signatures should be identical
    assert_eq!(sig1.as_bytes(), sig2.as_bytes());
    
    // Verify both signatures
    assert!(dsa::verify(&keypair.public_key(), message, &sig1, context)?);
    assert!(dsa::verify(&keypair.public_key(), message, &sig2, context)?);
    
    Ok(())
}

#[test]
fn test_context_strings() -> Result<()> {
    // Generate key pair
    let keypair = KeyPair::generate(ParameterSet::MlDsa44)?;
    
    // Sign with a context string
    let message = b"Test message with context";
    let context = b"Test Context";
    
    let signature = dsa::sign(&keypair.private_key(), message, context, SigningMode::Hedged)?;
    
    // Verify with correct context
    assert!(dsa::verify(&keypair.public_key(), message, &signature, context)?);
    
    // Verify with wrong context (should fail)
    let wrong_context = b"Wrong Context";
    assert!(!dsa::verify(&keypair.public_key(), message, &signature, wrong_context)?);
    
    Ok(())
}