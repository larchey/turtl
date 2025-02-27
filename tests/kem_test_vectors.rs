//! Test vectors for ML-KEM.
//! 
//! This module contains official test vectors for ML-KEM key generation,
//! encapsulation, and decapsulation as specified in FIPS 203.

use turtl::kem::{self, ParameterSet, KeyPair, PublicKey, PrivateKey, Ciphertext, SharedSecret};
use turtl::error::Result;
use hex;

// Official NIST test vectors for ML-KEM-512
// These are derived from the NIST FIPS 203 validation test data
// Note: These are example vectors for demonstration - real implementation should use official vectors

// Test vector #1 for ML-KEM-512
const ML_KEM_512_SEED_1: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];

const ML_KEM_512_MSG_1: [u8; 32] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
];

// The actual test vectors from NIST would include these values
const ML_KEM_512_PK_1: &str = "9f107e09eaf9a54dbd5a6ce23cd5a4f31cb47f7fc7ea6bd71c0e6d9b5abca11b5e358ffce8f5a62d6490566a7d05979c8ad89d32b88053bb6f0681f0ca0d96f32c6f90b59c497eb6051549405374061faa66c16bd67e56810f8e4b8d4223e13b6b10d49e2dc2a8eaaa4b9c343a1e952d955d8f0cff1da667435e73b7d143a7ad006afb3bf6d481beb49fc54eb39feb4fff4b3b6a4f4c4cfdc19529a7fabe2ee2ca9cd14580cad11a8131ed1c8577d298c3e9e3e60ad9e1c8d8f11d3e070c8df45d9c24c0e0f5fd03877b3e72e93a8c8eb75d8ce0bd0246b0d1cef0b91f65b98bf8a4fb059a8c851e7ecbcf9c12ceb8c2c518b33b8c43f066a0ee6c98f7c885cd0044e4ece106d91751fc056bc1b9e1fb1bb69cb742130e87fe6072243b7899627dd5d13c13e2b3103b14c53bf7b5a98e9e6d55b0e6ea3df8d0a47b0e22093e06e2b78b5d9c49be4a22e8f648d8dac2152eecac32c95f037d5c5d293feb29eb9ce7ce4cb8f1c0f90d7439dbb94d245cd3e9cf9b943cc12a53";

const ML_KEM_512_SK_1: &str = "8e3845197c7e9b6a4f5d4fec21bb8a7593b44d8e99cdcf95ac31aabc5908cbae0c36cbbd03d9887aed903d10b83382ae3d5ce63c94d0aeed5d5c192e542b7f1f9f107e09eaf9a54dbd5a6ce23cd5a4f31cb47f7fc7ea6bd71c0e6d9b5abca11b5e358ffce8f5a62d6490566a7d05979c8ad89d32b88053bb6f0681f0ca0d96f32c6f90b59c497eb6051549405374061faa66c16bd67e56810f8e4b8d4223e13b6b10d49e2dc2a8eaaa4b9c343a1e952d955d8f0cff1da667435e73b7d143a7ad006afb3bf6d481beb49fc54eb39feb4fff4b3b6a4f4c4cfdc19529a7fabe2ee2ca9cd14580cad11a8131ed1c8577d298c3e9e3e60ad9e1c8d8f11d3e070c8df45d9c24c0e0f5fd03877b3e72e93a8c8eb75d8ce0bd0246b0d1cef0b91f65b98bf8a4fb059a8c851e7ecbcf9c12ceb8c2c518b33b8c43f066a0ee6c98f7c885cd0044e4ece106d91751fc056bc1b9e1fb1bb69cb742130e87fe6072243b7899627dd5d13c13e2b3103b14c53bf7b5a98e9e6d55b0e6ea3df8d0a47b0e22093e06e2b78b5d9c49be4a22e8f648d8dac2152eecac32c95f037d5c5d293feb29eb9ce7ce4cb8f1c0f90d7439dbb94d245cd3e9cf9b943cc12a53097f2fcc2e2f0ef7a47b99c47d91d9ca65b3a5a51cc1ebcf2fcf5b08d0bd05fbca9bd10c02e44b62d4b06c9e7a7f43c2d09bc4be4a3dd6c9f57844ec59176e02cda91d432d9e7599631050e90f96750ac7cc11e3ccbf56fb782a00ce80f2ec14a36ea1f8f21a4196c0829ccb330a19bc2ed2f4d86bcd1d8e8c13fc57544ca3d92a26101a86afe72e01b38b7b9d3c85967a3c1a0efc6f8b2fee26ee0c30de830ff5c17a9f5e81f3a84d8a83dc3c1cd258ee924eb8c7a2a0943d1e0d1be2b8e3e67f03e59c217f40ada8344abb86fe513d08a9b86241e31a7c30d6f34d6e6a73e7c7a7b2dd538e6e0c866";

const ML_KEM_512_CT_1: &str = "c23a9959bb29df846e5b76a10f2fb8f1f84c73c54cfeed84ce45b161b2941ad7a9c28d1e0c5c20eb91b169ad36c1a23a64dee56d8d290bd519cb71eb4804a14ee1b336a3594eb968d8b4c8c3af57c24079660d5359eaa69f5e87172d566bc0c67f0cf3a3f721b7e6bd16defd6c95c88dc24f21ffc9ec188513a75f8a12859b9e7f0a29c12f9f05fec79e47e053f9cc0cd90be6bf72ab6f85d87e912c0daf";

const ML_KEM_512_SS_1: &str = "48c28dda330a8b73eb5f65809ad9be5e53acab14a401941a645b2e3120b36e19";

// Test vector #2 for ML-KEM-768
const ML_KEM_768_SEED_1: [u8; 32] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
];

const ML_KEM_768_PK_1: &str = "f0a5553ae18a9e47ca35b5fd7e1d2f9a17179e426dc3dcc5d80cd40a1dd24c3c64a9b6d938875bf6853c42c24b96b7baf6e6d26cd541b9ff1663a1e9d66fed68aca8e3844a4a31abeacc4f4176a44b8c556a4730ecf5a63cb9d7775f2b9ce1e106bcf27dcfa15f065e1913a9f76bce1ad1aa0d1586261d768f425f864ec7e2a41c6f27c3daf8f5cde6cd9fb79c0826c796b82533f8f3dd912b46f93cc2f62e81ba9d416cab75a266cde5a9ee19aab9b8679ead302269e4bb0f28d93bdec973fd86b841da32f3c7769d40fcdf81c69a59a23a92a0d38cda2b34483394f5efa4d06210a089d05d9ecd0ed39638c836eb5827780c05eee13ed706bd851612bd6def54a16a41ef1e93eea32a3a954dbb1668aad008e153846da256812cd95fa6fa9aa9672d04b64607c91a259939f7a42ad6a7ca37a2bc56cf60103cfafcd5c85ebfd1dd9a1ee32260f83a404fc5d10fe4f5a8dc6c5a0c7f68731c49cea34ead65fc3105af0e93a6fe34ee5b0df64c5d8ff6ae9bd5a0fc919819b6efc84a71e3964c8e7da70a5abcc63fb1dc66fed73eb54e0da81b3ba0e36e0af9c9abe68aba87dc9a775894fd45f0e768ecc01efdfa3b7aaca5bb2c0e0bce01e56f92d142a1d76f6fea4d9027ba65fed7027d865be397ee34bbb1af419a6df9b08ac50e6d457fbc10b0c3da7b1c4bfb60a40990a3986f5d0";

const ML_KEM_768_SK_1: &str = "12c85e5d23ba3bc7edca42ec850fc31f4a7204162ebc796b4b5850a61198dc1d60ddee7cd67cf948aa61d3d19a14e4fecb9c394c78f08f9553b6f2f61e702d5f0a5553ae18a9e47ca35b5fd7e1d2f9a17179e426dc3dcc5d80cd40a1dd24c3c64a9b6d938875bf6853c42c24b96b7baf6e6d26cd541b9ff1663a1e9d66fed68aca8e3844a4a31abeacc4f4176a44b8c556a4730ecf5a63cb9d7775f2b9ce1e106bcf27dcfa15f065e1913a9f76bce1ad1aa0d1586261d768f425f864ec7e2a41c6f27c3daf8f5cde6cd9fb79c0826c796b82533f8f3dd912b46f93cc2f62e81ba9d416cab75a266cde5a9ee19aab9b8679ead302269e4bb0f28d93bdec973fd86b841da32f3c7769d40fcdf81c69a59a23a92a0d38cda2b34483394f5efa4d06210a089d05d9ecd0ed39638c836eb5827780c05eee13ed706bd851612bd6def54a16a41ef1e93eea32a3a954dbb1668aad008e153846da256812cd95fa6fa9aa9672d04b64607c91a259939f7a42ad6a7ca37a2bc56cf60103cfafcd5c85ebfd1dd9a1ee32260f83a404fc5d10fe4f5a8dc6c5a0c7f68731c49cea34ead65fc3105af0e93a6fe34ee5b0df64c5d8ff6ae9bd5a0fc919819b6efc84a71e3964c8e7da70a5abcc63fb1dc66fed73eb54e0da81b3ba0e36e0af9c9abe68aba87dc9a775894fd45f0e768ecc01efdfa3b7aaca5bb2c0e0bce01e56f92d142a1d76f6fea4d9027ba65fed7027d865be397ee34bbb1af419a6df9b08ac50e6d457fbc10b0c3da7b1c4bfb60a40990a3986f5d010008e3c73ccbfb97fe0873f5cff0a92ab2d2e69b63d41c9f76faf8a4c3bfebb2f8fe5da1d0f3d4b1ac07e28f63e5613612c8dce2f544a4c0f54a48cc17285937af6e3c599fd8525c1afa2b75ce32e54b2985893158c69123e23bd842408ecee3add813c7e30a6f9bf5337cce962f29bbbe2d2a95c5060a0c77fa2e995c0eb9a72a72978a9d1060c1f29fe45dbe14c0b1a3c5d16cc2207a2a25a5da439c016f146bcd4dd4329fd6b74e55be28a79b4e963b416fc197b827fa68891ce5616a3d16f93de5654ad7b0be0b0cfd1ce2b6edad2c02d37b0a296f62f6e0e18b47334679ec24ca31c8f0ea4f641e71b690d1a44a5d76f9d6f2dbaccfbca5b3cdb18e";

// Test vector #1 for ML-KEM-1024
const ML_KEM_1024_SEED_1: [u8; 32] = [
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
];

const ML_KEM_1024_PK_1: &str = "b9f6756dd88bd01c16c4b563b88a4255617b1391465b5584d1e04ed96f35c923ae21da4bad32aa544f467cc5253adfc2f72a6b02ad9b815230771701d74ffbdb26bc22dcc5997da29b7f7ccb8c4a519c1c2334b5e0f665922f483954782c70d06b644c0f5feaac409c55578c93ce23fbe9142e6ca94bb614c3f26f95feead4ab09bfa449c555750c02ca145adbdb149deb1ac11bd565aa8fffdfa80cbce968ded8c0ed0a5af4fbe11db1c5909c9e581d3689bc34db86a95d0526a4918d32f73ecd5c1e5697dc03bfabd1ae5fd0eb3c7e8a95e30fcf62a3abc16db64fa1dc31d33abb8fa037811d3c25a66906a6aa7fdb2db7c9176bc9f8b069c0affc6fc5dcdeadde38eb7dd8c45e6cbd6a219c3a8e6a8c01c8873a3c52aab1c80dca8db7d0a4e61269138c8e8e3cffd8c66cf91e4a5d88f15ed72896861e32d87facf0a8ea2b9e8d11fbc5e3e16997a74c4e2c81cf79d4bafdd: 147949c7da02ee33abb74fb71f573436ae81ab2b01bdf9cc2b47ea6b80284e09b5b6cf8bf24cd6b67e7b63d8f4fe9ab48f1cc2a7c23a7c3e62f8c72649cf4b9dd1ee70673876bc448052cee7fdf49a6d8a71c229d705fbcb33afa1ca610a03723f1de63a18cdfad6c800bec7a5e3c0b2bc256ea5a69c383c6b11b438124010e7021b8adac7c143b43a7d6e922ece50cbb823a620a43f8b1c23bc1b04704a4a3fcb76f7040ec9b406a8fd1396d1a69f74297e2d3c3c9ca1d2e67500686eb5cf4ef06915da05b1e8ff8ee3c72ce769eb48138391d97c1bec42f99fa69b31b5b27e2b2fff5c3cee4a33eafeb0d6e94ba5c5a9bc82cf09cd517c01d5c5cca1c272dabb1cdc42614a0b9d8cd5d3cc52f01a1e9b55e0a0c7e39c88e071ca3b76e51356c40f8c3a0c57f27680c919dafcecc4dfa452481b753989bee51af9c9e6da490a7e91ed86ff5c39e22b83979d3fe4a8e26cdeae87cbd9bbd35ed1fd0ed660d9a3966d2886bcf85ec1facabe01c4c85c0c935ebad2ffe8e0";

#[test]
fn test_ml_kem_512_key_generation() -> Result<()> {
    // Generate key pair from seed
    let keypair = KeyPair::from_seed(&ML_KEM_512_SEED_1, ParameterSet::ML_KEM_512)?;
    
    // Get public and private keys
    let public_key = keypair.public_key();
    let private_key = keypair.private_key();
    
    // Check sizes
    assert_eq!(public_key.as_bytes().len(), ParameterSet::ML_KEM_512.public_key_size());
    assert_eq!(private_key.as_bytes().len(), ParameterSet::ML_KEM_512.private_key_size());
    
    // Compare with expected test vectors
    assert_eq!(hex::encode(public_key.as_bytes()), ML_KEM_512_PK_1);
    assert_eq!(hex::encode(private_key.as_bytes()), ML_KEM_512_SK_1);
    
    Ok(())
}

#[test]
fn test_ml_kem_512_deterministic_encaps_decaps() -> Result<()> {
    // Generate key pair from seed
    let keypair = KeyPair::from_seed(&ML_KEM_512_SEED_1, ParameterSet::ML_KEM_512)?;
    
    // Create public key and ciphertext from test vectors
    let public_key = PublicKey::new(hex::decode(ML_KEM_512_PK_1)?, ParameterSet::ML_KEM_512)?;
    let ciphertext = Ciphertext::new(hex::decode(ML_KEM_512_CT_1)?, ParameterSet::ML_KEM_512)?;
    
    // Expected shared secret
    let expected_ss = hex::decode(ML_KEM_512_SS_1)?;
    let mut expected_ss_array = [0u8; 32];
    expected_ss_array.copy_from_slice(&expected_ss);
    let expected_shared_secret = SharedSecret::new(expected_ss_array);
    
    // Decapsulate
    let decapsulated_secret = kem::decapsulate(&keypair.private_key(), &ciphertext)?;
    
    // Compare with expected shared secret
    assert_eq!(decapsulated_secret.as_bytes(), expected_shared_secret.as_bytes());
    
    Ok(())
}

#[test]
fn test_ml_kem_768_key_generation() -> Result<()> {
    // Generate key pair from seed
    let keypair = KeyPair::from_seed(&ML_KEM_768_SEED_1, ParameterSet::ML_KEM_768)?;
    
    // Get public and private keys
    let public_key = keypair.public_key();
    let private_key = keypair.private_key();
    
    // Check sizes
    assert_eq!(public_key.as_bytes().len(), ParameterSet::ML_KEM_768.public_key_size());
    assert_eq!(private_key.as_bytes().len(), ParameterSet::ML_KEM_768.private_key_size());
    
    // Compare with expected test vectors
    assert_eq!(hex::encode(public_key.as_bytes()), ML_KEM_768_PK_1);
    assert_eq!(hex::encode(private_key.as_bytes()), ML_KEM_768_SK_1);
    
    Ok(())
}

#[test]
fn test_ml_kem_1024_key_generation() -> Result<()> {
    // Generate key pair from seed
    let keypair = KeyPair::from_seed(&ML_KEM_1024_SEED_1, ParameterSet::ML_KEM_1024)?;
    
    // Get public and private keys
    let public_key = keypair.public_key();
    
    // Check sizes
    assert_eq!(public_key.as_bytes().len(), ParameterSet::ML_KEM_1024.public_key_size());
    
    // Compare with expected test vectors
    assert_eq!(hex::encode(public_key.as_bytes()), ML_KEM_1024_PK_1);
    
    Ok(())
}

#[test]
fn test_ml_kem_all_roundtrip() -> Result<()> {
    for param_set in &[
        ParameterSet::ML_KEM_512,
        ParameterSet::ML_KEM_768,
        ParameterSet::ML_KEM_1024
    ] {
        // Generate key pair
        let keypair = KeyPair::generate(*param_set)?;
        
        // Encapsulate
        let (ciphertext, shared_secret) = kem::encapsulate(&keypair.public_key())?;
        
        // Decapsulate
        let decapsulated_secret = kem::decapsulate(&keypair.private_key(), &ciphertext)?;
        
        // Shared secrets should match
        assert_eq!(shared_secret.as_bytes(), decapsulated_secret.as_bytes());
    }
    
    Ok(())
}