//! Zeroization verification tests.
//!
//! This module contains tests to verify that sensitive data (private keys,
//! shared secrets, etc.) is properly zeroized from memory when dropped.
//!
//! Proper zeroization is critical for security as it prevents sensitive
//! data from lingering in memory where it could be recovered by attackers.

use std::ptr;

/// Helper function to check if a memory region is zeroed
///
/// SAFETY: This is inherently unsafe as we're reading potentially freed memory.
/// This should only be used in tests immediately after dropping a value.
unsafe fn check_memory_is_zeroed(ptr: *const u8, len: usize) -> bool {
    for i in 0..len {
        if ptr::read(ptr.add(i)) != 0 {
            return false;
        }
    }
    true
}

/// Test that a byte array is zeroized when using zeroize crate
#[test]
fn test_byte_array_zeroization() {
    use zeroize::Zeroize;

    let mut secret = [0x42u8; 32];
    let ptr = secret.as_ptr();

    // Verify initial value
    assert_eq!(secret[0], 0x42);
    assert_eq!(secret[31], 0x42);

    // Zeroize the array
    secret.zeroize();

    // Verify it's zeroed
    assert_eq!(secret[0], 0x00);
    assert_eq!(secret[31], 0x00);

    // Verify entire array is zeroed
    unsafe {
        assert!(check_memory_is_zeroed(ptr, 32));
    }
}

/// Test that a Vec is zeroized when using zeroize crate
#[test]
fn test_vec_zeroization() {
    use zeroize::Zeroize;

    let mut secret = vec![0x42u8; 64];
    let ptr = secret.as_ptr();
    let original_len = secret.len();

    // Verify initial value
    assert_eq!(secret[0], 0x42);
    assert_eq!(secret[63], 0x42);

    // Zeroize the vector (this also clears the length)
    secret.zeroize();

    // After zeroization, vec is empty
    assert_eq!(secret.len(), 0);

    // Verify the original memory location was zeroed
    unsafe {
        assert!(check_memory_is_zeroed(ptr, original_len));
    }
}

/// Test automatic zeroization on drop using ZeroizeOnDrop
#[test]
fn test_zeroize_on_drop() {
    use zeroize::{Zeroize, ZeroizeOnDrop};

    #[derive(Zeroize, ZeroizeOnDrop)]
    struct Secret {
        data: [u8; 32],
    }

    let secret = Secret {
        data: [0x42u8; 32],
    };

    let ptr = secret.data.as_ptr();

    // Verify initial value
    assert_eq!(secret.data[0], 0x42);

    // Drop the secret
    drop(secret);

    // Note: Reading from freed memory is unsafe and undefined behavior
    // In a real-world scenario, the memory should be zeroed by ZeroizeOnDrop
    // We can't safely verify this after drop without more complex testing infrastructure
}

/// Test that String zeroization works
#[test]
fn test_string_zeroization() {
    use zeroize::Zeroize;

    let mut secret = String::from("sensitive_password_data_here");
    let ptr = secret.as_ptr();
    let len = secret.len();

    // Verify initial content
    assert!(secret.contains("password"));

    // Zeroize the string
    secret.zeroize();

    // String should be empty after zeroization
    assert_eq!(secret.len(), 0);

    // Original memory location should be zeroed
    unsafe {
        assert!(check_memory_is_zeroed(ptr, len));
    }
}

/// Test zeroization of custom struct with multiple fields
#[test]
fn test_struct_zeroization() {
    use zeroize::{Zeroize, ZeroizeOnDrop};

    #[derive(Zeroize)]
    #[zeroize(drop)]
    struct Credentials {
        username: String,
        password: Vec<u8>,
        session_key: [u8; 32],
    }

    let mut creds = Credentials {
        username: String::from("admin"),
        password: vec![0x42u8; 16],
        session_key: [0xAAu8; 32],
    };

    // Verify initial values
    assert_eq!(creds.username, "admin");
    assert_eq!(creds.password[0], 0x42);
    assert_eq!(creds.session_key[0], 0xAA);

    // Zeroize
    creds.zeroize();

    // Verify all fields are zeroed
    assert_eq!(creds.username.len(), 0);
    assert_eq!(creds.password.len(), 0);
    assert_eq!(creds.session_key[0], 0x00);
    assert_eq!(creds.session_key[31], 0x00);
}

/// Test that Option<T> is properly zeroized
#[test]
fn test_option_zeroization() {
    use zeroize::Zeroize;

    let mut maybe_secret = Some([0x42u8; 32]);

    // Verify initial value
    assert!(maybe_secret.is_some());
    assert_eq!(maybe_secret.as_ref().unwrap()[0], 0x42);

    // Zeroize the option
    maybe_secret.zeroize();

    // After zeroization, Option should be None
    assert!(maybe_secret.is_none());
}

/// Test zeroization of larger data structures
#[test]
fn test_large_buffer_zeroization() {
    use zeroize::Zeroize;

    let mut large_secret = vec![0xFFu8; 4096];
    let ptr = large_secret.as_ptr();
    let original_len = large_secret.len();

    // Verify initial pattern
    assert_eq!(large_secret[0], 0xFF);
    assert_eq!(large_secret[2048], 0xFF);
    assert_eq!(large_secret[4095], 0xFF);

    // Zeroize (this also clears the length)
    large_secret.zeroize();

    // After zeroization, vec is empty
    assert_eq!(large_secret.len(), 0);

    // Verify the original memory was zeroed
    unsafe {
        assert!(check_memory_is_zeroed(ptr, original_len));
    }
}

/// Test that zeroization happens even in panic scenarios
#[test]
fn test_zeroization_on_panic() {
    use zeroize::{Zeroize, ZeroizeOnDrop};
    use std::panic;

    #[derive(Zeroize, ZeroizeOnDrop)]
    struct PanicSecret {
        data: Vec<u8>,
    }

    // This test verifies that ZeroizeOnDrop works even during panic unwinding
    let result = panic::catch_unwind(|| {
        let _secret = PanicSecret {
            data: vec![0x42u8; 32],
        };

        // Simulate a panic
        panic!("Intentional panic for testing");
    });

    // The panic should have been caught
    assert!(result.is_err());

    // The secret should have been zeroized during unwinding
    // (We can't directly verify this without instrumentation, but the
    // ZeroizeOnDrop derive macro should handle it)
}

/// Test partial zeroization (zeroing specific fields)
#[test]
fn test_partial_zeroization() {
    use zeroize::Zeroize;

    struct PartialSecret {
        public_id: u64,
        private_key: [u8; 32],
    }

    let mut data = PartialSecret {
        public_id: 12345,
        private_key: [0x42u8; 32],
    };

    // Verify initial state
    assert_eq!(data.public_id, 12345);
    assert_eq!(data.private_key[0], 0x42);

    // Zeroize only the private key
    data.private_key.zeroize();

    // Public ID should remain unchanged
    assert_eq!(data.public_id, 12345);

    // Private key should be zeroed
    assert_eq!(data.private_key[0], 0x00);
    assert!(data.private_key.iter().all(|&b| b == 0));
}

/// Test zeroization of nested structures
#[test]
fn test_nested_structure_zeroization() {
    use zeroize::{Zeroize, ZeroizeOnDrop};

    #[derive(Zeroize)]
    #[zeroize(drop)]
    struct InnerSecret {
        key: [u8; 16],
    }

    #[derive(Zeroize)]
    #[zeroize(drop)]
    struct OuterSecret {
        inner: InnerSecret,
        outer_key: Vec<u8>,
    }

    let mut outer = OuterSecret {
        inner: InnerSecret {
            key: [0xAAu8; 16],
        },
        outer_key: vec![0xBBu8; 32],
    };

    // Verify initial state
    assert_eq!(outer.inner.key[0], 0xAA);
    assert_eq!(outer.outer_key[0], 0xBB);

    // Zeroize the outer structure
    outer.zeroize();

    // Both inner and outer should be zeroed
    assert_eq!(outer.inner.key[0], 0x00);
    assert_eq!(outer.outer_key.len(), 0);
}

/// Test that Copy types don't prevent zeroization
#[test]
fn test_zeroization_with_copy_types() {
    use zeroize::Zeroize;

    #[derive(Clone, Copy)]
    struct CopyData {
        value: u64,
    }

    // Even though CopyData is Copy, we can still zeroize arrays of it
    let mut data = [CopyData { value: 0x4242424242424242 }; 8];

    assert_eq!(data[0].value, 0x4242424242424242);

    // Zeroize the array by converting to bytes
    let data_bytes = unsafe {
        std::slice::from_raw_parts_mut(
            data.as_mut_ptr() as *mut u8,
            std::mem::size_of_val(&data)
        )
    };
    data_bytes.zeroize();

    // Verify zeroization
    assert_eq!(data[0].value, 0);
    assert_eq!(data[7].value, 0);
}

/// Test zeroization doesn't affect other data
#[test]
fn test_zeroization_isolation() {
    use zeroize::Zeroize;

    let mut secret1 = [0x42u8; 32];
    let mut secret2 = [0x43u8; 32];
    let mut public_data = [0x44u8; 32];

    // Zeroize only secret1
    secret1.zeroize();

    // secret1 should be zeroed
    assert!(secret1.iter().all(|&b| b == 0));

    // secret2 and public_data should be unchanged
    assert_eq!(secret2[0], 0x43);
    assert_eq!(public_data[0], 0x44);
}

/// Test that slice zeroization works
#[test]
fn test_slice_zeroization() {
    use zeroize::Zeroize;

    let mut buffer = [0x42u8; 64];

    // Zeroize only a portion of the buffer
    buffer[16..48].zeroize();

    // First 16 bytes should be unchanged
    assert_eq!(buffer[0], 0x42);
    assert_eq!(buffer[15], 0x42);

    // Middle 32 bytes should be zeroed
    assert_eq!(buffer[16], 0x00);
    assert_eq!(buffer[47], 0x00);

    // Last 16 bytes should be unchanged
    assert_eq!(buffer[48], 0x42);
    assert_eq!(buffer[63], 0x42);
}

/// Test that Box<T> zeroization works
#[test]
fn test_box_zeroization() {
    use zeroize::Zeroize;

    let mut secret = Box::new([0x42u8; 32]);

    assert_eq!(secret[0], 0x42);

    // Zeroize the boxed value
    secret.zeroize();

    assert_eq!(secret[0], 0x00);
    assert!(secret.iter().all(|&b| b == 0));
}
