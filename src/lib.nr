pub mod utils;
use std::hash::{sha256, sha256_var};

/// Computes the HMAC-SHA256 of a given message using a specified key.
///
/// # Parameters
///
/// - `key`: A byte array representing the key used for HMAC computation. The length of the key is `M`.
/// - `message`: A byte array representing the message to be hashed. The length of the message is `N`.
///
/// # Returns
///
/// A byte array of length 32 representing the HMAC-SHA256 hash of the input message.
///
/// # Steps
///
/// 1. **Prepare the key**: Adjusts the key to the appropriate length.
/// 2. **Create the inner and outer padded keys**: Generates the inner and outer padded keys by XORing the adjusted key with specific constants.
/// 3. **Perform the inner hash**: Computes the SHA256 hash of the concatenation of the inner padded key and the message.
/// 4. **Perform the outer hash**: Computes the SHA256 hash of the concatenation of the outer padded key and the inner hash.
///
/// # Example
///
/// ```noir
/// let key: [u8; 16] = [0x0b; 16];
/// let message: [u8; 8] = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x21, 0x21];
/// let hmac = hmac_sha256(key, message);
/// ```
pub fn hmac_sha256<let M: u32, let N: u32>(key: [u8; M], message: [u8; N]) -> [u8; 32] {
    // Step 1: Prepare the key
    let adjusted_key = utils::adjust_key(key);

    // Step 2: Create the inner and outer padded keys
    let inner_key_pad: [u8; 64] = utils::xor_key(adjusted_key, 0x36);
    let outer_key_pad: [u8; 64] = utils::xor_key(adjusted_key, 0x5C);

    // Step 3: Perform the inner hash (SHA256(key XOR ipad || message))
    let inner_input: [u8; N + 64] = inner_key_pad.concat(message);
    let inner_hash: [u8; 32] = sha256(inner_input);

    // Step 4: Perform the outer hash (SHA256(key XOR opad || inner_hash))
    let outer_input: [u8; 64 + 32] = outer_key_pad.concat(inner_hash);
    let hmac_result: [u8; 32] = sha256(outer_input);

    hmac_result
}

/// Computes the HMAC-SHA256 for a given key and message with a specified length.
///
/// # Arguments
///
/// * `key` - A vector of bytes representing the secret key.
/// * `message` - A vector of bytes representing the message to be hashed.
/// * `length` - A 32-bit unsigned integer representing the length of the message.
///
/// # Returns
///
/// A 32-byte array containing the HMAC-SHA256 result.
///
/// # Steps
///
/// 1. Adjust the key to the appropriate length.
/// 2. Create the inner and outer padded keys by XORing the adjusted key with specific constants.
/// 3. Perform the inner hash by concatenating the inner padded key with the message and applying SHA256.
/// 4. Perform the outer hash by concatenating the outer padded key with the inner hash and applying SHA256 again.
///
/// # Example
///
/// ```noir
/// let key = vec![0x0b; 20];
/// let message = vec![0x48, 0x69, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65];
/// let length = message.len() as u32;
/// let hmac = hmac_sha256_var(key, message, length);
/// ```
pub fn hmac_sha256_var(key: Vec<u8>, message: Vec<u8>, length: u32) -> [u8; 32] {
    // Step 1: Prepare the key
    let adjusted_key = utils::adjust_key_var(key);

    // Step 2: Create the inner and outer padded keys
    let inner_key_pad: [u8; 64] = utils::xor_key(adjusted_key, 0x36);
    let outer_key_pad: [u8; 64] = utils::xor_key(adjusted_key, 0x5C);

    // Step 3: Perform the inner hash (SHA256(key XOR ipad || message))
    let mut inner_input = [0; utils::MAX_MESSAGE_LENGTH + 64];
    for i in 0..64 {
        inner_input[i] = inner_key_pad[i];
    }
    for i in 64..(length + 64) {
        inner_input[i] = message.get(i - 64);
    }

    let inner_hash: [u8; 32] = sha256_var(inner_input, (length + 64) as u64);

    // Step 4: Perform the outer hash (SHA256(key XOR opad || inner_hash))
    let outer_input: [u8; 64 + 32] = outer_key_pad.concat(inner_hash);
    let hmac_result: [u8; 32] = sha256(outer_input);

    hmac_result
}

#[test]
fn test_64_length_key() {
    let key: [u8; 64] = "63E9B5F9DA4584483662FC2E5A48763E9B5F9DA4584483662FC2E5A487FDRYYH".as_bytes();
    let message: [u8; 5] = "hello".as_bytes();
    let res = hmac_sha256(key, message);
    let expected: [u8; 32] = [
        243, 14, 222, 21, 160, 253, 85, 19, 34, 12, 79, 201, 14, 138, 30, 175, 153, 185, 22, 108, 170, 58, 75, 138, 193, 119, 151, 53, 21, 125, 31, 42
    ];

    for i in 0..32 {
        assert_eq(res[i], expected[i]);
    }
}

#[test]
fn test_64_length_key_vec() {
    let key: Vec<u8> = "63E9B5F9DA4584483662FC2E5A48763E9B5F9DA4584483662FC2E5A487FDRYYH".as_bytes_vec();
    let message: Vec<u8> = "hello".as_bytes_vec();
    let res = hmac_sha256_var(key, message, message.len());
    let expected: [u8; 32] = [
        243, 14, 222, 21, 160, 253, 85, 19, 34, 12, 79, 201, 14, 138, 30, 175, 153, 185, 22, 108, 170, 58, 75, 138, 193, 119, 151, 53, 21, 125, 31, 42
    ];

    for i in 0..32 {
        assert_eq(res[i], expected[i]);
    }
}

#[test]
fn test_small_key() {
    let key: [u8; 48] = "63E9B5F9DA4584483662FC2E5A48763E9B5F9DA458448366".as_bytes();
    let message: [u8; 5] = "hello".as_bytes();
    let res = hmac_sha256(key, message);
    let expected: [u8; 32] = [
        119, 49, 131, 18, 148, 236, 222, 245, 254, 97, 107, 5, 181, 94, 168, 19, 83, 246, 98, 214, 181, 170, 57, 140, 48, 248, 0, 175, 137, 180, 140, 3
    ];

    for i in 0..32 {
        assert_eq(res[i], expected[i]);
    }
}

#[test]
fn test_small_key_vec() {
    let key: Vec<u8> = "63E9B5F9DA4584483662FC2E5A48763E9B5F9DA458448366".as_bytes_vec();
    let message: Vec<u8> = "hello".as_bytes_vec();
    let res = hmac_sha256_var(key, message, message.len());
    let expected: [u8; 32] = [
        119, 49, 131, 18, 148, 236, 222, 245, 254, 97, 107, 5, 181, 94, 168, 19, 83, 246, 98, 214, 181, 170, 57, 140, 48, 248, 0, 175, 137, 180, 140, 3
    ];

    for i in 0..32 {
        assert_eq(res[i], expected[i]);
    }
}

#[test]
fn test_large_key() {
    let key: [u8; 96] = "63E9B5F9DA4584483662FC2E5A48763E9B5F9DA45844836663E9B5F9DA4584483662FC2E5A48763E9B5F9DA458448366".as_bytes();
    let message: [u8; 5] = "hello".as_bytes();
    let res = hmac_sha256(key, message);
    let expected: [u8; 32] = [
        87, 130, 14, 145, 126, 39, 230, 167, 188, 244, 24, 186, 45, 179, 209, 156, 168, 43, 227, 201, 11, 41, 202, 36, 182, 157, 20, 97, 229, 7, 167, 13
    ];

    for i in 0..32 {
        assert_eq(res[i], expected[i]);
    }
}

#[test]
fn test_large_key_vec() {
    let key: Vec<u8> = "63E9B5F9DA4584483662FC2E5A48763E9B5F9DA45844836663E9B5F9DA4584483662FC2E5A48763E9B5F9DA458448366".as_bytes_vec();
    let message: Vec<u8> = "hello".as_bytes_vec();
    let res = hmac_sha256_var(key, message, message.len());
    let expected: [u8; 32] = [
        87, 130, 14, 145, 126, 39, 230, 167, 188, 244, 24, 186, 45, 179, 209, 156, 168, 43, 227, 201, 11, 41, 202, 36, 182, 157, 20, 97, 229, 7, 167, 13
    ];

    for i in 0..32 {
        assert_eq(res[i], expected[i]);
    }
}

#[test]
fn test_large_message() {
    let key: [u8; 64] = "63E9B5F9DA4584483662FC2E5A48763E9B5F9DA4584483662FC2E5A487FDRYYH".as_bytes();
    let message: [u8; 248] = [52; 248];
    let res = hmac_sha256(key, message);
    let expected: [u8; 32] = [
        107, 120, 168, 169, 0, 12, 170, 67, 217, 252, 4, 64, 183, 157, 165, 20, 238, 184, 21, 175, 122, 110, 79, 86, 153, 5, 176, 138, 202, 205, 144, 227
    ];

    for i in 0..32 {
        assert_eq(res[i], expected[i]);
    }
}

#[test]
fn test_large_message_vec() {
    let key: Vec<u8> = "63E9B5F9DA4584483662FC2E5A48763E9B5F9DA4584483662FC2E5A487FDRYYH".as_bytes_vec();
    let message: Vec<u8> = Vec::from_slice([52 as u8; 248]);
    let res: [u8; 32] = hmac_sha256_var(key, message, message.len());
    let expected: [u8; 32] = [
        107, 120, 168, 169, 0, 12, 170, 67, 217, 252, 4, 64, 183, 157, 165, 20, 238, 184, 21, 175, 122, 110, 79, 86, 153, 5, 176, 138, 202, 205, 144, 227
    ];

    for i in 0..32 {
        assert_eq(res[i], expected[i]);
    }
}
