pub mod utils;

use std::hash::{sha256, sha256_var};
use utils::adjust_key;

/// Computes the HMAC-SHA256 of a given message using a provided key.
///
/// # Parameters
///
/// - `key`: A `BoundedVec<u8, M>` representing the secret key used for HMAC computation.
/// - `message`: A `BoundedVec<u8, N>` representing the message to be hashed.
///
/// # Returns
///
/// - A `[u8; 32]` array containing the HMAC-SHA256 result.
///
/// # Steps
///
/// 1. Adjusts the key to ensure it is of the correct length.
/// 2. Creates the inner and outer padded keys by XORing the adjusted key with specific constants.
/// 3. Computes the inner hash by concatenating the inner padded key with the message and hashing the result.
/// 4. Computes the outer hash by concatenating the outer padded key with the inner hash and hashing the result.
///
/// # Example
///
/// ```noir
/// let key: BoundedVec<u8, 64> = BoundedVec::from_array("secret".as_bytes());
/// let message: BoundedVec<u8, 256> = BoundedVec::from_array("hello".as_bytes());
/// let hmac_result = hmac_sha256(key, message);
///
/// ```
pub fn hmac_sha256<let M: u32, let N: u32>(
    key: BoundedVec<u8, M>,
    message: BoundedVec<u8, N>,
) -> [u8; 32] {
    // Step 1: Prepare the key
    let adjusted_key = adjust_key(key);

    // Step 2: Create the inner and outer padded keys
    let inner_key_pad: [u8; 64] = adjusted_key.map(|a| a ^ 0x36);
    let outer_key_pad: [u8; 64] = adjusted_key.map(|a| a ^ 0x5C);

    // Step 3: Perform the inner hash (SHA256(key XOR ipad || message))
    let inner_input: [u8; N + 64] = inner_key_pad.concat(message.storage());
    let inner_hash: [u8; 32] = sha256_var(inner_input, 64 + message.len() as u64);

    // Step 4: Perform the outer hash (SHA256(key XOR opad || inner_hash))
    let outer_input: [u8; 64 + 32] = outer_key_pad.concat(inner_hash);
    let hmac_result: [u8; 32] = sha256(outer_input);

    hmac_result
}

#[test]
fn test_64_length_key() {
    let key: BoundedVec<u8, 64> = BoundedVec::from_array(
        "63E9B5F9DA4584483662FC2E5A48763E9B5F9DA4584483662FC2E5A487FDRYYH".as_bytes(),
    );
    let message: BoundedVec<u8, 256> = BoundedVec::from_array("hello".as_bytes());
    let res = hmac_sha256(key, message);
    let expected: [u8; 32] = [
        243, 14, 222, 21, 160, 253, 85, 19, 34, 12, 79, 201, 14, 138, 30, 175, 153, 185, 22, 108,
        170, 58, 75, 138, 193, 119, 151, 53, 21, 125, 31, 42,
    ];

    for i in 0..32 {
        assert_eq(res[i], expected[i]);
    }
}

#[test]
fn test_small_key() {
    let key: BoundedVec<u8, 64> = BoundedVec::from_array(
        "63E9B5F9DA4584483662FC2E5A48763E9B5F9DA458448366".as_bytes(),
    );
    let message: BoundedVec<u8, 256> = BoundedVec::from_array("hello".as_bytes());
    let res = hmac_sha256(key, message);
    let expected: [u8; 32] = [
        119, 49, 131, 18, 148, 236, 222, 245, 254, 97, 107, 5, 181, 94, 168, 19, 83, 246, 98, 214,
        181, 170, 57, 140, 48, 248, 0, 175, 137, 180, 140, 3,
    ];

    for i in 0..32 {
        assert_eq(res[i], expected[i]);
    }
}

#[test]
fn test_large_key() {
    let key: BoundedVec<u8, 256> = BoundedVec::from_array(
        "63E9B5F9DA4584483662FC2E5A48763E9B5F9DA45844836663E9B5F9DA4584483662FC2E5A48763E9B5F9DA458448366"
            .as_bytes(),
    );
    let message: BoundedVec<u8, 256> = BoundedVec::from_array("hello".as_bytes());
    let res = hmac_sha256(key, message);
    let expected: [u8; 32] = [
        87, 130, 14, 145, 126, 39, 230, 167, 188, 244, 24, 186, 45, 179, 209, 156, 168, 43, 227,
        201, 11, 41, 202, 36, 182, 157, 20, 97, 229, 7, 167, 13,
    ];

    for i in 0..32 {
        assert_eq(res[i], expected[i]);
    }
}

#[test]
fn test_large_message() {
    let key: BoundedVec<u8, 256> = BoundedVec::from_array(
        "63E9B5F9DA4584483662FC2E5A48763E9B5F9DA4584483662FC2E5A487FDRYYH".as_bytes(),
    );
    let message: BoundedVec<u8, 512> = BoundedVec::from_array([52 as u8; 248]);
    let res = hmac_sha256(key, message);
    let expected: [u8; 32] = [
        107, 120, 168, 169, 0, 12, 170, 67, 217, 252, 4, 64, 183, 157, 165, 20, 238, 184, 21, 175,
        122, 110, 79, 86, 153, 5, 176, 138, 202, 205, 144, 227,
    ];

    for i in 0..32 {
        assert_eq(res[i], expected[i]);
    }
}
