use std::hash::{sha256, sha256_var};

pub global MAX_KEY_LENGTH: u32 = 256;
pub global MAX_MESSAGE_LENGTH: u32= 512;

/// XORs each byte of the given key with the specified pad byte.
///
/// # Arguments
///
/// * `key` - A 64-byte array representing the key to be XORed.
/// * `pad_byte` - A single byte used to XOR each byte of the key.
///
/// # Returns
///
/// A 64-byte array where each byte is the result of XORing the corresponding byte of the key with the pad byte.
///
/// # Example
///
/// ```
/// let key: [u8; 64] = [0x1F; 64];
/// let pad_byte: u8 = 0xAA;
/// let result = xor_key(key, pad_byte);
/// assert_eq!(result, [0xB5; 64]);
/// ```
pub fn xor_key(key: [u8; 64], pad_byte: u8) -> [u8; 64] {
    let mut result: [u8; 64] = [0 as u8; 64];
    for i in 0..64 {
        result[i] = key[i] ^ pad_byte;
    }
    result
}

/// Adjusts the provided key to a fixed length of 64 bytes.
/// 
/// This function takes a key of any length and adjusts it to a fixed length of 64 bytes.
/// If the key is exactly 64 bytes, it is returned as is. If the key is longer than 64 bytes,
/// it is hashed using SHA-256 and the resulting 32-byte hash is used. If the key is shorter
/// than 64 bytes, it is padded with zeros to reach the required length.
/// 
/// # Parameters
/// - `key`: An array of bytes representing the key to be adjusted. The length of the array is
///   determined by the generic parameter `N`.
/// 
/// # Returns
/// A 64-byte array containing the adjusted key.
/// 
/// # Example
/// ```noir
/// let key: [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
/// let adjusted_key = adjust_key(key);
/// ```
pub fn adjust_key<let N: u32>(key: [u8; N]) -> [u8; 64] {
    if (N == 64) {
        let mut result: [u8; 64] = [0 as u8; 64];
        for i in 0..64 {
            result[i] = key[i];
        }
        result
    } else if N > 64 {
        // If key is longer than 64 bytes, hash it
        let hashed_key: [u8; 32] = sha256(key);
        let mut result: [u8; 64] = [0 as u8; 64];
        for i in 0..32 {
            result[i] = hashed_key[i];
        }
        result
    } else {
        let mut padded_key: [u8; 64] = [0 as u8; 64];
        for i in 0..N {
            padded_key[i] = key[i];
        }
        padded_key
    }
}

/// Adjusts the given key vector to a fixed size array of 64 bytes.
/// 
/// # Arguments
/// 
/// * `keyVec` - A vector of bytes representing the key.
/// 
/// # Returns
/// 
/// A fixed size array of 64 bytes. If the input key is exactly 64 bytes, it is copied directly.
/// If the input key is longer than 64 bytes, it is hashed using SHA-256 and the resulting 32-byte hash is used.
/// If the input key is shorter than 64 bytes, it is copied and the remaining bytes are set to zero.
/// 
/// # Example
/// 
/// ```noir
/// let key = vec![1, 2, 3, 4, 5];
/// let adjusted_key = adjust_key_vec(key);
/// ```
pub fn adjust_key_var(keyVec: Vec<u8>) -> [u8; 64] {
    let N: u32 = keyVec.len();
    let mut key: [u8; 64] = [0 as u8; 64];

    if (N == 64) {
        for i in 0..64 {
            key[i] = keyVec.get(i);
        }
        key
    } else if N > 64 {
        assert(keyVec.len() <= MAX_KEY_LENGTH, "Key length exceeds maximum key length");
        let mut padded_key: [u8; 256] = [0; MAX_KEY_LENGTH];
        for i in 0..N {
            padded_key[i] = keyVec.get(i);
        }
        let hashed_key: [u8; 32] = sha256_var(padded_key, N as u64);
        for i in 0..32 {
            key[i] = hashed_key[i];
        }
        key
    } else {
        for i in 0..N {
            key[i] = keyVec.get(i);
        }
        key
    }
}

/// Trait `ArrayExtentions` provides an extension method for arrays.
/// 
/// # Methods
/// 
/// - `concat`: Concatenates the current array with another array of type `[u8; N]` and returns a new array of size `N + 64`.
///
/// # Type Parameters
///
/// - `N`: A constant generic parameter representing the size of the `other` array.
trait ArrayExtentions {
    fn concat<let N: u32>(self, other: [u8; N]) -> [u8; N + 64];
}

/// Trait implementation for extending arrays of 64 bytes with another array of arbitrary length.
///
/// # Methods
///
/// - `concat`: Concatenates the current array with another array of length `N`, returning a new array of length `N + 64`.
///
/// # Parameters
///
/// - `self`: The current array of 64 bytes.
/// - `other`: Another array of length `N`.
///
/// # Returns
///
/// - A new array of length `N + 64` containing the elements of the current array followed by the elements of the `other` array.
///
/// # Example
///
/// ```noir
/// let array1: [u8; 64] = [1; 64];
/// let array2: [u8; 32] = [2; 32];
/// let result = array1.concat(array2);
/// `result` is now an array of length 96 with the first 64 elements from `array1` and the next 32 elements from `array2`.
/// ```
impl ArrayExtentions for [u8; 64] {
    fn concat<let N: u32>(self, other: [u8; N]) -> [u8; N + 64] {
        let mut result: [u8; N + 64] = [0 as u8; N + 64];
        for i in 0..64 {
            result[i] = self[i];
        }
        for i in 0..N {
            result[i + 64] = other[i];
        }
        result
    }
}
