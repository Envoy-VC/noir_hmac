use std::hash::sha256_var;

/// Adjusts the provided key to a fixed length of 64 bytes.
///
/// If the key is exactly 64 bytes, it is copied directly to the result.
/// If the key is longer than 64 bytes, it is hashed using SHA-256 and the resulting 32-byte hash is copied to the result.
/// If the key is shorter than 64 bytes, it is copied to the beginning of the result and the remaining bytes are set to zero.
///
/// # Parameters
/// - `key`: A `BoundedVec<u8, M>` representing the key to be adjusted. The length of the key is bounded by `M`.
///
/// # Returns
/// A `[u8; 64]` array containing the adjusted key.
pub fn adjust_key<let M: u32>(key: BoundedVec<u8, M>) -> [u8; 64] {
    let mut result: [u8; 64] = [0 as u8; 64];
    if (key.len() == 64) {
        for i in 0..64 {
            result[i] = key.get(i);
        }
    } else if key.len() > 64 {
        // If key is longer than 64 bytes, hash it
        let hashed_key: [u8; 32] = sha256_var(key.storage(), key.len() as u64);
        for i in 0..32 {
            result[i] = hashed_key[i];
        }
    } else {
        for i in 0..64 {
            if (i < key.len()) {
                result[i] = key.get(i);
            }
        }
    }
    result
}

trait ArrayExtentions {
    fn concat<let N: u32>(self, other: [u8; N]) -> [u8; N + 64];
}

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
