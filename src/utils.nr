use std::hash::sha256;

pub fn xor_key(key: [u8; 64], pad_byte: u8) -> [u8; 64] {
    let mut result: [u8; 64] = [0 as u8; 64];
    for i in 0..64 {
        result[i] = key[i] ^ pad_byte;
    }
    result
}

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

trait ArrayConcat {
    fn concat<let N: u32>(self, other: [u8; N]) -> [u8; N + 64];
}

impl ArrayConcat for [u8; 64] {
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
