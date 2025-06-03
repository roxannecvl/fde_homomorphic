// This module contains the padding function for SHA3-256
use tfhe::boolean::prelude::*;

/// This function pads plaintext data before it is encrypted and then hashed
pub fn pad_sha3_256_bytes(data_array: &[u8]) -> Vec<bool> {
    const RATE_BYTES: usize = 1088 / 8;
    let mut data = data_array.to_vec();

    // If we only need one byte to reach a block, we add the special 0x86 suffix:
    if data.len() % RATE_BYTES == RATE_BYTES - 1 {
        data.push(0x86);
    } else {
        // Otherwise, do the 0x06 prefix, padding and finally 0x80,
        // to reach a length multiple of a block
        data.push(0x06);
        while data.len() % RATE_BYTES != RATE_BYTES - 1 { data.push(0x00);}
        data.push(0x80);
    }

    // From bytes representation output the boolean array representation
    data.iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1))
        .collect()
}


/// This function pads a Ciphertext
pub fn pad_sha3_256_cipher(ct : Vec<Ciphertext>, sk : &ServerKey) -> Vec<Ciphertext> {
    const RATE_BYTES: usize = 1088 / 8;
    assert_eq!(ct.len() % 8, 0);
    let nb_bytes = ct.len() / 8;

    let mut mut_ct = ct.clone();


    // If we only need one byte to reach a block, we add the special 0x86 suffix:
    if nb_bytes % RATE_BYTES == RATE_BYTES - 1 {
        let new_byte = 0x86;
        for i in 0..8 {
            let new_cipher : Ciphertext = sk.trivial_encrypt(((new_byte>> i) & 1) == 1);
            mut_ct.push(new_cipher);
        }

    } else {
        // Otherwise, do the 0x06 prefix, padding and finally 0x80,
        // to reach a length multiple of a block
        let new_byte = 0x06;
        for i in 0..8 {
            let new_cipher : Ciphertext = sk.trivial_encrypt(((new_byte>> i) & 1) == 1);
            mut_ct.push(new_cipher);
        }

        let zero_byte_cipher: Ciphertext = sk.trivial_encrypt(false);
        while mut_ct.len() % RATE_BYTES != RATE_BYTES - 1 {
            for _ in 0..8 {
                mut_ct.push(zero_byte_cipher.clone());
            }
        }
        let new_byte = 0x80;
        for i in 0..8 {
            let new_cipher : Ciphertext = sk.trivial_encrypt(((new_byte>> i) & 1) == 1);
            mut_ct.push(new_cipher);
        }
    }
    mut_ct
}

// This function is useful at the end of the protocol, to unpad the decrypted data and compute
// Sha3 on it.
pub fn unpad_sha3_256_bytes(padded_bits: &[bool]) -> Vec<u8> {
    // Check that the bit length is divisible by 8
    assert_eq!(padded_bits.len() % 8,  0);

    // Get bytes
    let bytes : Vec<u8> = padded_bits.chunks(8)
        .map(|chunk| {
            chunk.iter().enumerate().fold(0u8, |acc, (i, &bit)| {
                if bit {
                    acc | (1 << i)
                } else {
                    acc
                }
            })
        })
        .collect();

    // Remove padding by finding the place where the padding starts
    let bytes_slice : &[u8] = (&bytes).as_slice();
    let last : u8= bytes_slice[bytes_slice.len() -1];
    let mut last_index = 1;

    if last == 0x86 { //0x86 = 134
        // Case A: single‐byte padding; just pop that one 0x86
        return bytes_slice[0..bytes_slice.len() -1].to_vec();
    }

    if last == 0x80 { // 0x80 = 128
        while bytes_slice[bytes_slice.len() -last_index] != 0x06 { // 0x06 = 6
            last_index += 1;
        }
        return bytes[0..bytes_slice.len() - last_index].to_vec();
    }

    panic!("Invalid padding: did not find 0x86 or 0x80 at end");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::boolean::prelude::*;

    #[test]
    fn test_add_modulo_2_256() {
        let test:[u8; 16]  = [62, 33, 1, 29, 45, 1, 2, 7, 1, 0, 9, 46, 61, 1, 33, 22];
        let pad_test = pad_sha3_256_bytes(&test);
        let unpad_test = unpad_sha3_256_bytes(&pad_test);
        assert_eq!(unpad_test, test);
    }
}



