// This module contains the padding function for SHA3-256

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
