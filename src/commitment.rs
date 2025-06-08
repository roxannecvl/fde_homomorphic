/// This files contains a commitment scheme based of hash functions

use rand::{rngs::OsRng, RngCore};
use crate::homomorphic_functions::hex_sha3;

pub struct Opening {
    pub nonce: [u8; 32],   // base64‐encoded ciphertext
    pub data: Vec<u8>,  // base64‐encoded evaluation key
}

/// Commit to `data` by hashing a random 32-byte nonce || msg.
/// Returns (commitment, opening), where:
/// - `commitment` is the hash
/// - `opening` is an Opening, i.e a secret nonce and the data commited.
pub fn commit(data: &[u8]) -> (String, Opening) {
    // sample a 256-bit random nonce
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    // compute C = SHA3(nonce || msg)
    let mut concatanation  = nonce.to_vec();
    concatanation.extend_from_slice(data);
    let hash = hex_sha3(concatanation.as_slice());

    // create the opening, consisting of the data and nonce
    let opening = Opening{nonce: nonce, data : data.to_vec()};

    (hash, opening)
}

/// Verify that the `Opening` (nonce, msg) open `commitment`.
pub fn verify_open(commitment: String, opening: &Opening) -> bool {
    let mut concatanation  = opening.nonce.to_vec();
    concatanation.extend_from_slice(&opening.data);
    let hash = hex_sha3(concatanation.as_slice());
    hash == commitment
}
