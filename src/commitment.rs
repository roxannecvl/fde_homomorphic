use rand::{rngs::OsRng, RngCore};
use serde::{Serialize, Deserialize};
use tfhe::boolean::ciphertext::Ciphertext;
use tfhe::boolean::prelude::ServerKey;
use crate::homomorphic_functions::hex_sha3;


#[derive(Serialize, Deserialize)]
pub struct Opening {
    pub nonce: [u8; 32],   // base64‐encoded ciphertext
    pub data: Vec<u8>,  // base64‐encoded evaluation key
}

/// Commit to `msg` by hashing a random 32-byte nonce || msg.
/// Returns (commitment, opening), where:
/// - `commitment` is a string
/// - `opening` is an Opening, i.e a secret nonce and the data commited.
pub fn commit(data: &[u8]) -> (String, Opening) {
    // sample a 256-bit random nonce
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    // compute C = SHA3(nonce || msg)
    let mut concatanation  = nonce.to_vec();
    concatanation.extend_from_slice(data);
    let hash = hex_sha3(concatanation.as_slice());

    let mut opening = Opening{nonce: nonce, data : data.to_vec()};

    (hash, opening)
}

/// Verify that (nonce, msg) open `commitment`.
pub fn verify_open(commitment: String, opening: &Opening) -> bool {
    let mut concatanation  = opening.nonce.to_vec();
    concatanation.extend_from_slice(&opening.data);
    let hash = hex_sha3(concatanation.as_slice());
    hash == commitment
}
