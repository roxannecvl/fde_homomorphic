/// Encrypts and decrypts Ciphertext to booleans
/// Taken from the tfhe-rs library in the sha256 example main

use tfhe::boolean::ciphertext::Ciphertext;
use tfhe::boolean::client_key::ClientKey;

pub fn encrypt_bools(bools: Vec<bool>, ck: &ClientKey) -> Vec<Ciphertext> {
    let mut ciphertext = vec![];

    for bool in bools {
        ciphertext.push(ck.encrypt(bool));
    }
    ciphertext
}

pub fn decrypt_bools(ciphertext: &Vec<Ciphertext>, ck: &ClientKey) -> Vec<bool> {
    let mut bools = vec![];

    for cipher in ciphertext {
        bools.push(ck.decrypt(cipher));
    }
    bools
}