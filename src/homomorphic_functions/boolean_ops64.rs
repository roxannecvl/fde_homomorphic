// This module contains  operations on encrypted bit strings used in the sha3 function, implemented
// with homomorphic boolean operations. These use parallel optimizations.
use rayon::prelude::*;
use std::array;
use tfhe::boolean::prelude::{BinaryBooleanGates, Ciphertext, ServerKey};



//  ------------------------------ CIPHERTEXT-CIPHERTEXT OPERATIONS --------------------------------
// This function rotates the Ciphertext to the right by n
// Taken from boolean_ops
pub fn rotate_right(x: &[Ciphertext; 64], n: usize) -> [Ciphertext; 64] {
    let mut result = x.clone();
    result.rotate_right(n);
    result
}


// Parallelized homomorphic bitwise xor operation for two 64 bits ciphertexts
pub fn xor_64(a: &[Ciphertext; 64], b: &[Ciphertext; 64], sk: &ServerKey) -> [Ciphertext; 64] {
    let mut result = a.clone();
    result
        .par_iter_mut()
        .zip(a.par_iter().zip(b.par_iter()))
        .for_each(|(dst, (lhs, rhs))| *dst = sk.xor(lhs, rhs));
    result
}

// Parallelized homomorphic bitwise and operation for two 64 bits ciphertexts
pub fn and_64(a: &[Ciphertext; 64], b: &[Ciphertext; 64], sk: &ServerKey) -> [Ciphertext; 64] {
    let mut result = a.clone();
    result
        .par_iter_mut()
        .zip(a.par_iter().zip(b.par_iter()))
        .for_each(|(dst, (lhs, rhs))| *dst = sk.and(lhs, rhs));
    result
}


// ------------------------------ PLAINTEXT-CIPHERTEXT OPERATIONS ----------------------------------
// Homomorphic bitwise xor operation for one 64 bits ciphertext with one 64 bit plaintext
pub fn xor_with_plain_64(a: &[Ciphertext; 64], b: &[bool; 64], sk: &ServerKey, ) -> [Ciphertext; 64]{
     array::from_fn(|i| { sk.xor(&a[i], b[i]) })
}

// Homomorphic bitwise xor operation for one n-bits ciphertext with one n-bit plaintext
pub fn xor_with_plain(a: &[Ciphertext], b: &[bool], sk: &ServerKey, ) -> Vec<Ciphertext> {
    assert_eq!(a.len(), b.len(), "length mismatch");
    a.iter().zip(b.iter()).map(|(ct, &b)| sk.xor(ct, b)).collect()
}



