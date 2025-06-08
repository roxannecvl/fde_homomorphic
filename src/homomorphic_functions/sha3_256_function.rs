/// Homomorphic SHA3-256 implementation using TFHE-rs Boolean API
///
/// This file also provides `sha3_fhe` which takes a fixed-size block of 1088 encrypted bits
/// and returns 256 encrypted bits representing the SHA3-256 digest.
use tfhe::boolean::prelude::*;
use sha3::{Digest, Sha3_256};

use crate::homomorphic_functions::{rotate_right, xor_64, and_64, xor_with_plain_64};

/// Round constants for Keccak-f[1600]
const N_ROUNDS : usize = 24; // number of rounds nᵣ = 12 + 2ℓ, hence 24 for Keccak-f[1600] [Keccak §1.2]

/**
 * Round constants: output of a maximum-length linear feedback shift register (LFSR) for the
 * ι step [Keccak §1.2, §2.3.5], keccak.noekeon.org/specs_summary.html.
 *
 *   RC[iᵣ][0][0][2ʲ−1] = rc[j+7iᵣ] for 0 ≤ j ≤ l
 * where
 *   rc[t] = ( xᵗ mod x⁸ + x⁶ + x⁵ + x⁴ + 1 ) mod x in GF(2)[x].
 */
const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];


/// Used to get the hex form of the hash once the sha has been decrypted
pub fn bools_to_hex(bits: &[bool]) -> String {
    let bytes = bits_to_bytes_lsb(bits);
    assert_eq!(bytes.len(), 32);
    hex::encode(bytes)
}

/// The plaintext implementation of sha3
pub fn hex_sha3(data : &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let hex   = hex::encode(result);
    hex
}

/// Used to get the hash of data in the form of Vec<bool>
pub fn sha3_hash_from_vec_bool(data: Vec<bool>) -> String {
    // Get bytes from Vec<bool>
    let bytes : Vec<u8> = data.chunks(8)
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
    // then hash normally
    hex_sha3(&bytes)
}

/// Homomorphic SHA3-256, returns 256 Ciphertext bits
/// Expects a padded ciphertext
pub fn sha3_256_fhe(
    input: Vec<Ciphertext>,
    sk: &ServerKey,
) -> [Ciphertext; 256] {
    // Prepare trivial ciphertexts
    let zero = sk.trivial_encrypt(false);
    let one = sk.trivial_encrypt(true);
    let one_lane: [Ciphertext; 64] = std::array::from_fn(|_| one.clone());
    let zero_uint64 =  std::array::from_fn(|_| zero.clone());
    let five_zero_uint64 = std::array::from_fn(|_| zero_uint64.clone());

    // Gather input
    let bits_ct = input.clone();

    // Allocate fixed buffers
    let mut state: [[[Ciphertext; 64]; 5]; 5] = std::array::from_fn(|_| five_zero_uint64.clone());
    let mut c_buf: [[Ciphertext; 64]; 5] = five_zero_uint64.clone();
    let mut d_buf: [[Ciphertext; 64]; 5] = five_zero_uint64.clone();

    // Process each 1088-bit block
    for (_, block) in bits_ct.chunks(1088).enumerate() {
        // Absorb
        for (j, ct) in block.chunks(64).enumerate() {
            let new_cipher_u64: [Ciphertext; 64] = std::array::from_fn(|i| {ct[i].clone()});
            let x = j % 5;
            let y = j / 5;
            state[x][y] = xor_64(&state[x][y], &new_cipher_u64, &sk);
        }

        // Perform the keccak permutation
        keccak_f1600_boolean(
            &mut state,
            sk,
            &one_lane,
            &mut c_buf,
            &mut d_buf,
        );
    }

    // Squeeze first 256 bits
    let out: [Ciphertext; 256] = std::array::from_fn(|k| {
        // compute which lane (x,y) and which bit z within that lane
        let x = (k / 64) % 5;
        let y = (k / 64) / 5;
        let z = k % 64;
        // clone out that bit-ciphertext
        state[x][y][z].clone()
    });
    out
}

// -------------------------- HELPER FUNCTIONS ---------------------------------------

// This function does the keccak f1600 permutation for sha3-256
fn keccak_f1600_boolean(
    state: &mut [[[Ciphertext; 64]; 5]; 5],
    sk: &ServerKey,
    one_lane: &[Ciphertext; 64],
    c_buf: &mut [[Ciphertext; 64]; 5],
    d_buf: &mut [[Ciphertext; 64]; 5],
) {
    // Keccak-f permutations
    for r in 0..N_ROUNDS{

        // θ phase
        for x in 0..5 {
            c_buf[x] = state[x][0].clone();
            for y in 1..5 {
                c_buf[x] = xor_64(&c_buf[x], &state[x][y], sk);
            }
        }
        for x in 0..5{
            d_buf[x] = xor_64(&c_buf[(x+4)%5], &rotate_right(&c_buf[(x+1)%5], 1), sk);
            for y in 0..5 {
                state[x][y] = xor_64(&state[x][y], &d_buf[x], sk);
            }
        }

        // ρ + π phase
        let mut x = 1;
        let mut y = 0;
        let mut current = state[x][y].clone();
        for t in 0..24 {
            let new_x = y;
            let new_y = (2*x + 3*y) % 5;
            let tmp = state[new_x][new_y].clone();
            state[new_x][new_y] = rotate_right(&current, ((t+1)*(t+2)/2) % 64);
            current = tmp;
            x = new_x;
            y = new_y;
        }

        // χ phase
        for y in 0..5 {
            let col: [[Ciphertext; 64]; 5] = [
                state[0][y].clone(),
                state[1][y].clone(),
                state[2][y].clone(),
                state[3][y].clone(),
                state[4][y].clone(),
            ];

            for x in 0..5 {
                let cx   = &col[x];
                let cx1  = &col[(x + 1) % 5];
                let cx2  = &col[(x + 2) % 5];
                // homomorphic NOT = XOR with all-ones
                let not_cx1 = xor_64(cx1, &one_lane, sk);
                // and-part: (~C[x+1]) & C[x+2]
                let and_part = and_64(&not_cx1, cx2, sk);
                // final: C[x] ^ and_part
                state[x][y] = xor_64(cx, &and_part, sk);
            }
        }

        // ι phase
        let rc_r_bits = u64_to_bits_lsb(RC[r]);
        state[0][0] = xor_with_plain_64(&state[0][0] , &rc_r_bits, &sk);
    }
}

// transforms a u64 into an array of 64 bool
fn u64_to_bits_lsb(x: u64) -> [bool; 64] {
    let mut bits = [false; 64];
    for i in 0..64 {
        bits[i] = ((x >> i) & 1) != 0;
    }
    bits
}

// transforms bits to bytes
fn bits_to_bytes_lsb(bits: &[bool]) -> Vec<u8> {
    bits.chunks(8)
        .map(|chunk| {
            chunk.iter()
                .enumerate()
                .fold(0u8, |acc, (i, &b)| if b { acc | (1 << i) } else { acc })
        })
        .collect()
}



