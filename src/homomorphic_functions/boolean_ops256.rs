/// This module contains helper functions for the multiplication of bitstring of 256 bit with ciphertexts
/// All the functions were adapted from boolean_ops in zama's sha256 example
/// EXCEPT: compute_challenge, mul_ciphertext_by_plain_csd_opt_256, mult_two_plain_256,
/// add_two_plain_256, to_csd_be, to_csd

use rayon::prelude::*;
use std::array;
use tfhe::boolean::prelude::{BinaryBooleanGates, Ciphertext, ServerKey};


/// Computes the chal:
/// a + b x (comp_hash1 - exp_hash1) + c x (comp_hash2 - exp_hash2)
pub fn compute_challenge(
    comp_hash1: &[Ciphertext;256],
    comp_hash2: &[Ciphertext;256],
    exp_hash1: &[bool;256],
    exp_hash2: &[bool;256],
    a: &[bool;256],
    b: &[bool;256],
    c: &[bool;256],
    sk: &ServerKey,
) -> [Ciphertext;256]{

    // perfrom b x comp_hash1 and c x comp_hash2 and add them up
    let enc_mult1 = mul_ciphertext_by_plain_csd_opt_256(comp_hash1, b, &sk);
    let enc_mult2 = mul_ciphertext_by_plain_csd_opt_256(comp_hash2, c, &sk);
    let sum_mult = add_256(&enc_mult1, &enc_mult2, sk);

    // compute the plaintext part of the hash : a - b x exp_hash1 - c x exp_hash2
    let neg_exp_hash1 = plain_minus_shift(exp_hash1, 0);
    let neg_exp_hash2 = plain_minus_shift(exp_hash2, 0);
    let neg_mult1 = mult_two_plain_256(&neg_exp_hash1, b);
    let neg_mult2 = mult_two_plain_256(&neg_exp_hash2, c);
    let mut plain_part = add_two_plain_256(a, &neg_mult1);
    plain_part = add_two_plain_256(&plain_part, &neg_mult2);

    // add up the plaintext and ciphertext part
    add_plain_256(&sum_mult, &plain_part, sk)
}



//  ------------------------------ CIPHERTEXT-CIPHERTEXT OPERATIONS --------------------------------
/// Adds two 256-bits ciphertext, considered as big-endian
/// Modified from add in boolean_ops
fn add_256(
    a: &[Ciphertext; 256],
    b: &[Ciphertext; 256],
    sk: &ServerKey,
) -> [Ciphertext; 256] {
    let (propagate, generate) = rayon::join(|| xor_256(a, b, sk), || and_256(a, b, sk));
    let carry = brent_kung_256(&propagate, &generate, sk);
    xor_256(&propagate, &carry, sk)
}


/// Implementation of the Brent Kung parallel prefix algorithm
/// This function computes the carry signals in parallel while minimizing the number of homomorphic
/// operations
/// Modified from brent_kung in boolean_ops
fn brent_kung_256(
    propagate: &[Ciphertext; 256],
    generate: &[Ciphertext; 256],
    sk: &ServerKey,
) -> [Ciphertext; 256] {
    // make mutable copies
    let mut propagate = propagate.clone();
    let mut generate  = generate.clone();

    // ── 8 “up‐sweep” stages (0..8) ───────────────────────────────
    for d in 0..8 {
        let stride = 1 << d;

        // pick out every 2*stride chunk, working backwards
        let indices: Vec<(usize, usize)> = (0..256 - stride)
            .rev()
            .step_by(2 * stride)
            .map(|i| i + 1 - stride)
            .enumerate()
            .collect();

        // compute the new (propagate, generate) for each cell in parallel
        let updates: Vec<(usize, Ciphertext, Ciphertext)> = indices
            .into_par_iter()
            .map(|(n, idx)| {
                // grey cell at the very first combine; black cells otherwise
                let new_p = if n == 0 {
                    propagate[idx].clone()
                } else {
                    sk.and(&propagate[idx], &propagate[idx + stride])
                };
                let new_g = sk.or(
                    &generate[idx],
                    &sk.and(&generate[idx + stride], &propagate[idx]),
                );
                (idx, new_p, new_g)
            })
            .collect();

        // write them back
        for (idx, p, g) in updates {
            propagate[idx] = p;
            generate[idx]  = g;
        }

        // ── then when d==7 (i.e. after 8 up‐sweep stages), do 7 “down‐sweep” refine stages ──
        if d == 7 {
            let mut cells = 0;
            // refine passes: d2 = 0..5
            for d2 in 0..7 {
                // compute the stride for this refine level
                let stride = 1 << (7 - d2 - 1);
                cells += 1 << d2;

                // each of the first `cells` cells gets a final-generate update
                let indices: Vec<(usize, usize)> = (0..cells)
                    .map(|cell| (cell, stride + 2 * stride * cell))
                    .collect();

                let updates: Vec<(usize, Ciphertext)> = indices
                    .into_par_iter()
                    .map(|(_, idx)| {
                        let new_g = sk.or(
                            &generate[idx],
                            &sk.and(&generate[idx + stride], &propagate[idx]),
                        );
                        (idx, new_g)
                    })
                    .collect();

                for (idx, g) in updates {
                    generate[idx] = g;
                }
            }
        }
    }

    // ── extract the carry bits ─────────────────────────────────────
    // carry[i] = generate[i+1]  for i in 0..255
    let mut carry = trivial_bools_256(&[false; 256], sk);
    carry[..255].clone_from_slice(&generate[1..256]);

    carry
}


/// Xor a 256 bit ciphertext with a 256 bit ciphertext bitwise
/// Use parallelization for performance
fn xor_256(a: &[Ciphertext; 256], b: &[Ciphertext; 256], sk: &ServerKey) -> [Ciphertext; 256] {
    let mut result = a.clone();
    result
        .par_iter_mut()
        .zip(a.par_iter().zip(b.par_iter()))
        .for_each(|(dst, (lhs, rhs))| *dst = sk.xor(lhs, rhs));
    result
}


// And a 256 bit ciphertext with a 256 bit ciphertext bitwise
// Use parallelization for performance
fn and_256(a: &[Ciphertext; 256], b: &[Ciphertext; 256], sk: &ServerKey) -> [Ciphertext; 256] {
    let mut result = a.clone();
    result
        .par_iter_mut()
        .zip(a.par_iter().zip(b.par_iter()))
        .for_each(|(dst, (lhs, rhs))| *dst = sk.and(lhs, rhs));
    result
}

/// This function first shifts a ciphertext by n and then multiplies it by -1
fn minus_shift(a: &[Ciphertext; 256], n: usize, sk: &ServerKey) -> [Ciphertext; 256] {
    // Shift, Negate bits, Add 1
    // Step 1 : shift
    let shifted: [Ciphertext; 256] = shift_left(a, n, sk);

    // Step 2 : Negate bits by xoring with all 1s
    let all_ones_plain: [bool; 256] = [true; 256];
    let not_shift: [Ciphertext; 256] =
        xor_with_plain_256(&shifted, &all_ones_plain, sk);

    // Step 3: Build a 256-bit plaintext which represents 1 and add it
    let mut one: [bool; 256] = [false; 256];
    one[255] = true;
    add_plain_256(&not_shift, &one, sk)
}
/// shifts a ciphertext to the left by n
fn shift_left(x: &[Ciphertext; 256], n: usize, sk: &ServerKey) -> [Ciphertext; 256] {
    let mut result = x.clone();
    result.rotate_left(n);
    result[(256 - n)..256].fill_with(|| sk.trivial_encrypt(false));
    result
}

// ------------------------------ PLAINTEXT-CIPHERTEXT OPERATIONS ----------------------------------
/// This function multiplies a 256 bit plaintext with a 256 bit ciphertext and uses the CSD algorithm
// /to do so, a and p are considered as big-endian.
pub fn mul_ciphertext_by_plain_csd_opt_256(
    a_bits: &[Ciphertext; 256],
    p_bits: &[bool; 256],
    sk: &ServerKey,
) -> [Ciphertext; 256] {

    // Get the csd representation of the plaintext
    let csd: [i8; 256] = to_csd_be(p_bits);

    let zero256: [Ciphertext; 256] = trivial_bools_256(&[false; 256], sk);

    // This vector will hold partial products of a multiplied by various powers of two
    let mut partials: Vec<[Ciphertext; 256]> = Vec::new();

    for i in 0..256 {
        match csd[i] {
            0 => {
                // No contribution when digit = 0.
            }
            1 => {
                // Positive partial, shift a left by the correct power of two
                let shifted: [Ciphertext; 256] = shift_left(a_bits, 255 - i, sk);

                partials.push(shifted);
            }
            -1 => {
                // Negative, partial, shift left and do minus one to the partial result
                let minus_shift = minus_shift(a_bits, 255 - i, sk);
                partials.push(minus_shift);
            }
            _ => unreachable!("CSD digit must be -1, 0, or +1"),
        }
    }

    // If p was 0 and all partial shifts are empty, return 0
    if partials.is_empty() {
        return zero256;
    }

    // Add partial multiplications in a tree structure
    // Repeatedly reduce by pairing adjacent elements
    // In case of uneven layer.len(), the last element is just cloned
    let mut nodes = partials;
    while nodes.len() > 1 {
       nodes = nodes
            .par_chunks(2)
            .map(|chunk| {
                if chunk.len() == 2 { add_256(&chunk[0], &chunk[1], sk) }
                else { chunk[0].clone() }
            }).collect();
    }
    // Now we only have the root of the tree left, we return that
    let acc = nodes.pop().unwrap();
    acc

}


/// Adds a 256 bit ciphertext with a 256 bits bit string, both are considered as big-endian
/// Modified from add in boolean_ops
pub fn add_plain_256(
    a: &[Ciphertext; 256],
    b: &[bool; 256],
    sk: &ServerKey,
) -> [Ciphertext; 256] {
    let (propagate, generate) = rayon::join(|| xor_with_plain_256(a, b, sk), || and_with_plain_256(a, b, sk));
    let carry = brent_kung_256(&propagate, &generate, sk);
    xor_256(&propagate, &carry, sk)
}

/// Xors a 256 bit plaintext with a 256 bit ciphertext bitwise
pub fn xor_with_plain_256(a: &[Ciphertext; 256], b: &[bool; 256], sk: &ServerKey, ) -> [Ciphertext; 256]{
    array::from_fn(|i| { sk.xor(&a[i], b[i]) })
}

/// Ands a 256 bit plaintext with a 256 bit ciphertext bitwise
fn and_with_plain_256(a: &[Ciphertext; 256], b: &[bool; 256], sk: &ServerKey) -> [Ciphertext; 256] {
    array::from_fn(|i| { sk.and(&a[i], b[i]) })
}

// ------------------------------- PLAINTEXT-PLAINTEXT OPERATIONS ----------------------------------

/// Multiply two 256 bit-string (big-endian) with shift and add algo
fn mult_two_plain_256(a: &[bool; 256], b: &[bool; 256]) -> [bool; 256] {
    let zero256: [bool; 256] =[false; 256];

    // Get all partial powers of a, which will then be added to get the final result
    let mut partials: Vec<[bool; 256]> = Vec::new();

    for i in 0..256 {
        match b[i] {
            false => {
                // No contribution when digit = 0.
            }
            true => {
                // Shift the array a to get the correct magnitude
                let shifted: [bool; 256] = plain_shift_left(&a, 255 - i);
                partials.push(shifted);
            }
        }
    }

    // If the constant was 0, return the 0 array
    if partials.is_empty() {
        return zero256;
    }

    // Add all partial results in an accumulator
    let mut acc: [bool; 256] = partials.remove(0);
    for next_word in partials.into_iter() {
        acc = add_two_plain_256(&acc, &next_word);
    }
    acc
}

/// Add two bit strings of 256 bits
fn add_two_plain_256(a: &[bool; 256], b: &[bool; 256]) -> [bool; 256] {
    // Start with the carry = 0, then do bitwise addition, taking into account the carry
    let mut carry : bool = false;
    let mut result = [false; 256];
    for i in 0..256{
        if a[255 - i] && b[255 - i]{
            result[255 - i] = carry;
            carry = true;
        }else if a[255 - i] || b[255 - i]{
            if !carry {
                result[255 - i] = true;
            }
        } else {
            result[255 - i] = carry;
            carry = false;
        }
    }
    result
}

/// This function first shifts a plaintext by n and then multiplies it by -1
fn plain_minus_shift(a: &[bool; 256], n: usize) -> [bool; 256] {
    // Shift, Negate bits, Add 1
    // Step 1 : shift
    let shifted: [bool; 256] = plain_shift_left(a, n);

    // Step 2 : Negate bits by xoring with all 1s
    let all_ones_plain: [bool; 256] = [true; 256];
    let not_shift: [bool; 256] = array::from_fn(|i| shifted[i] ^ all_ones_plain[i]);

    // Step 3: Build a 256-bit plaintext which represents 1 and add it
    let mut one: [bool; 256] = [false; 256];
    one[255] = true;
    add_two_plain_256(&not_shift, &one)
}

/// This function shifts left an array a bool by 'shift'
fn plain_shift_left(x: &[bool; 256], n: usize) -> [bool; 256] {
    let mut result = x.clone();
    result.rotate_left(n);
    result[(256 - n)..256].fill_with(|| false);
    result
}

// Takes a 256 bits bit string and return the trivial encryption of the bitstring
// Taken from trivial_bools in boolean_ops
pub fn trivial_bools_256(bools: &[bool; 256], sk: &ServerKey) -> [Ciphertext; 256] {
    array::from_fn(|i| sk.trivial_encrypt(bools[i]))
}


// --------------------------------------- UTILS ---------------------------------------------------
/// For a big-endian plaintext, this returns the CSD-digit array
fn to_csd_be(p_big: &[bool; 256]) -> [i8; 256] {
    // We reverse the big_endian representation to get the little endian one
    let mut p_little: [bool; 256] = [false; 256];
    for i in 0..256 { p_little[i] = p_big[255 - i]; }

    // Get the csd representation of the little endian plaintext
    let csd_little = to_csd(&p_little);

    // Get back the big endian representation by reversing csd_little
    let mut csd_be: [i8; 256] = [0i8; 256];
    for i in 0..256 { csd_be[i] = csd_little[255 - i]; }

    csd_be
}



/// Given a little endian plaintext, get the csd representation of the plaintext
/// { -1, 0, +1 }
fn to_csd(p_bits: &[bool; 256]) -> [i8; 256] {
    let mut csd = [0i8; 256];
    let mut i = 0;
    while i < 256 {
        if !p_bits[i] && csd[i]== 0 {
            // Do nothing, csd[i] is already 0
            i += 1;
        } else {
            // We found a run of one-bits starting at i
            // Count how many consecutive 1’s:
            let mut consecutive_ones = 1;
            while i + consecutive_ones < 256 && p_bits[i + consecutive_ones] {
                consecutive_ones += 1;
            }
            // If run_len == 1, we can safely set csd[i] = +1 and move on.
            if consecutive_ones == 1 {
                csd[i] = 1;
                i += 1;
            } else {
                // run_len ≥ 2. We take the entire block of run_len 1’s
                // and replace them by: +1 at position (i + run_len), and −1 at position i.
                csd[i] = -1;
                if i + consecutive_ones < 256 {
                    // Might be already nonzero if we carried over from a previous step;
                    // in that rare case, we must propagate again. To keep it simple:
                    //   we add +1 in that next position, and if it becomes +2, convert that to (0, +1 at next).
                    let carry_pos = i + consecutive_ones;
                    csd[carry_pos] = 1;

                    /*// But if that made it +2, we must push that carry upward:
                    while carry_pos < 256 && csd[carry_pos] == 2 {
                        // 2 → (-2 + 4)?  No. In signed‐digit, “2” at position k
                        // can be replaced by “0 at k” and “+1 at k+1”. (Because 2 · 2^k = 1·2^{k+1}.)
                        csd[carry_pos] = 0;
                        carry_pos += 1;
                        if carry_pos < 256 {
                            csd[carry_pos] += 1;
                        }
                    }*/
                }
                // Move i past the entire run:
                i += consecutive_ones;
            }
        }
    }
    csd
}





#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::boolean::prelude::*;


    fn to_bool_array(arr: [i32; 256]) -> [bool; 256] {
        let mut bool_arr = [false; 256];
        for i in 0..256 {
            if arr[i] == 1 {
                bool_arr[i] = true;
            }
        }
        bool_arr
    }
    fn encrypt(bools: &[bool; 256], ck: &ClientKey) -> [Ciphertext; 256] {
        array::from_fn(|i| ck.encrypt(bools[i]))
    }

    fn decrypt(bools: &[Ciphertext; 256], ck: &ClientKey) -> [bool; 256] {
        array::from_fn(|i| ck.decrypt(&bools[i]))
    }

    #[test]
    fn test_add_modulo_2_256() {
        let (ck, sk) = gen_keys();

        let a_bool =  to_bool_array([
            0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
            1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
            1, 0, 0, 1,0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
            1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
            1, 0, 0, 1,0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
            1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
            1, 0, 0, 1,0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
            1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
            1, 0, 0, 1,
        ]);

        let a = encrypt(&a_bool, &ck);

        let b_bool = to_bool_array([
            0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            1, 0, 1, 1,0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            1, 0, 1, 1,0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            1, 0, 1, 1,0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            1, 0, 1, 1,
        ]);
        let b = encrypt(&b_bool, &ck);

        let c_bool = to_bool_array([
            0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0,
            1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0,
            1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            1, 0, 1, 1,
        ]);
        let c = encrypt(&c_bool, &ck);

        let d_bool = to_bool_array([
            1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1,
            1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1,
            1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1,
            1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1,
            1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1,
            1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1,
            1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1,
            1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1,
            1, 0, 0, 0,
        ]);
        let d = encrypt(&d_bool, &ck);

        // Tests
        let sum_enc = add_256(&a, &b,  &sk);
        let sum = decrypt(&sum_enc, &ck);
        let expected = add_two_plain_256(&a_bool, &b_bool);
        assert_eq!(sum, expected);

        let sum2_enc = add_256(&c, &d, &sk);
        let sum2 = decrypt(&sum2_enc, &ck);
        let expected2 = add_two_plain_256(&c_bool, &d_bool);

        assert_eq!(sum2, expected2);
    }

    #[test]
    fn test_mul_modulo_2_256() {
        let (ck, sk) = gen_keys();

        let a_bool =  to_bool_array([
            0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0,
            0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
            1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0,
            0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1,
            0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1,
            0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0,
            1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1,
            0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
            1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1,
        ]);

        let a = encrypt(&a_bool, &ck);

        let b_bool = to_bool_array([
            0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0,
            1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0,
            1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1,
            0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1,
            1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0,
            1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1,
            0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1,
        ]);

        let c_bool = to_bool_array([
            0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1,
            0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0,
            1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0,
            0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1,
            1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0,
            0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0,
            1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1,
            0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1,
            1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0,
        ]);
        let c = encrypt(&c_bool, &ck);

        let d_bool = to_bool_array([
            1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0,
            0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1,
            1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0,
            0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1,
            1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1,
            1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
            1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0,
            1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
            1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1,
        ]);


        // Tests
        let mul_enc = mul_ciphertext_by_plain_csd_opt_256(&a, &b_bool, &sk);
        let mul = decrypt(&mul_enc, &ck);
        let expected = mult_two_plain_256(&a_bool, &b_bool);
        assert_eq!(mul, expected);

        let mul_enc2 = mul_ciphertext_by_plain_csd_opt_256(&c, &d_bool, &sk);
        let mul2 = decrypt(&mul_enc2, &ck);
        let expected2 = mult_two_plain_256(&c_bool, &d_bool);
        assert_eq!(mul2, expected2);
    }


    #[test]
    fn test_challenge() {
        let (ck, sk) = gen_keys();

        let a_bool =  to_bool_array([
            0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0,
            0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
            1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0,
            0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1,
            0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1,
            0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0,
            1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1,
            0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
            1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1,
        ]);

        let b_bool = to_bool_array([
            0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0,
            1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0,
            1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1,
            0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1,
            1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0,
            0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0,
            1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1,
            0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1,
        ]);

        let c_bool = to_bool_array([
            0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1,
            0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0,
            1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0,
            0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1,
            1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0,
            0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0,
            1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1,
            0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1,
            1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0,
        ]);

        let hash1_bool = to_bool_array([
            1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0,
            0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1,
            1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0,
            0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1,
            1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1,
            1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
            1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0,
            1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
            1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1,
        ]);
        let hash1 = encrypt(&hash1_bool, &ck);

        let hash2_bool = to_bool_array([
            1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0,
            0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1,
            1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0,
            0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1,
            1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1,
            0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
            1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0,
            1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1,0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
            1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0,
        ]);
        let hash2 = encrypt(&hash2_bool, &ck);


        // Tests
        let chal_enc = compute_challenge(
            &hash1, &hash2, &hash1_bool, &hash2_bool, &a_bool, &b_bool, &c_bool, &sk);
        let chal = decrypt(&chal_enc, &ck);
        assert_eq!(chal, a_bool);
    }


}