/// This module implements the Trivium stream cipher, using boolean or Ciphertext
/// for the representation of the inner bits.
/// This was taken from trivium in the zama library and adapted for the boolean API.

use crate::static_deque::StaticDeque;
use rayon::prelude::*;
use tfhe::boolean::prelude::*;
use crate::homomorphic_functions::xor_with_plain;

/// TriviumStream: a struct implementing the Trivium stream cipher, using T for the internal
/// representation of bits (bool or FheBool). To be able to compute FHE operations, it also owns
/// an Option for a ServerKey.
pub struct TriviumStream<T> {
    a: StaticDeque<93, T>,
    b: StaticDeque<84, T>,
    c: StaticDeque<111, T>,
    // only present for the encrypted version:
    fhe_key: Option<ServerKey>,
}

impl TriviumStream<bool> {
    /// Constructor for `TriviumStream<bool>`: arguments are the secret key and the input vector.
    /// Outputs a TriviumStream object already initialized (1152 steps have been run before
    /// returning)
    pub fn new(key: [bool; 80], iv: [bool; 80]) -> TriviumStream<bool> {
        // Initialization of Trivium registers: a has the secret key, b the input vector,
        // and c a few ones.
        let mut a_register = [false; 93];
        let mut b_register = [false; 84];
        let mut c_register = [false; 111];

        for i in 0..80 {
            a_register[93 - 80 + i] = key[i];
            b_register[84 - 80 + i] = iv[i];
        }

        c_register[0] = true;
        c_register[1] = true;
        c_register[2] = true;

        TriviumStream::<bool>::new_from_registers(a_register, b_register, c_register, None)
    }

    // COPY OF GENERIC TRIVIUM, REPLACED T by bool
    fn new_from_registers(
        a_register: [bool; 93],
        b_register: [bool; 84],
        c_register: [bool; 111],
        key: Option<ServerKey>,
    ) -> Self {
        let mut ret = Self {
            a: StaticDeque::<93, bool>::new(a_register),
            b: StaticDeque::<84, bool>::new(b_register),
            c: StaticDeque::<111, bool>::new(c_register),
            fhe_key: key,
        };
        ret.init();
        ret
    }

    /// The specification of Trivium includes running 1152 (= 18*64) unused steps to mix up the
    /// registers, before starting the proper stream
    fn init(&mut self) {
        for _ in 0..18 {
            self.next_64();
        }
    }

    /// Computes one turn of the stream, updating registers and outputting the new bit.
    pub fn next_bool(&mut self) -> bool {

        let [o, a, b, c] = self.get_output_and_values(0);

        self.a.push(a);
        self.b.push(b);
        self.c.push(c);

        o
    }

    /// Computes a potential future step of Trivium, n terms in the future. This does not update
    /// registers, but rather returns with the output, the three values that will be used to
    /// update the registers, when the time is right. This function is meant to be used in
    /// parallel.
    fn get_output_and_values(&self, n: usize) -> [bool; 4] {
        assert!(n < 65);

        let (((temp_a, temp_b), (temp_c, a_and)), (b_and, c_and)) = rayon::join(
            || {
                rayon::join(
                    || {
                        rayon::join(
                            || &self.a[65 - n] ^ &self.a[92 - n],
                            || &self.b[68 - n] ^ &self.b[83 - n],
                        )
                    },
                    || {
                        rayon::join(
                            || &self.c[65 - n] ^ &self.c[110 - n],
                            || &self.a[91 - n] & &self.a[90 - n],
                        )
                    },
                )
            },
            || {
                rayon::join(
                    || &self.b[82 - n] & &self.b[81 - n],
                    || &self.c[109 - n] & &self.c[108 - n],
                )
            },
        );

        let ((o, a), (b, c)) = rayon::join(
            || {
                rayon::join(
                    || &(&temp_a ^ &temp_b) ^ &temp_c,
                    || &temp_c ^ &(&c_and ^ &self.a[68 - n]),
                )
            },
            || {
                rayon::join(
                    || &temp_a ^ &(&a_and ^ &self.b[77 - n]),
                    || &temp_b ^ &(&b_and ^ &self.c[86 - n]),
                )
            },
        );

        [o, a, b, c]
    }

    /// This calls `get_output_and_values` in parallel 64 times, and stores all results in a Vec.
    fn get_64_output_and_values(&self) -> Vec<[bool; 4]> {
        (0..64)
            .into_par_iter()
            .map(|x| self.get_output_and_values(x))
            .rev()
            .collect()
    }

    /// Computes 64 turns of the stream, outputting the 64 bits all at once in a
    /// Vec (first value is oldest, last is newest)
    pub fn next_64(&mut self) -> Vec<bool> {

        let mut values = self.get_64_output_and_values();


        let mut ret = Vec::<bool>::with_capacity(64);

        while let Some([o, a, b, c]) = values.pop() {
            ret.push(o);
            self.a.push(a);
            self.b.push(b);
            self.c.push(c);
        }
        ret
    }
}

impl TriviumStream<Ciphertext> {
    /// Constructor for `TriviumStream<Ciphertext>`: arguments are the encrypted secret key and input
    /// vector, and the FHE server key.
    /// Outputs a TriviumStream object already initialized (1152 steps have been run before
    /// returning)
    pub fn new(key: [Ciphertext; 80], iv: [bool; 80], sk: &ServerKey) -> TriviumStream<Ciphertext> {

        // Initialization of Trivium registers: a has the secret key, b the input vector,
        // and c a few ones.
        let mut a_register: [Ciphertext; 93] = std::array::from_fn(|_| { sk.trivial_encrypt(false)});
        let mut b_register: [Ciphertext; 84] = std::array::from_fn(|_| { sk.trivial_encrypt(false)});
        let mut c_register: [Ciphertext; 111] = std::array::from_fn(|_| { sk.trivial_encrypt(false)});

        for i in 0..80 {
            a_register[93 - 80 + i] = key[i].clone();
            b_register[84 - 80 + i] = sk.trivial_encrypt(iv[i]);
        }

        c_register[0] = sk.trivial_encrypt(true);
        c_register[1] = sk.trivial_encrypt(true);
        c_register[2] = sk.trivial_encrypt(true);

        TriviumStream::<Ciphertext>::new_from_registers(
            a_register,
            b_register,
            c_register,
            Some(sk.clone()),
        )
    }


    // COPY FROM GENERIC TRIVIUM, REPLACED IT BY CIPHERTEXT
    fn new_from_registers(
        a_register: [Ciphertext; 93],
        b_register: [Ciphertext; 84],
        c_register: [Ciphertext; 111],
        key: Option<ServerKey>,
    ) -> Self {
        let mut ret = Self {
            a: StaticDeque::<93, Ciphertext>::new(a_register),
            b: StaticDeque::<84, Ciphertext>::new(b_register),
            c: StaticDeque::<111, Ciphertext>::new(c_register),
            fhe_key: key,
        };
        ret.init();
        ret
    }

    /// The specification of Trivium includes running 1152 (= 18*64) unused steps to mix up the
    /// registers, before starting the proper stream
    fn init(&mut self) {
        for _ in 0..18 {
            self.next_64();
        }
    }

    /// Computes one turn of the stream, updating registers and outputting the new bit.
    pub fn next_bool(&mut self) -> Ciphertext {

        let [o, a, b, c] = self.get_output_and_values(0);

        self.a.push(a);
        self.b.push(b);
        self.c.push(c);

        o
    }

    /// Computes a potential future step of Trivium, n terms in the future. This does not update
    /// registers, but rather returns with the output, the three values that will be used to
    /// update the registers, when the time is right. This function is meant to be used in
    /// parallel.
    fn get_output_and_values(&self, n: usize) -> [Ciphertext; 4] {
        assert!(n < 65);
        let sk: ServerKey = self.fhe_key.clone().expect("TriviumStream<Ciphertext> must have an FHE key");

        let (((temp_a, temp_b), (temp_c, a_and)), (b_and, c_and)) = rayon::join(
            || {
                rayon::join(
                    || {
                        rayon::join(
                            || sk.xor(&self.a[65 - n], &self.a[92 - n]),
                            || sk.xor(&self.b[68 - n], &self.b[83 - n]),

                        )
                    },
                    || {
                        rayon::join(
                            ||sk.xor(&self.c[65 - n], &self.c[110 - n]),
                            ||sk.and(&self.a[91 - n], &self.a[90 - n]),
                        )
                    },
                )
            },
            || {
                rayon::join(
                    || sk.and(&self.b[82 - n], &self.b[81 - n]),
                    || sk.and(&self.c[109 - n], &self.c[108 - n]),
                )
            },
        );

        let ((o, a), (b, c)) = rayon::join(
            || {
                rayon::join(

                    ||Self::triple_xor(&temp_a, &temp_b, &temp_c, &sk),
                    ||Self::triple_xor(&temp_c, &c_and, &self.a[68 - n], &sk),
                )
            },
            || {
                rayon::join(
                    ||Self::triple_xor(&temp_a, &a_and, &self.b[77 - n], &sk),
                    ||Self::triple_xor(&temp_b, &b_and, &self.c[86 - n], &sk),
                )
            },
        );

        [o, a, b, c]
    }

    /// This calls `get_output_and_values` in parallel 64 times, and stores all results in a Vec.
    fn get_64_output_and_values(&self) -> Vec<[Ciphertext; 4]> {
        (0..64)
            .into_par_iter()
            .map(|x| self.get_output_and_values(x))
            .rev()
            .collect()
    }

    /// Computes 64 turns of the stream, outputting the 64 bits all at once in a
    /// Vec (first value is oldest, last is newest)
    pub fn next_64(&mut self) -> Vec<Ciphertext> {
        let mut values = self.get_64_output_and_values();

        let mut ret = Vec::<Ciphertext>::with_capacity(64);

        while let Some([o, a, b, c]) = values.pop() {
            ret.push(o);
            self.a.push(a);
            self.b.push(b);
            self.c.push(c);
        }
        ret
    }

    fn triple_xor (a : &Ciphertext, b: &Ciphertext, c: &Ciphertext, sk : &ServerKey) -> Ciphertext {
        let inter = sk.xor(a, b);
        sk.xor(c, &inter)
    }
}

// This function returns the symmetric keystream derived from initial key and iv
pub fn get_plain_keystream_n (key : [bool; 80], iv : [bool; 80], size : usize) -> Vec<bool>{
    let mut clear_trivium = TriviumStream::<bool>::new(key, iv);
    let mut keystream: Vec<bool> = Vec::with_capacity(size);
    while keystream.len() + 64 <= size {
        let cipher_outputs = clear_trivium.next_64();
        for c in cipher_outputs {
            keystream.push(c)
        }
    }
    while keystream.len()  < size {
        let c = clear_trivium.next_bool();
        keystream.push(c)
    }
    keystream
}

// This function returns the homomorphic encryption of the symmetric keystream derived from initial
// key and iv
pub fn get_cipher_keystream_n (key : [Ciphertext; 80], iv : [bool; 80], size : usize, sk: &ServerKey) -> Vec<Ciphertext>{
    let mut fhe_trivium =
        TriviumStream::<Ciphertext>::new(key, iv.clone(), sk);
    let mut fhe_keystream: Vec<Ciphertext> = Vec::with_capacity(size);
    while fhe_keystream.len() + 64 <= size {
        let cipher_outputs = fhe_trivium.next_64();
        for c in cipher_outputs {
            fhe_keystream.push(c)
        }
    }
    while fhe_keystream.len()  < size {
        let c = fhe_trivium.next_bool();
        fhe_keystream.push(c)
    }
    fhe_keystream
}

// Performs the trivium symmetric encryption
pub fn symmetric_enc(input : Vec<bool>, key : [bool; 80], iv : [bool; 80] ) -> Vec<bool> {
    let keystream = get_plain_keystream_n(key, iv, input.len());
    let sym_end_data = keystream.iter()
        .zip(input.iter())
        .map(|(&bit_a, &bit_b)| bit_a ^ bit_b)
        .collect();
    sym_end_data
}

// Performs the trivium symmetric decryption
pub fn symmetric_dec(input : Vec<bool>, key : [bool; 80], iv : [bool; 80] ) -> Vec<bool> {
   // same as encryption as it is just xoring
    symmetric_enc(input, key, iv)
}


// Performs the trivium symmetric decryption
pub fn homomoprhic_symmetric_dec(input : Vec<bool>, key : [Ciphertext; 80], iv : [bool; 80], sk : &ServerKey) -> Vec<Ciphertext> {
    let fhe_keystream = get_cipher_keystream_n(key, iv, input.len(), sk);
    xor_with_plain(&fhe_keystream, &input, &sk)
}

