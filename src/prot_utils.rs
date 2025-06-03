use tfhe::boolean::ciphertext::Ciphertext;
use tfhe::boolean::client_key::ClientKey;
use crate::commitment::*;
use crate::homomorphic_functions::{decrypt_bools, bools_to_hex, sha3_hash_from_vec_bool};
use std::io::{self, Read};
use std::net::{TcpStream};

pub const SUCCESS: u8 = 1;
pub const ABORT: u8 = 0;
pub const CLIENT_PORT: u16 = 9002;
pub const SC_PORT: u16 = 9003;
pub const SERVER_PORT: u16 = 9001;

pub const DATA_FILE : &str = "data.txt";
pub const HASH_FILE : &str = "hash.txt";

// Verify function for smart contract and server for protocol I
pub fn verify(hash_ct : Vec<Ciphertext>, hash : String, com : String, op : &Opening) -> bool {
    if !verify_open(com, op) { return false }
    let secret_key : ClientKey = bincode::deserialize(op.data.as_slice()).unwrap();
    let hash_comp = decrypt_bools(&hash_ct, &secret_key);
    bools_to_hex(&hash_comp) == hash
}

// VerifyKA function for smart contract and server for protocol II
pub fn verify_ka(hash_a : String, hash_k : String, a : Vec<bool>, k : Vec<bool>) -> bool {
    let hash_a_comp = sha3_hash_from_vec_bool(a);
    let hash_k_comp = sha3_hash_from_vec_bool(k);
    hash_a_comp == hash_a && hash_k_comp == hash_k
}


// Reads one message, does not wait for connection to be closed
pub fn read_one_message(mut stream: &TcpStream) -> io::Result<Vec<u8>> {
    // Read  4 bytes for the big-endian length prefix
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    // Read the message
    let mut buf = vec![0u8; msg_len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn prepare_message(msg: &[u8]) -> Vec<u8> {
    let len = msg.len() as u32;
    // length in big endian
    let len_be = len.to_be_bytes();

    // Append the message to its length
    let mut buf = Vec::with_capacity(4 + msg.len());
    buf.extend_from_slice(&len_be);
    buf.extend_from_slice(msg);

    buf
}


// Reads all data from stream until EOF into buf.
pub fn read_all_bytes(mut stream: TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .expect("Failed to read JSON from Server");
    buf
}