use std::io::{ Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::{fs};
use std::time::Instant;
use rand::Rng;
use tfhe::boolean::ciphertext::Ciphertext;
use tfhe::boolean::gen_keys;
use fde_protocols::prot_utils::*;
use fde_protocols::homomorphic_functions::{decrypt_bools, encrypt_bools, hex_sha3, pad_sha3_256_bytes, pad_sha3_256_cipher, symmetric_enc, unpad_sha3_256_bytes};
fn main() {
    println!("Server ▶ Starting...");
    let data = fs::read(DATA_FILE).map_err(|e| {
        format!(
            "Failed to read `{}`: {}",
            DATA_FILE, e
        )
    }).unwrap();

    let mut time_recap: String = String::new();
    let start = Instant::now();
    let padded_input = pad_sha3_256_bytes(data.as_slice());

    // Get keys
    let (ck, sk) = gen_keys();
    let (sym_key, iv, buf_sym_key) = get_rand_key_iv();

    // Get key stream of length of data and symmetrically encrypt the data
    let sym_enc_data = symmetric_enc(padded_input, sym_key, iv);
    println!("Server ▶ Encrypted the data symmetrically ");
    let time = start.elapsed();
    let mut full_time = time;
    time_recap.push_str(&format!(" (pad and symmetric encryption: {:?}, ", time));

    let start = Instant::now();
    let encrypted_key = encrypt_bools(sym_key.to_vec(), &ck);
    println!("Server ▶ Encrypted the symmetric key homomophically");
    let time = start.elapsed();
    full_time = full_time + time;
    time_recap.push_str(&format!(" homomorphic encryption: {:?}, ", time));

    let start = Instant::now();
    let hash_sym_key = hex_sha3(buf_sym_key.as_slice());
    let time = start.elapsed();
    full_time = full_time + time;
    time_recap.push_str(&format!(" hash of sym key: {:?}, ", time));

    // Send sym_enc_data, hash_key, encrypted_key, iv,  homomorphic_public_key to the client
    let sym_enc_data_serialize = bincode::serialize(&sym_enc_data).unwrap();
    let encrypted_sym_key_serialize = bincode::serialize(&encrypted_key).unwrap();
    let sym_key_hash_serialize = bincode::serialize(&hash_sym_key).unwrap();
    let iv_serialize = bincode::serialize(&iv.as_slice()).unwrap();
    let public_key_serialize = bincode::serialize(&sk).unwrap();

    println!("Server ▶ sent (ct, Hk, kct, pk) off-chain to Client");
    let mut client_conn =
        TcpStream::connect(("127.0.0.1", CLIENT_PORT)).expect("Failed to connect to Client");
    client_conn.write_all(prepare_message(&sym_enc_data_serialize).as_slice()).expect("Failed to write data to SmartContract");
    client_conn.write_all(prepare_message(&encrypted_sym_key_serialize).as_slice()).expect("Failed to write data to SmartContract");
    client_conn.write_all(prepare_message(&sym_key_hash_serialize).as_slice()).expect("Failed to write data to SmartContract");
    client_conn.write_all(prepare_message(&iv_serialize).as_slice()).expect("Failed to write data to SmartContract");
    client_conn.write_all(prepare_message(&public_key_serialize).as_slice()).expect("Failed to write data to SmartContract");

    println!("Server ▶ sent (ct, Hk, kct, pk) off-chain to Client");

    // Listen for client chal and shut down connexion with client
    let chal_data : Vec<u8> = read_one_message(&client_conn).unwrap();
    client_conn.shutdown(Shutdown::Both).expect("Failed to shutdown Client");
    println!("Server ▶ shutdown Client");

    // Compute a
    let start = Instant::now();
    let chal : Vec<Ciphertext> = bincode::deserialize(&chal_data).unwrap();
    let a : Vec<bool> = decrypt_bools(&chal, &ck);
    let time = start.elapsed();
    full_time = full_time + time;
    time_recap.push_str(&format!(" decrypt chal and get â: {:?}, ", time));

    // Listen to smart contract for Ha and Hk
    let listener =
        TcpListener::bind(("127.0.0.1", SERVER_PORT)).expect("Failed to bind Server listener");
    let (mut sc_conn, _) = listener
        .accept()
        .expect("Failed to accept connection from SmartContract");

    let h_a_serialized = read_one_message(&sc_conn).unwrap();
    let h_k_serialized = read_one_message(&sc_conn).unwrap();

    let h_a : String = bincode::deserialize(&h_a_serialized).unwrap();
    let h_k : String = bincode::deserialize(&h_k_serialized).unwrap();

    println!("Server ▶ Verifying client's inputs");
    let start = Instant::now();
    let verif = verify_ka(h_a, h_k, a.clone(), sym_key.to_vec());
    let time = start.elapsed();
    full_time = full_time + time;
    time_recap.push_str(&format!(" verify_ka {:?}", time));


    let status = if verif { SUCCESS } else {ABORT};
    let key = if verif {sym_key} else {[false; 80]};
    let a_sent = if verif {a} else{[false; 256].to_vec()};

    sc_conn.write_all(prepare_message(&[status]).as_slice()).expect("Failed to write data to SmartContract");
    let key_serialized = bincode::serialize(&key.as_slice()).unwrap();
    sc_conn.write_all(prepare_message(key_serialized.as_slice()).as_slice()).expect("Failed to write data to SmartContract");
    let a_serialized = bincode::serialize(&a_sent.as_slice()).unwrap();
    sc_conn.write_all(prepare_message(a_serialized.as_slice()).as_slice()).expect("Failed to write data to SmartContract");

    println!("Server ▶ sent (k, â) on‐chain to SmartContract");

    // Wait for signal from smart contract
    let status_bytes = read_one_message(&sc_conn).unwrap().pop().unwrap();
    println!("Server ▶ final outcome from SmartContract = {}", status_bytes);

    println!("Server ▶ done.");

    let mut beginning_time_string = String::new();
    beginning_time_string.push_str(&format!(
        "SERVER COMPUTATION COST IS {:?}" , full_time
    ));

    beginning_time_string.push_str(time_recap.as_str());
    println!("{}", beginning_time_string);
}

// Returns a random key and iv, both 80-bit bit strings
fn get_rand_key_iv()->([bool; 80], [bool; 80], [u8; 10]){
    let mut buf_key = vec![0u8; 10];
    rand::thread_rng().fill(&mut buf_key[..]);
    let buf_key_ret : &[u8] = buf_key.as_mut_slice();
    let mut buf_iv = vec![0u8; 10];
    rand::thread_rng().fill(&mut buf_iv[..]);

    let mut key_bits: [bool;80] = [false; 80];
    let mut iv_bits:  [bool;80] = [false; 80];

    for (byte_idx, (byte_iv, byte_key)) in buf_iv.iter().zip(buf_key_ret).enumerate() {
        for bit_in_byte in 0..8 {
            let mask = 1 << (bit_in_byte);
            let bool_iv = (byte_iv & mask) != 0;
            let bool_key = (byte_key & mask) != 0;
            iv_bits[byte_idx * 8 + bit_in_byte] = bool_iv;
            key_bits[byte_idx * 8 + bit_in_byte] = bool_key;
        }
    }
    (key_bits, iv_bits, buf_key_ret.try_into().unwrap())
}
