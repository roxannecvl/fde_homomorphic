/// This binary runs the server for Protocol I, a protocol for fair data exchange using homomorphic encryption
use std::io::{ Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::{fs};
use std::time::Instant;
use tfhe::boolean::ciphertext::Ciphertext;
use tfhe::boolean::gen_keys;
use fde_protocols::commitment::{commit};
use fde_protocols::prot_utils::*;
use fde_protocols::homomorphic_functions::{encrypt_bools, pad_sha3_256_bytes};

fn main() {
    // 1 : retrieve the data
    let data = fs::read(DATA_FILE).map_err(|e| {
        format!(
            "Failed to read `{}`: {}",
            DATA_FILE, e
        )
    }).unwrap();

    // 2 : pad and encrypt the data homomorphically
    let mut time_recap: String = String::new();
    let start = Instant::now();
    let padded_input = pad_sha3_256_bytes(data.as_slice());
    let (ck, sk) = gen_keys();
    let enc_data = encrypt_bools(padded_input, &ck);
    let time = start.elapsed();
    time_recap.push_str(&format!(" (pad and encrypt : {:?}, ", time));
    let mut full_time = time;

    // 3 : send the encrypted data and the commitment and the public key to the client
    let ct_serialize = bincode::serialize(&enc_data).unwrap();
    let secret_key_serialize = bincode::serialize(&ck).unwrap();
    let public_key_serialize = bincode::serialize(&sk).unwrap();
    let (commitment, opening) = commit(secret_key_serialize.as_slice());
    let com_serialize = bincode::serialize(&commitment).unwrap();
    let mut client_conn =
        TcpStream::connect(("127.0.0.1", CLIENT_PORT)).expect("Failed to connect to Client");
    client_conn.write_all(prepare_message(&ct_serialize).as_slice()).expect("Failed to write data to SmartContract");
    client_conn.write_all(prepare_message(&public_key_serialize).as_slice()).expect("Failed to write data to SmartContract");
    client_conn.write_all(prepare_message(&com_serialize).as_slice()).expect("Failed to write data to SmartContract");
    println!("Server ▶ sent (ct, pk, com) off-chain to Client");
    client_conn.shutdown(Shutdown::Both).expect("Failed to shutdown Client");
    println!("Server ▶ shutdown Client");

    // 4:  Listen to the smart contract for Hct, H, com
    let listener =
        TcpListener::bind(("127.0.0.1", SERVER_PORT)).expect("Failed to bind Server listener");
    let (mut sc_conn, _) = listener
        .accept()
        .expect("Failed to accept connection from SmartContract");
    let hash_enc_serialized = read_one_message(&sc_conn).unwrap();
    let hash_serialized = read_one_message(&sc_conn).unwrap();
    let com_serialized = read_one_message(&sc_conn).unwrap();
    let h_ct : Vec<Ciphertext> = bincode::deserialize(&hash_enc_serialized).unwrap();
    let h : String = bincode::deserialize(&hash_serialized).unwrap();
    let com : String = bincode::deserialize(&com_serialized).unwrap();

    // 5 : run the verify function
    println!("Server ▶ Verifying client's inputs");
    let start = Instant::now();
    let verif = verify(h_ct, h, com, &opening);
    let time = start.elapsed();
    time_recap.push_str(&format!(" verify : {:?})", time));
    full_time += time;

    // 6 : send the secret key to the smart contract
    let status = if verif { SUCCESS } else {ABORT};
    let nonce = if verif {opening.nonce} else {[0u8; 32]};
    let data = if verif {opening.data} else {vec![0u8; 0]};
    sc_conn.write_all(prepare_message(&[status]).as_slice()).expect("Failed to write data to SmartContract");
    sc_conn.write_all(prepare_message(&nonce).as_slice()).expect("Failed to write data to SmartContract");
    sc_conn.write_all(prepare_message(&data).as_slice()).expect("Failed to write data to SmartContract");
    println!("Server ▶ sent (status, opening) on‐chain to SmartContract");

    // 7 : wait for the final success signal from smart contract
    let status_bytes = read_one_message(&sc_conn).unwrap().pop().unwrap();
    println!("Server ▶ final outcome from SmartContract = {}", status_bytes);
    println!("Server ▶ done.");

    // 8 : print statistics about the run
    let mut beginning_time_string = String::new();
    beginning_time_string.push_str(&format!(
        "SERVER COMPUTATION COST IS {:?}" , full_time
    ));
    beginning_time_string.push_str(time_recap.as_str());
    println!("{}", beginning_time_string);
}
