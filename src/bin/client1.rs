/// This binary runs the client for Protocol I, a protocol for fair data exchange using homomorphic encryption

use std::fs;
use std::io::{ Write};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;
use tfhe::boolean::prelude::*;
use fde_protocols::homomorphic_functions::{decrypt_bools, hex_sha3, sha3_256_fhe, unpad_sha3_256_bytes};
use fde_protocols::prot_utils::*;


fn main() {
    // 1 : retrieve the hash of the data
    let hash_data = fs::read_to_string(HASH_FILE).map_err(|e| {
        format!(
            "Failed to read `{}`: {}",
            HASH_FILE, e
        )
    }).unwrap();

    let mut time_recap: String = String::new();

    // 2 : wait for the server to send ct, evk, op, and unserialize them
    println!("Client ▶ listening on port {} …", CLIENT_PORT);
    let listener =
        TcpListener::bind(("127.0.0.1", CLIENT_PORT)).expect("Failed to bind Client listener");
    let (server_conn, addr) = listener
        .accept()
        .expect("Failed to accept connection from Server");
    println!("Client ▶ accepted connection from Server at {}", addr);


    let ct_serialized : Vec<u8> = read_one_message(&server_conn).unwrap();
    let pk_serialized : Vec<u8> = read_one_message(&server_conn).unwrap();
    let com_serialized : Vec<u8> = read_one_message(&server_conn).unwrap();
    let len_comm = ct_serialized.len() + pk_serialized.len() + com_serialized.len();
    let ct : Vec<Ciphertext> = bincode::deserialize(&ct_serialized).unwrap();
    let ct_copy = ct.clone();
    let pk : ServerKey = bincode::deserialize(&pk_serialized).unwrap();

    println!(
        "Client ▶ read {} bytes total from Server (JSON).",
        len_comm
    );

    let com_off_chain = format!(
        "OFF-CHAIN COMMUNICATION COST: {} bytes (ct is {} bytes, pk is {} bytes, com is {} bytes)\n",
        len_comm,
        ct_serialized.len(),
        pk_serialized.len(),
        com_serialized.len(),
    );

    // 3 : compute the hash of the data homomorphically
    let start = Instant::now();
    let hash_enc = sha3_256_fhe(ct, &pk);
    let time = start.elapsed();
    time_recap.push_str(&format!(" (homomorphic hash time is : {:?},", time));
    let mut full_time = time;
    println!("Client ▶ computed Hct = SHA3(ct)");

    // 4 : send the hash and homomorphic hash to the smart contract,
    let hash_enc_serialized = bincode::serialize(&hash_enc.to_vec()).unwrap();
    let hash_serialized = bincode::serialize(&hash_data).unwrap();
    println!("Client ▶ connecting to SmartContract at port {} …", SC_PORT);
    let mut sc_conn =
        TcpStream::connect(("127.0.0.1", SC_PORT)).expect("Failed to connect to SmartContract");

    sc_conn.write_all(prepare_message(&hash_enc_serialized).as_slice()).expect("Failed to write data to SmartContract");
    sc_conn.write_all(prepare_message(&hash_serialized).as_slice()).expect("Failed to write data to SmartContract");
    sc_conn.write_all(prepare_message(&com_serialized).as_slice()).expect("Failed to write data to SmartContract");
    println!("Client ▶ sent (H, Hct, Com) on‐chain to SmartContract");

    // 5 : Wait for the secret key / status message (if the protocol suceeded or not),
    // in a real scenario the secret key would be public at that point
    // and the smart contract wouldn't have had to send it
    let mut status_data = read_one_message(&sc_conn).unwrap();
    let data = read_one_message(&sc_conn).unwrap();
    let status = status_data.pop().unwrap();

    if status == ABORT {
        println!("Client ▶ final outcome from SmartContract = ABORT");
        println!("Client ▶ done.");
    }else{
        println!("Client ▶ final outcome from SmartContract = SUCCESS");
        println!("Client ▶ decrypting the data....");

        // 6 : Unserialize the secret key, decrypt the data and check that it was the expected data
        let secret_key : ClientKey = bincode::deserialize(&data).unwrap();
        let start = Instant::now();
        let data = decrypt_bools(&ct_copy, &secret_key);
        let unpaded_data = unpad_sha3_256_bytes(data.as_slice());
        let time = start.elapsed();
        time_recap.push_str(&format!(" decryption time is : {:?})", time));
        full_time = time + full_time;

        println!("Client ▶ Computing the hash....");
        let direct_hash = hex_sha3(unpaded_data.as_slice());
        let real = hash_data.clone();
        if direct_hash ==  real{
            println!("Client RETRIEVED THE EXPECTED DATA");
        }else{
            println!("Client DID NOT RETRIEVE THE EXPECTED DATA");
            println!("real hash is : {}", real);
            println!("homomorphic decryption then hash : {}", direct_hash);
        }
    }

    // 7 : Print some statistics about the run
    let mut beginning_time_string = String::new();
    beginning_time_string.push_str(&format!(
        "CLIENT COMPUTATION COST IS {:?}" , full_time
    ));
    beginning_time_string.push_str(time_recap.as_str());
    println!("{}", beginning_time_string);
    println!("{}", com_off_chain);
}
