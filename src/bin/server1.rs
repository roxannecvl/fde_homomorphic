use rand::Rng;
use std::io::{read_to_string, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use serde::{Deserialize, Serialize};
use tfhe::boolean::ciphertext::Ciphertext;
use tfhe::boolean::gen_keys;
use tfhe::boolean::prelude::ServerKey;
use fde_protocols::commitment::commit;
use fde_protocols::prot1_utils::*;
use fde_protocols::homomorphic_functions::{decrypt_bools, encrypt_bools, pad_sha3_256_bytes};




fn main() {
    //Todo read data from file
    let data = "easy_input";
    let padded_input = pad_sha3_256_bytes(data.as_bytes());

    let (ck, sk) = gen_keys();
    let enc_data = encrypt_bools(padded_input, &ck);

    let ct_serialize = bincode::serialize(&enc_data).unwrap();
    let pk_serialize = bincode::serialize(&ck).unwrap();
    let sk_serialize = bincode::serialize(&sk).unwrap();

    let (commitment, opening) = commit(sk_serialize.as_slice());
    let com_serialize = bincode::serialize(&commitment).unwrap();

    let msg1 : Message1 = Message1{ct: ct_serialize, pk: pk_serialize, com: com_serialize};
    let msg1_data = serde_json::to_string_pretty(&msg1).unwrap();
    let mut client_conn =
        TcpStream::connect(("127.0.0.1", CLIENT_PORT)).expect("Failed to connect to Client");
    client_conn.write_all(msg1_data.as_bytes()).expect("Failed to write data to SmartContract");
    println!("Server ▶ sent (ct, pk, com) off-chain to Client");


    // Listen for smart contract Hct, H, com
    let listener =
        TcpListener::bind(("127.0.0.1", SERVER_PORT)).expect("Failed to bind Server listener");

    let (sc_conn, addr) = listener
        .accept()
        .expect("Failed to accept connection from SmartContract");

    // Read the server's message (until EOF)
    let all_bytes = read_all_bytes(sc_conn);

    // ─── Parse JSON into our struct ───
    let string_msg = read_to_string(all_bytes.as_slice()).expect("Failed to read data");
    let msg2: Message2 = serde_json::from_str(&string_msg).expect("Failed to deserialize JSON");

    let h : String = bincode::deserialize(&msg2.h).unwrap();
    let h_ct : Vec<Ciphertext> = bincode::deserialize(&msg2.h_ct).unwrap();
    let com : String = bincode::deserialize(&msg2.com).unwrap();

    let verif = verify(h_ct, h, com, &opening);
    let empty_key = [0u8].to_vec();
    let msg3 : Message3 = if verif {
        Message3{status: true, secret_key: bincode::serialize(&ck).unwrap()}
    } else {
        Message3{status: false, secret_key: empty_key}
    };


    let msg3_data = serde_json::to_string_pretty(&msg3).unwrap();
    println!("Server ▶ connecting to SmartContract at port {} …", SC_PORT);
    let mut sc_conn =
        TcpStream::connect(("127.0.0.1", SC_PORT)).expect("Failed to connect to SmartContract");

    sc_conn.write_all(msg3_data.as_bytes()).expect("Failed to write data to SmartContract");
    println!("Server ▶ sent (status, key) on‐chain to SmartContract");

    // Wait for "end_successful" / "end_unsuccessful" from SmartContract:
    let status_bytes = read_all_bytes(sc_conn);
    let outcome = String::from_utf8(status_bytes).expect("Invalid UTF‐8 in outcome");
    println!("Server ▶ final outcome from SmartContract = {}", outcome);

    println!("Server ▶ done.");
}
