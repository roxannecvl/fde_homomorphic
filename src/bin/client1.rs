
use std::io::{read_to_string, Write};
use std::net::{TcpListener, TcpStream};
use tfhe::boolean::prelude::*;
use fde_protocols::homomorphic_functions::{trivial_bools_256};
use fde_protocols::prot1_utils::*;


fn main() {
    println!("Client ▶ listening on port {} …", CLIENT_PORT);
    let listener =
        TcpListener::bind(("127.0.0.1", CLIENT_PORT)).expect("Failed to bind Client listener");

    // First, wait for the server to send ct, evk, op
    let (server_conn, addr) = listener
        .accept()
        .expect("Failed to accept connection from Server");
    println!("Client ▶ accepted connection from Server at {}", addr);

    // Read the server's message (until EOF)
    let all_bytes = read_all_bytes(server_conn);
    let len_comm = all_bytes.len();
    println!(
        "Client ▶ read {} bytes total from Server (JSON).",
        len_comm
    );

    // ─── Parse JSON into our struct ───
    let string_msg = read_to_string(all_bytes.as_slice()).expect("Failed to read data");
    let msg: Message1 = serde_json::from_str(&string_msg).expect("Failed to deserialize JSON");

    let ct : Vec<Ciphertext> = bincode::deserialize(&msg.ct).unwrap();
    let pk : ServerKey = bincode::deserialize(&msg.pk).unwrap();
    println!(
        "Client ▶ deserialized JSON; ct is {} bytes, pk is {} bytes, com is {} bytes ===> TOTAL IS {} bytes .",
        msg.ct.len(),
        msg.pk.len(),
        msg.com.len(),
        len_comm,
    );

    // TODO : write on outcome file the total off chain communication

    // TODO : read the hash form the txt
    let hash = "f2b1ec10ed2a3b2d2b2738c5c4d36edd51caea4c15111fde90f2bf660e486853";

    let fake_bools = [true, false, true, true, true, false, true, true,true, false, true,
        true, true, false, true, true, true, false, true, true, true, false, true, true,true, false,
        true, true, true, false, true, true, true, false, true, true, true, false, true, true, true,
        false, true, true, true, false, true, true, true, false, true, true, true, false, true, true,
        true, false, true, true, true, false, true, true, true, false, true, true, true, false, true,
        true,true, false, true, true, true, false, true, true, true, false, true, true, true, false,
        true, true,true, false, true, true, true, false, true, true, true, false, true, true, true,
        false, true, true, true, false, true, true, true, false, true, true, true, false, true, true,
        true, false, true, true, true, false, true, true, true, false, true, true, true, false, true,
        true, true, false, true, true,true, false, true, true, true, false, true, true, true, false,
        true, true, true, false, true, true,true, false, true, true, true, false, true, true, true,
        false, true, true, true, false, true, true, true, false, true, true, true, false, true, true,
        true, false, true, true, true, false, true, true, true, false, true, true, true, false, true,
        true, true, false, true, true, true, false, true, true,true, false, true, true, true, false,
        true, true, true, false, true, true, true, false, true, true,true, false, true, true, true,
        false, true, true, true, false, true, true, true, false, true, true, true, false, true, true,
        true, false, true, true, true, false, true, true, true, false, true, true, true, false, true,
        true, true, false, true, true,];


    let mut hash_enc = trivial_bools_256(&fake_bools, &pk).to_vec();
    hash_enc[0]  = ct[0].clone();

    // let hash_enc = sha3_256_fhe(ct, &pk);
    println!("Client ▶ computed Hct = SHA3(ct)");

    let hash_enc_serialize = bincode::serialize(&hash_enc).unwrap();
    let hash_serialize = bincode::serialize(hash).unwrap();
    let com_serialize = msg.com.clone();

    let msg2 : Message2 = Message2{h:hash_serialize, h_ct:hash_enc_serialize, com:com_serialize};
    let msg2_data = serde_json::to_string_pretty(&msg2).unwrap();


    // Connect to SmartContract and send (H, Hct):
    println!("Client ▶ connecting to SmartContract at port {} …", SC_PORT);
    let mut sc_conn =
        TcpStream::connect(("127.0.0.1", SC_PORT)).expect("Failed to connect to SmartContract");

    sc_conn.write_all(msg2_data.as_bytes()).expect("Failed to write data to SmartContract");
    println!("Client ▶ sent (H, Hct, Com) on‐chain to SmartContract");

    // Wait for "end_successful" / "end_unsuccessful" from SmartContract:
    let status_bytes = read_all_bytes(sc_conn);
    let outcome = String::from_utf8(status_bytes).expect("Invalid UTF‐8 in outcome");
    println!("Client ▶ final outcome from SmartContract = {}", outcome);

    println!("Client ▶ done.");
}
