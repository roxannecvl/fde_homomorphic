/// This binary runs the smart contract for Protocol II, a protocol for fair data exchange using hybrid homomorphic encryption
use std::io::{Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Instant;
use fde_protocols::prot_utils::*;

fn main() {
    // 1 : wait for the client to send Ha, Hk, and unserialize them
    println!("Smart Contract ▶ listening on port {} …", SC_PORT);
    let listener =
        TcpListener::bind(("127.0.0.1", SC_PORT)).expect("Failed to bind SmartContract listener");
    let (mut client_conn, addr) = listener
        .accept()
        .expect("Failed to accept connection from Client");
    println!("Smart Contract ▶ accepted connection from client at {}", addr);
    let mut time_recap: String = String::new();
    time_recap.push_str(&format!(
        "SMART CONTRACT COMPUTATION COST {}",
        ""
    ));
    let hash_a_serialized = read_one_message(&client_conn).unwrap();
    let hash_k_serialized = read_one_message(&client_conn).unwrap();
    let len_comm = hash_a_serialized.len() + hash_k_serialized.len();
    println!("Smart Contract ▶ read {} bytes total from Client (JSON).", len_comm);
    let h_a : String = bincode::deserialize(&hash_a_serialized).unwrap();
    let h_k : String = bincode::deserialize(&hash_k_serialized).unwrap();

    // 2 : wait for the server to send a, k and the status from the server
    let mut server_conn =
        TcpStream::connect(("127.0.0.1", SERVER_PORT)).expect("Failed to connect to Server");
    server_conn.write_all(&prepare_message(&hash_a_serialized)).expect("Failed to write data to Server");
    server_conn.write_all(&prepare_message(&hash_k_serialized)).expect("Failed to write data to Server");
    let mut status_data = read_one_message(&server_conn).unwrap();
    let k_serialized = read_one_message(&server_conn).unwrap();
    let a_serialized = read_one_message(&server_conn).unwrap();
    let op_len = k_serialized.len() + a_serialized.len();
    let mut status = status_data.pop().unwrap();
    let message_for_client2 = prepare_message(k_serialized.as_slice());

    // 3 : if the server aborted, abort as well
    if status == ABORT {
        let message_for_client1 = prepare_message(status_data.as_slice());
        let message_for_server = prepare_message([ABORT].as_slice());

        client_conn.write_all(&message_for_client1).expect("Failed to write data to Client");
        client_conn.write_all(&message_for_client2).expect("Failed to write data to Client");
        server_conn.write_all(&message_for_server).expect("Failed to write data to Server");
    }else {
        // 4 : run VerifyKA function
        let start = Instant::now();
        let a_bytes = bincode::deserialize(&a_serialized).unwrap();
        let k_bytes = bincode::deserialize(&k_serialized).unwrap();
        let status_bool = verify_ka(h_a, h_k, a_bytes, k_bytes);
        let time = start.elapsed();

        time_recap.push_str(&format!("SMART CONTRACT COMPUTATION COST IS {:?}" , time));
        time_recap.push_str(&format!(" (verify : {:?})", time));

        // 5 : send the final status to client and server, and symmetric secret key to client
        status = if status_bool { SUCCESS }else { ABORT };
        let message_for_client1 = if status_bool {
            prepare_message([SUCCESS].as_slice())
        } else {
            prepare_message([ABORT].as_slice())
        };
        let message_for_server = if status_bool{
            prepare_message([SUCCESS].as_slice())
        }else{
            prepare_message([ABORT].as_slice())
        };
        client_conn.write_all(&message_for_client1).expect("Failed to write data to Client");
        client_conn.write_all(&message_for_client2).expect("Failed to write data to Client");
        server_conn.write_all(&message_for_server).expect("Failed to write data to Server");
        client_conn.shutdown(Shutdown::Both).expect("Failed to shutdown Client");
        server_conn.shutdown(Shutdown::Both).expect("Failed to shutdown Server");
    }

    // 6 : print some statistics about the run
    println!("SmartContract ▶ final outcome from SmartContract = {}", status==SUCCESS);
    println!("SmartContract ▶ done.");
    println!("{}", time_recap);
    println!(
        "ON-CHAIN COMMUNICATION COST: {} bytes (Ha = {}, Hk = {}, a = {}, k = {}) .",
        len_comm + op_len,
        hash_a_serialized.len(),
        hash_k_serialized.len(),
        a_serialized.len(),
        k_serialized.len()
    );
}


