use std::io::{Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Instant;
use tfhe::boolean::prelude::*;
use fde_protocols::commitment::Opening;
use fde_protocols::prot_utils::*;


fn main() {
    println!("Smart Contract ▶ listening on port {} …", SC_PORT);
    let listener =
        TcpListener::bind(("127.0.0.1", SC_PORT)).expect("Failed to bind SmartContract listener");

    // First, wait for the client to send Hct, H, com
    let (mut client_conn, addr) = listener
        .accept()
        .expect("Failed to accept connection from Client");
    println!("Smart Contract ▶ accepted connection from client at {}", addr);

    let mut time_recap: String = String::new();
    time_recap.push_str(&format!(
        "SMART CONTRACT COMPUTATION COST {}",
        ""
    ));

    // Read the client's messages
    let hash_enc_serialized = read_one_message(&client_conn).unwrap();
    let mut len_comm = hash_enc_serialized.len();
    let hash_serialized = read_one_message(&client_conn).unwrap();
    len_comm += hash_serialized.len();
    let com_serialized = read_one_message(&client_conn).unwrap();
    len_comm += com_serialized.len();
    println!(
        "Smart Contract ▶ read {} bytes total from Client (JSON).",
        len_comm
    );

    let h_ct : Vec<Ciphertext> = bincode::deserialize(&hash_enc_serialized).unwrap();
    let h : String = bincode::deserialize(&hash_serialized).unwrap();
    let com : String = bincode::deserialize(&com_serialized).unwrap();

    let mut server_conn =
        TcpStream::connect(("127.0.0.1", SERVER_PORT)).expect("Failed to connect to Server");
    server_conn.write_all(&prepare_message(&hash_enc_serialized)).expect("Failed to write data to Server");
    server_conn.write_all(&prepare_message(&hash_serialized)).expect("Failed to write data to Server");
    server_conn.write_all(&prepare_message(&com_serialized)).expect("Failed to write data to Server");


    let mut status_data = read_one_message(&server_conn).unwrap();
    let nonce = read_one_message(&server_conn).unwrap();
    let data = read_one_message(&server_conn).unwrap();

    let op_len = nonce.len() + data.len();

    let mut status = status_data.pop().unwrap();

    let message_for_client2 = prepare_message(data.as_slice());

    if status == ABORT {
        let message_for_client1 = prepare_message(status_data.as_slice());
        let message_for_server = prepare_message([ABORT].as_slice());

        client_conn.write_all(&message_for_client1).expect("Failed to write data to Client");
        client_conn.write_all(&message_for_client2).expect("Failed to write data to Client");
        server_conn.write_all(&message_for_server).expect("Failed to write data to Server");
    }else {
        let nonce_shape : [u8; 32] = nonce.try_into().unwrap();
        let opening  : Opening = Opening{nonce : nonce_shape, data: data};
        let start =  Instant::now();
        let status_bool = verify(h_ct, h, com, &opening);
        let time = start.elapsed();

        time_recap.push_str(&format!("SMART CONTRACT COMPUTATION COST IS {:?}" , time));
        time_recap.push_str(&format!(" (verify : {:?})", time));

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

    println!("SmartContract ▶ final outcome from SmartContract = {}", status==SUCCESS);

    println!("SmartContract ▶ done.");

    println!("{}", time_recap);
    println!(
        "ON-CHAIN COMMUNICATION COST: {} bytes (Hct = {}, H = {}, com = {}, op = {}) .",
        len_comm + op_len,
        hash_enc_serialized.len(),
        hash_serialized.len(),
        com_serialized.len(),
        op_len,
    );
}


