/// This binary runs the client for Protocol II, a protocol for fair data exchange using hybrid homomorphic encryption
use std::fs;
use std::io::{ Write};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;
use rand::Rng;
use tfhe::boolean::prelude::*;
use fde_protocols::homomorphic_functions::{compute_challenge, hex_sha3, homomoprhic_symmetric_dec, pad_sha3_256_cipher, sha3_256_fhe, sha3_hash_from_vec_bool, symmetric_dec, unpad_sha3_256_bytes};
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

    // 2 : wait for the server to send Hk, k_ct, IV, ct, sk and unserialize them
    println!("Client ▶ listening on port {} …", CLIENT_PORT);
    let listener =
        TcpListener::bind(("127.0.0.1", CLIENT_PORT)).expect("Failed to bind Client listener");
    let (mut server_conn, addr) = listener
        .accept()
        .expect("Failed to accept connection from Server");
    println!("Client ▶ accepted connection from Server at {}", addr);

    let sym_enc_data_serialized = read_one_message(&server_conn).unwrap();
    let encrypted_sym_key_serialized = read_one_message(&server_conn).unwrap();
    let sym_key_hash_serialized = read_one_message(&server_conn).unwrap();
    let iv_serialized = read_one_message(&server_conn).unwrap();
    let public_key_serialized = read_one_message(&server_conn).unwrap();

    let sym_enc_data : Vec<bool> = bincode::deserialize(&sym_enc_data_serialized).unwrap();
    let encrypted_sym_key_part : Vec<Ciphertext> = bincode::deserialize(&encrypted_sym_key_serialized).unwrap();
    let encrypted_sym_key : [Ciphertext; 80] = encrypted_sym_key_part.try_into().unwrap();

    let sym_key_hash : String = bincode::deserialize(&sym_key_hash_serialized).unwrap();
    let iv_part : Vec<bool> = bincode::deserialize(&iv_serialized).unwrap();
    let iv : [bool; 80] = iv_part.try_into().unwrap();
    let public_key : ServerKey = bincode::deserialize(&public_key_serialized).unwrap();

    let len_comm = sym_enc_data_serialized.len() + encrypted_sym_key_serialized.len() +
        sym_key_hash_serialized.len() + iv_serialized.len() + public_key_serialized.len();

    println!(
        "Client ▶ read {} bytes total from Server (JSON).",
        len_comm
    );

    // 3 : run CreateChal
    // 3a : decrypt the data homomorphically
    println!("Client ▶ decrypting the data homomorphically...");
    let start = Instant::now();
    let small_start = Instant::now();
    let data_dec = homomoprhic_symmetric_dec(sym_enc_data.clone(), encrypted_sym_key.clone(), iv,  &public_key);
    let small_time = small_start.elapsed();
    println!("Decrypting the data homomorphically took {:?}", small_time);

    // 3b : compute the hash of data homomorphically
    let small_start = Instant::now();
    println!("Client ▶ Computing the hash of the data homomorphically ...");
    let data_hash_comp = sha3_256_fhe(data_dec, &public_key);
    let small_time = small_start.elapsed();
    println!("Computing the hash of the data took {:?}", small_time);

    // 3c : compute the hash of symmetric key homomorphically
    let small_start = Instant::now();
    println!("Client ▶ Computing the hash of the key homomorphically ...");
    let padded_sym_key = pad_sha3_256_cipher(encrypted_sym_key.to_vec(), &public_key);
    let key_hash_comp = sha3_256_fhe(padded_sym_key.to_vec(), &public_key);
    let small_time = small_start.elapsed();
    println!("Computing the hash of the key {:?}", small_time);

    // 3d : compute the final challenge with the intermediate values
    println!("Client ▶ computing the challenge with the hashes ...");
    let small_start = Instant::now();
    let (a, b, c) = get_rand_abc();

    // get the plaintext hashes
    let sym_key_hash_bytes = hex::decode(sym_key_hash).unwrap();
    let sym_key_hash_bits_vec : Vec<bool> =  sym_key_hash_bytes.iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8)).collect();
    let sym_key_hash_bits : [bool; 256] = sym_key_hash_bits_vec.try_into().unwrap();
    let data_hash_bytes = hex::decode(hash_data.clone()).unwrap();
    let data_hash_bits_vec: Vec<bool> =  data_hash_bytes.iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8)).collect();
    let data_hash_bits: [bool; 256] = data_hash_bits_vec.try_into().unwrap();

    let chal = compute_challenge(
        &key_hash_comp, &data_hash_comp, &sym_key_hash_bits, &data_hash_bits, &a, &b, &c, &public_key);
    let small_time = small_start.elapsed();
    println!("Computing the chal {:?}", small_time);
    let time = start.elapsed();
    let mut full_time = time;
    time_recap.push_str(&format!(" (createChal : {:?},", time));

    // 4 : send chal to the server
    let chal_serialized = bincode::serialize(&chal.as_slice()).unwrap();
    server_conn.write_all(prepare_message(chal_serialized.as_slice()).as_slice()).unwrap();
    println!("Client ▶ sent chal to the server");
    let com_off_chain = format!(
        "OFF-CHAIN COMMUNICATION COST: {} bytes (ct is {} bytes, H_k is {} bytes, k_ct is {} bytes, iv is {},  public_key is {} bytes, chal is {} bytes)\n",
        len_comm + chal_serialized.len(),
        sym_enc_data_serialized.len(),
        sym_key_hash_serialized.len(),
        encrypted_sym_key_serialized.len(),
        iv_serialized.len(),
        public_key_serialized.len(),
        chal_serialized.len()
    );
    let hash_a = sha3_hash_from_vec_bool(a.to_vec());

    // 5 : send the hash of a and of the hash key to the smart contract
    let h_a_serialized = bincode::serialize(&hash_a).unwrap();
    println!("Client ▶ connecting to SmartContract at port {} …", SC_PORT);
    let mut sc_conn =
        TcpStream::connect(("127.0.0.1", SC_PORT)).expect("Failed to connect to SmartContract");
    sc_conn.write_all(prepare_message(&h_a_serialized).as_slice()).expect("Failed to write data to SmartContract");
    sc_conn.write_all(prepare_message(&sym_key_hash_serialized).as_slice()).expect("Failed to write data to SmartContract");
    println!("Client ▶ sent (Ha, Hk) on‐chain to SmartContract");

    // 6 : wait for the secret symmetric key and status from smart contract (in real life those
    // values would be public on the blockchain)
    let mut status_data = read_one_message(&sc_conn).unwrap();
    let key_serialized = read_one_message(&sc_conn).unwrap();
    let key_part : Vec<bool> = bincode::deserialize(&key_serialized).unwrap();
    let key : [bool; 80] = key_part.try_into().unwrap();
    let status = status_data.pop().unwrap();

    if status == ABORT {
        println!("Client ▶ final outcome from SmartContract = ABORT");
        println!("Client ▶ done.");
    }else{
        // 7 : decrypt the data symmetrically with the symmetric key and check that it has the
        // expected hash
        println!("Client ▶ final outcome from SmartContract = SUCCESS");
        println!("Client ▶ decrypting the data....");
        let start = Instant::now();
        let data_dec = symmetric_dec(sym_enc_data.to_vec(), key, iv);
        let unpaded_data = unpad_sha3_256_bytes(data_dec.as_slice());
        let time = start.elapsed();
        time_recap.push_str(&format!(" decryption time is : {:?})", time));
        full_time = time + full_time;
        println!("Client ▶ Computing the hash....");

        let direct_hash = hex_sha3(unpaded_data.as_slice());
        let real = hash_data.clone();
        if direct_hash ==  real{
            println!("Client RETRIEVED THE EXPECTED DATA");
        }else{
            println!("real hash is : {}", real);
            println!("homomorphic decryption then hash : {}", direct_hash);
        }
    }

    // 8 : Print some statistics about the run
    let mut beginning_time_string = String::new();
    beginning_time_string.push_str(&format!(
        "CLIENT COMPUTATION COST IS {:?}" , full_time
    ));

    beginning_time_string.push_str(time_recap.as_str());
    println!("{}", beginning_time_string);
    println!("{}", com_off_chain);
}

/// Returns a triple of random bit strings
fn get_rand_abc()->([bool; 256], [bool; 256], [bool; 256]){
    let mut buf_a = vec![0u8; 32];
    rand::thread_rng().fill(&mut buf_a[..]);
    let mut buf_b = vec![0u8; 32];
    rand::thread_rng().fill(&mut buf_b[..]);
    let mut buf_c = vec![0u8; 32];
    rand::thread_rng().fill(&mut buf_c[..]);

    let mut a: [bool;256] = [false; 256];
    let mut b: [bool;256] = [false; 256];
    let mut c: [bool;256] = [false; 256];


    for (byte_idx, ((byte_a, byte_b), byte_c)) in buf_a.iter().zip(buf_b).zip(buf_c).enumerate() {
        for bit_in_byte in 0..8 {
            let mask = 1 << (bit_in_byte);
            let bool_a = (byte_a & mask) != 0;
            let bool_b = (byte_b & mask) != 0;
            let bool_c = (byte_c & mask) != 0;
            a[byte_idx * 8 + bit_in_byte] = bool_a;
            b[byte_idx * 8 + bit_in_byte] = bool_b;
            c[byte_idx * 8 + bit_in_byte] = bool_c;
        }
    }
    (a, b, c)
}
