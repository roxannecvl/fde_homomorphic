/// This binary setups the needed file to run the protocols, it creates a data.txt and writes its
/// hash in hash.txt. These files will be used by the client and server in a run of the protocols.
use std::env;
use std::error::Error;
use std::fs;
use std::process;
use rand::Rng;
use fde_protocols::homomorphic_functions::hex_sha3;
use fde_protocols::prot_utils::{DATA_FILE, HASH_FILE};

/// prints usage of the function in case of incorrect usage
fn print_usage_and_exit(program: &str) -> ! {
    eprintln!(
        "Usage:\n give a size (we then use a random data of that size) or a name of the file \
         where there is the data \n  {0} --filename <name.txt>\n  {0} --size <num_bytes>",
        program
    );
    process::exit(1);
}

fn main() -> Result<(), Box<dyn Error>> {
    // 1 : collect command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        print_usage_and_exit(&args[0]);
    }

    // 1a : `data` will hold either the file contents or the generated random bytes.
    let data: Vec<u8> = match args[1].as_str() {
        "--filename" => {
            let input_filename = &args[2];
            // Read entire file into `Vec<u8>` if the user provided a filename
            let contents = fs::read(input_filename).map_err(|e| {
                format!(
                    "Failed to read `{}`: {}",
                    input_filename,
                    e
                )
            })?;
            contents
        }
        "--size" => {
            // parse requested size as usize if the user provided a size and generate `n` random bytes
            let n: usize = args[2].parse().map_err(|e| {
                format!(
                    "Invalid number for --size (`{}`): {}",
                    args[2], e
                )
            })?;
            let mut buf = vec![0u8; n];
            rand::thread_rng().fill(&mut buf[..]);
            buf
        }
        _ => {
            // if the user provided an incorrect command
            print_usage_and_exit(&args[0]);
        }
    };

    // 2 : write the raw bytes into "data.txt"
    fs::write(DATA_FILE, &data)
        .map_err(|e| format!("Could not write data.txt: {}", e))?;

    // 3 : compute SHA3 of data
    let hash = hex_sha3(&data);

    // 4 : write that hex digest into "hash.txt"
    fs::write(HASH_FILE, hash)
        .map_err(|e| format!("Could not write hash.txt: {}", e))?;

    Ok(())
}
