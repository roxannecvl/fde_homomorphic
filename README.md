# Fair Data Exchange via Homomorphic Encryption 

This project contains the code to run two different fair data exchange protocols. 
They use one instance of client, server, and smart contract each. Protocol I uses homomorphic encryption while Protocol II uses hybrid homomorphic encryption.

## Prerequisites 
Rust and Cargo are needed to run this project.
Install Rust and Cargo in one command using [rustup](https://rustup.rs/):
```bash
curl https://sh.rustup.rs -sSf | sh
```
Ensure that `$HOME/.cargo/bin` is in your system's PATH. You might need to source your shell's configuration file (e.g., `source $HOME/.cargo/env` or `source ~/.bashrc`) or restart your terminal.

If you already have rust, make sure it updated with: 
```bash
rustup update
```

Make sure rust is correctly installated with: 
```bash
 rustc --version
```

## Running the protocols 
 > **Warning:** All commands are expected to be run from the root of this project

Before running any of the two protocols, you should build the project in release mode. 
`cargo build --release`

Then you should run the `setup` binary. You can either give to `setup` the filename of the file which contains the data you want to exchange or a size in bytes, in that case it will exchange a random data of that size (in case you just want to test the functionality of the project). For example:
```bash 
./target/release/setup --size 128 # option 1 with size
./target/release/setup --filename filename.txt # option 2 with filename
```


This will create two files, `data.txt`, with the data, and `hash.txt` with the hash of the data. If you already have these two files in the root of this project, running `setup` is not necessary.

### Protocol I 

You have two options to run Protocol I 
#### Option 1 
Open 3 terminals and run the client, the server and the smart contract in each of them separately. Always start with the client, then smart contract, then server. 
```bash
./target/release/client1 # in terminal 1 
```
```bash
./target/release/smart_contract1 # in terminal 2
```
```bash
./target/release/server1 # in terminal 3 
```

#### Option 2 
If you just want to test the the protocol, you can run the script `./run_prot1.sh <size>` which will call `./target/release/setup`, run the `client1`, `server1` and `smart_contract1`, and append a summary of the run (communication and computation costs) in `prot1_output.txt`. You'll find more details about the run in `client_out.txt`, `server_out.txt` and `sc_out.txt`. 

### Protocol II 

Similarly, you have two options to run Protocol II 
#### Option 1 
Open 3 terminals and run the client, the server and the smart contract in each of them separately. Always start with the client, then smart contract, then server. 
```bash
./target/release/client2 # in terminal 1 
```
```bash
./target/release/smart_contract2 # in terminal 2
```
```bash
./target/release/server2 # in terminal 3 
```

#### Option 2 
If you just want to test the the protocol, you can run the script `./run_prot2.sh <size>` which will call `./target/release/setup`, run the `client2`, `server2` and `smart_contract2`, and append a summary of the run (communication and computation costs) in `prot2_output.txt`. You'll find more details about the run in `client2_out.txt`, `server2_out.txt` and `sc2_out.txt`. 


## Evaluating the performance of the protocols 
 > **Warning:** Evaluating the performance is a time-consuming operation.


First, make sure you delete or move `prot1_output.txt` and `prot2_output.txt`. 
To evaluate the protocols you should run
```bash
./eval_prot1.sh
./eval_prot2.sh
```
You can modify in these two scripts how many times you should evaluate each size and on which different sizes you want to evaluate. 
This will output two summary files `prot1_output.txt` and `prot2_output.txt`, with a recap of computation and communication costs for each run. 
To get graphs you can run: 
```python
python graph_plotter.py
```
This will produce 5 `.png` files: communication costs (off and on chain), computation costs (for client, server, and smart contract). 

## Proprietary code 
**The following code was taken as is from the tfhe-rs library**

`./src/static_decque/*` from  [tfhe-rs trivium app](https://github.com/zama-ai/tfhe-rs/tree/main/apps/trivium/src/static_deque)

`./encryption.rs` from the main in the [sha256_bool example](https://github.com/zama-ai/tfhe-rs/blob/main/tfhe/examples/sha256_bool/main.rs)

**The following code was slightly adapted from the tfhe-rs library** 

`./src/new_trivium.rs` from  [tfhe-rs trivium app](https://github.com/zama-ai/tfhe-rs/blob/main/apps/trivium/src/trivium/trivium_bool.rs)

`./src/boolean_ops64.rs` from tfhe-rs sha256_bool example, [boolean_ops.rs](https://github.com/zama-ai/tfhe-rs/blob/main/tfhe/examples/sha256_bool/boolean_ops.rs)

all functions in `./src/boolean_ops256.rs` from tfhe-rs sha256_bool example, [boolean_ops.rs](https://github.com/zama-ai/tfhe-rs/blob/main/tfhe/examples/sha256_bool/boolean_ops.rs) except: 
`compute_challenge`, `mul_ciphertext_by_plain_csd_opt_256`, `mult_two_plain_256`, `add_two_plain_256`, `to_csd_be`, `to_csd`

**This proprietary code is thus under the following license**
```
BSD 3-Clause Clear License

Copyright © 2025 ZAMA.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this
list of conditions and the following disclaimer in the documentation and/or other
materials provided with the distribution.

3. Neither the name of ZAMA nor the names of its contributors may be used to endorse
or promote products derived from this software without specific prior written permission.

NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY THIS LICENSE.
THIS SOFTWARE IS PROVIDED BY THE ZAMA AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
ZAMA OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
