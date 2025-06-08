# Fair Data Exchange via Homomorphic Encryption 

This project contains the code to run two different fair data exchange protocols. 
They use one instance of client, server, and smart contract each. 

## Protocol I 
Uses client1.rs, smart_contract1.rs, server1.rs, uses homomorphic encryption to enable fair data exchange, where 


## Running the protocols 
Before running any of the two protocols, you should build the project in release mode. 
`cargo build --release`

Then you should run setup, you can either give to setup a file with the data you want to exchange or a size in bytes, in that case it will exchange a random data of that size (in case you just want to test the functionality of the project). 

`./target/release/setup --size 128`
`./target/release/setup --filename data.txt`


