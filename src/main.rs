use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use rand::RngCore;

fn to_name_list(value: &str) -> Vec<u8> {
    // A string containing a comma-separated list of names.
    // https://datatracker.ietf.org/doc/html/rfc4251#section-5
    // Examples:
    // value                      representation (hex)
    // -----                      --------------------
    // (), the empty name-list    00 00 00 00
    // ("zlib")                   00 00 00 04 7a 6c 69 62
    // ("zlib,none")              00 00 00 09 7a 6c 69 62 2c 6e 6f 6e 65

    let len = (value.len() as u32).to_be_bytes();

    let mut bytes: Vec<u8> = vec![];

    for b in len {
        bytes.push(b);
    }

    for b in value.as_bytes().to_vec() {
        bytes.push(b);
    }

    bytes
}

fn handle_client(mut stream: TcpStream) {
    println!("{:?}", stream);

    let mut buf = [0u8; 32768];
    loop {
        let n = stream.read(&mut buf).unwrap();

        if n == 0 {
            break;
        }

        std::io::stdout().write_all(&buf[..n]).unwrap();
        std::io::stdout().flush().unwrap();

        // send identification string
        const IDENTIFICATION_STRING: &str = "SSH-2.0-rust_custom_ssh_1.0\r\n";
        stream.write_all(IDENTIFICATION_STRING.as_bytes()).unwrap();
        stream.flush().unwrap();

        // init KEX
        let mut kex_packet: Vec<u8> = vec![];

        // SSH_MSG_KEXINIT
        kex_packet.push(20u8);

        // byte[16], cookie (random bytes)
        let mut cookie: [u8; 16] = [0; 16];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut cookie);

        for rand_num in cookie {
            kex_packet.push(rand_num);
        }
        //  name-list    kex_algorithms
        const SUPPORTED_KEX_ALGORITHMS: &str = "diffie-hellman-group14-sha256";
        for cb in SUPPORTED_KEX_ALGORITHMS.as_bytes() {
            let owned_cb = cb.to_owned();
            kex_packet.push(owned_cb);
        }
        //  name-list    server_host_key_algorithms

        //  name-list    encryption_algorithms_client_to_server (ciphers)

        //  name-list    encryption_algorithms_server_to_client (ciphers)

        //  name-list    mac_algorithms_client_to_server

        //  name-list    mac_algorithms_server_to_client

        //  name-list    compression_algorithms_client_to_server

        //  name-list    compression_algorithms_server_to_client

        //  name-list    languages_client_to_server
        //  EMPTY
        //  name-list    languages_server_to_client
        //  EMPTY
        //  boolean      first_kex_packet_follows
        //  FALSE
        //  uint32       0 (reserved for future extension)

        // send list of supported algorithms (KEX)
        stream.write_all(&kex_packet).unwrap();
        stream.flush().unwrap();
    }
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:3022")?;

    for stream in listener.incoming() {
        handle_client(stream?);
    }

    Ok(())
}
