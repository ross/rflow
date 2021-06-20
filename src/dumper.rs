use std::io::prelude::*;
use std::fs::File;
use rflow::v5::V5;

pub fn main() {
    let mut file = match File::open("recorded.netflow") {
        Ok(b) => b,
        Err(e) => panic!("failed to open file {}", e)
    };

    let mut buffer = [0_u8; 2048];

    let n = match file.read(&mut buffer) {
        Ok(n) => n,
        Err(e) => panic!("failed to read from file {}", e)
    };

    let mut pos = &buffer[..n];
    while pos.len() > 0 {
        match V5::from_bytes(pos) {
            Ok((rest, v5)) => {
                println!("v5={:#?}", v5);
                pos = rest;
            }
            Err(e) => panic!("failed to parse v5 {}", e)
        }
    }
}
