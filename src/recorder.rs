use std::io::prelude::*;
use std::fs::File;
use std::net::UdpSocket;
use std::str;
use std::thread;
//use rflow::test;

pub fn main() {
    
    let socket = match UdpSocket::bind("192.168.1.189:2055") {
        Ok(s) => s,
        Err(e) => panic!("couldn't bind socket: {}", e)
    };

    let mut file = match File::create("recorded.netflow") {
        Ok(b) => b,
        Err(e) => panic!("failed to open file {}", e)
    };

    let mut buf = [0; 2048];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((amt, src)) => {
                thread::spawn(move || {
                    println!("amt: {}", amt);
                    println!("src: {}", src);
                    println!("{}", str::from_utf8(&buf).unwrap_or(""));
                    println!("buf={:x?}", buf);
                });
                file.write_all(&buf);
            },
            Err(e) => {
                println!("couldn't recieve a datagram: {}", e);
            }
        }
    }
}
