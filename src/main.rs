use base64::{engine::general_purpose, Engine as _};
use bit_vec::BitVec;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::convert::TryInto;
use std::env;
use std::fmt;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::copy;
use std::mem::transmute;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::str;
use std::time::{Duration, SystemTime};
use std::vec;

fn walk_object(name: &str, x: &Value, result: &mut Vec<String>) {
    let Value::Object(x) = x else { return };
    println!("name {:?}", name);
    println!("value {:?}", x);
    result.push(name.to_string());
    for (name, field) in x {
        println!("name {:?}", name);
        println!("field {:?}", field);
        walk_object(&name, field, result);
    }
}

fn main() -> Result<(), std::io::Error> {
    let mut peers = &mut HashSet::new();
    let socket = UdpSocket::bind("0.0.0.0:34254")?;
    std::env::set_current_dir("./pejovu");
    loop {
        let mut buf = [0; 0x10000];
        let (_amt, src) = socket.recv_from(&mut buf).expect("socket err");
        let object: Vec<Value> = serde_json::from_slice(&buf[0.._amt]).unwrap();
        peers.insert(src);
        for message in &object {
            println!("type {}", message);
            println!("type {}", message["message_type"]);
            match message["message_type"].as_str().unwrap() {
                "Please send peers." => send_peers(&socket, src, &peers),
                "Receive peers." => receive_peers(peers, message),
                "Please send content." => send_content(&socket, src, &peers, message),
                "Receive content." => receive_content(&socket, src, &peers, message),
                _ => (),
            };
            let mut result = vec![];
            walk_object("rot", message, &mut result);
            println!("{:?}", result);
        }
    }
    Ok(())
}

fn send_peers(socket: &UdpSocket, src: SocketAddr, peers: &HashSet<SocketAddr>) -> () {
    println!("sending peers {:?}", peers);
    let p: Vec<SocketAddr> = peers.into_iter().cloned().collect();

    let mut message = json!([
        {"message_type":
        "Receive peers.",
        "peers":  serde_json::to_value(p).unwrap()}]);
    let message_bytes: Vec<u8> = serde_json::to_vec(&message).unwrap();
    println!("sending peers {:?}", str::from_utf8(&message_bytes));
    socket.send_to(&message_bytes, src);
}

fn receive_peers(peers: &mut HashSet<SocketAddr>, message: &Value) -> () {
    for p in message["peers"].as_array().unwrap() {
        println!(" a peer {:?}", p);
        let sa: SocketAddr = p.as_str().unwrap().parse().unwrap();
        peers.insert(sa);
    }
}

fn send_content(
    socket: &UdpSocket,
    src: SocketAddr,
    peers: &HashSet<SocketAddr>,
    message_in: &Value,
) -> () {
    if message_in["content_sha256"].as_str().unwrap().find("/") != None
        || message_in["content_sha256"].as_str().unwrap().find("\\") != None
    {
        return;
    };
    let mut file = File::open(message_in["content_sha256"].as_str().unwrap()).unwrap();
    let mut to_read = message_in["content_length"].as_u64().unwrap() as usize;
    if to_read > 4096 {
        to_read = 4096
    }
    let mut content = vec![0; to_read];
    let content_length = file
        .read_at(&mut content, message_in["content_offset"].as_u64().unwrap())
        .unwrap();
    let content_b64: String = general_purpose::STANDARD_NO_PAD.encode(content);
    let mut message_out = json!([
        {"message_type": "Receive content.",
        "content_sha256":  message_in["content_sha256"],
        "content_offset":  message_in["content_offset"],
        "content_b64":  content_b64,
        }
    ]);
    let message_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
    println!("sending content {:?}", str::from_utf8(&message_bytes));
    socket.send_to(&message_bytes, src);
}

fn receive_content(
    socket: &UdpSocket,
    src: SocketAddr,
    peers: &HashSet<SocketAddr>,
    message_in: &Value,
) -> () {
    if message_in["content_sha256"].as_str().unwrap().find("/") != None
        || message_in["content_sha256"].as_str().unwrap().find("\\") != None
    {
        return;
    };
    fs::create_dir("./incoming");
    let path = "./incoming/".to_owned() + message_in["content_sha256"].as_str().unwrap();
    println!(
        "receiving {:?} at {:?} offset",
        path, message_in["content_offset"]
    );
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let content_bytes = general_purpose::STANDARD_NO_PAD
        .decode(message_in["content_b64"].as_str().unwrap())
        .unwrap();
    file.write_at(
        &content_bytes,
        message_in["content_offset"].as_u64().unwrap(),
    );
}
