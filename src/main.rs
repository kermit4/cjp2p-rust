// don't use too many Rustisms, it should be readable to any engineer not just Rusticans

use base64::{engine::general_purpose, Engine as _};
use bitvec::prelude::*;
use serde_json::{json, Map, Value, Value::Null};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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
    let mut peers: HashSet<SocketAddr> = HashSet::new();
    peers.insert("159.69.54.127:24254".parse().unwrap());
    peers.insert("148.71.89.128:24254".parse().unwrap());
    let socket = UdpSocket::bind("0.0.0.0:24254")?;
    std::env::set_current_dir("./pejovu");
    let mut peer_i = peers.iter();
    socket.send_to(b"[]", peer_i.next().unwrap()); // let people know im here
    socket.send_to(b"[]", peer_i.next().unwrap()); // let people know im here
    let mut args = env::args();
    args.next();
    let mut inbound_states: HashMap<String, InboundState> = HashMap::new();
    for v in args {
        new_inbound_state(&mut inbound_states, v.as_str());
    }
    loop {
        let mut buf = [0; 0x10000];
        let (_amt, src) = socket.recv_from(&mut buf).expect("socket err");
        let messages: Vec<Value> = serde_json::from_slice(&buf[0.._amt]).unwrap();
        println!("{:?} said something", src);
        peers.insert(src);
        let mut message_out: Vec<Value> = Vec::new();
        for message_in in &messages {
            println!("type {}", message_in);
            println!("type {}", message_in["message_type"]);
            let reply = match message_in["message_type"].as_str().unwrap() {
                "Please send peers." => send_peers(&peers),
                "These are peers." => receive_peers(&mut peers, message_in),
                "Please send content." => send_content(message_in),
                "Here is content." => receive_content(message_in, &mut inbound_states),
                _ => Null,
            };
            if reply != Null {
                message_out.push(json!(reply))
            };
            let mut result = vec![];
            walk_object("rot", message_in, &mut result);
            println!("{:?}", result);
        }
        if message_out.len() == 0 {
            continue;
        }
        let message_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
        println!("sending message {:?}", str::from_utf8(&message_bytes));
        socket.send_to(&message_bytes, src);
    }
    Ok(())
}

fn send_peers(peers: &HashSet<SocketAddr>) -> Value {
    println!("sending peers {:?}", peers);
    let p: Vec<SocketAddr> = peers.into_iter().cloned().collect();
    return json!(
        {"message_type": "These are peers.",
        "peers":  p});
}

fn receive_peers(peers: &mut HashSet<SocketAddr>, message: &Value) -> Value {
    for p in message["peers"].as_array().unwrap() {
        println!(" a peer {:?}", p);
        let sa: SocketAddr = p.as_str().unwrap().parse().unwrap();
        peers.insert(sa);
    }
    return json!(serde_json::Value::Null);
}

fn send_content(message_in: &Value) -> Value {
    if message_in["content_sha256"].as_str().unwrap().find("/") != None
        || message_in["content_sha256"].as_str().unwrap().find("\\") != None
    {
        return Null;
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
    return json!(
        {"message_type": "Here is content.",
        "content_sha256":  message_in["content_sha256"],
        "content_offset":  message_in["content_offset"],
        "content_b64":  content_b64,
        }
    );
}

fn receive_content(
    message_in: &Value,
    inbound_states: &mut HashMap<String, InboundState>,
) -> Value {
    let sha256 = message_in["content_sha256"].as_str().unwrap();
    if !inbound_states.contains_key(sha256) {
        return Null;
    }
    let mut inbound_state = inbound_states.get_mut(sha256).unwrap();
    if sha256.find("/") != None || sha256.find("\\") != None {
        return Null;
    };
    let content_bytes = general_purpose::STANDARD_NO_PAD
        .decode(message_in["content_b64"].as_str().unwrap())
        .unwrap();
    inbound_state.file.write_at(
        &content_bytes,
        message_in["content_offset"].as_u64().unwrap(),
    );
    //inbound_state.blocks_remaining -= 1;
    let offset = message_in["content_offset"].as_i64().unwrap() as usize;
    if inbound_state.length < offset + content_bytes.len() {
        inbound_state.length = offset + content_bytes.len();
    }
    inbound_state
        .bitmap
        .resize((inbound_state.length + 4095) / 4096, false);
    inbound_state.bitmap.set((offset / 4096) as usize, true);
    return request_content_block(inbound_state);
}
//
fn request_content_block(inbound_state: &mut InboundState) -> Value {
    //                println!("{}",inbound_state.bitmap.iter().position(|x| x == false ).unwrap());
    //       while {
    inbound_state.next_block += 1;
    //                inbound_state.next_block %= inbound_state.len/4096;
    //               inbound_state.bitmap.get(inbound_state.next_block as usize).unwrap()
    //         } {}
    return json!([
        {"message_type": "Pleae send content.",
        "content_sha256":  inbound_state.sha256,
        "content_offset":  inbound_state.next_block*4096,
        "content_length": 4096,
        }
    ]);
}

fn new_inbound_state(inbound_states: &mut HashMap<String, InboundState>, sha256: &str) -> () {
    fs::create_dir("./incoming");
    let path = "./incoming/".to_owned() + &&sha256;
    inbound_states.insert(
        sha256.to_string(),
        InboundState {
            file: OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open(path)
                .unwrap(),
            next_block: 0,
            bitmap: BitVec::new(),
            sha256: sha256.to_string(),
            length: 1,
        },
    );
    //    let mut peer_i = peers.iter();
    //  socket.send_to ( json!([ request_content_block(&inbound_state)]), peer_i.next().unwrap()); // should be part of a timer
}

struct InboundState {
    file: File,
    next_block: u64,
    bitmap: BitVec,
    sha256: String,
    length: usize,
    // last host
}
