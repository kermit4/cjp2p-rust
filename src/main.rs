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

const PLEASE_SEND_CONTENT: &str = "Please send content.";
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
    peers.insert("148.71.89.128:24254".parse().unwrap());
    peers.insert("159.69.54.127:24254".parse().unwrap());
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    std::env::set_current_dir("./pejovu");
    let mut args = env::args();
    args.next();
    let mut inbound_states: HashMap<String, InboundState> = HashMap::new();
    for v in args {
        println!("queing new {:?}", v);
        new_inbound_state(&mut inbound_states, v.as_str());
    }
    loop {
        let mut buf = [0; 0x10000];
        socket.set_read_timeout(Some(Duration::new(1, 0)))?;
        println!("main loop");
        let (_amt, src) = match socket.recv_from(&mut buf) {
            Ok(_r) => _r,
            Err(_e) => {
                println!("inactivity, bumping transfer and asking for more peers");
                for p in peers.iter() {
                    println!("p loop");
                    let mut message_out: Vec<Value> = Vec::new();
                    message_out.push(json!({"message_type":"Please send peers."})); // let people know im here
                    let message_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
                    println!(
                        "sending message {:?} to {:?}",
                        str::from_utf8(&message_bytes),
                        p
                    );
                    socket.send_to(&message_bytes, p);
                }
                let mut to_remove = "".to_owned();
                for i in inbound_states.values_mut() {
                    println!("is loop");
                    if (i.blocks_complete * 4096 > i.eof) {
                        to_remove = i.sha256.as_str().to_owned();
                        continue;
                    }
                    for p in peers.iter() {
                        println!("p loop");
                        let mut message_out: Vec<Value> = Vec::new();
                        message_out.push(json!(request_content_block(i)));
                        let message_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
                        println!(
                            "sending message {:?} to {:?}",
                            str::from_utf8(&message_bytes),
                            p
                        );
                        socket.send_to(&message_bytes, p);
                    }
                }
                println!("maybe removing {:?}", to_remove);
                if to_remove != "" {
                    let path = "./incoming/".to_owned() + &to_remove;
                    let new_path = "./".to_owned() + &to_remove;
                    fs::rename(path, new_path);
                    inbound_states.remove(&to_remove);
                };
                continue;
            }
        };
        let messages: Vec<Value> = serde_json::from_slice(&buf[0.._amt]).unwrap();
        println!("{:?} said something", src);
        peers.insert(src);
        let mut message_out: Vec<Value> = Vec::new();
        for message_in in &messages {
            println!("message {}", message_in);
            println!("type {}", message_in["message_type"]);
            let reply = match message_in["message_type"].as_str().unwrap() {
                "Please send peers." => send_peers(&peers),
                "These are peers." => receive_peers(&mut peers, message_in),
                PLEASE_SEND_CONTENT => send_content(message_in),
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
    let sha256 = message_in["content_id"].as_str().unwrap();
    if sha256.find("/") != None || sha256.find("\\") != None {
        return Null;
    };
    println!("going to send {:?}", sha256);
    let mut file = match File::open(sha256) {
        Ok(_r) => _r,
        _ => return Null,
    };

    let mut to_read = message_in["content_length"].as_u64().unwrap() as usize;
    if to_read > 4096 {
        to_read = 4096
    }
    let mut buf = vec![0; to_read];
    let content_length = file
        .read_at(&mut buf, message_in["content_offset"].as_u64().unwrap())
        .unwrap();
    let (content, _) = buf.split_at(content_length);
    let content_b64: String = general_purpose::STANDARD_NO_PAD.encode(content);
    return json!(
        {"message_type": "Here is content.",
        "content_id":  message_in["content_id"],
        "content_offset":  message_in["content_offset"],
        "content_b64":  content_b64,
        "content_eof":file.metadata().unwrap().len(),
        }
    );
}

fn receive_content(
    message_in: &Value,
    inbound_states: &mut HashMap<String, InboundState>,
) -> Value {
    let sha256 = message_in["content_id"].as_str().unwrap();
    if !inbound_states.contains_key(sha256) {
        return Null;
    }
    let mut inbound_state = inbound_states.get_mut(sha256).unwrap();
    if sha256.find("/") != None || sha256.find("\\") != None {
        return Null;
    };
    let offset = message_in["content_offset"].as_i64().unwrap() as usize;
    let block = ((offset / 4096) as usize);
    if inbound_state.bitmap[block] {
        return Null;
    }
    let content_bytes = general_purpose::STANDARD_NO_PAD
        .decode(message_in["content_b64"].as_str().unwrap())
        .unwrap();
    inbound_state.file.write_at(
        &content_bytes,
        message_in["content_offset"].as_u64().unwrap(),
    );
    inbound_state.blocks_complete += 1;
    inbound_state.eof = message_in["content_eof"].as_i64().unwrap() as usize;
    let blocks = (inbound_state.eof + 4095) / 4096;
    inbound_state.bitmap.resize(blocks, false);
    inbound_state.bitmap.set(block, true);
    if offset + content_bytes.len() >= inbound_state.eof {
        inbound_state.next_block = 0;
    }
    return request_content_block(inbound_state);
}
//
fn request_content_block(inbound_state: &mut InboundState) -> Value {
    if (inbound_state.blocks_complete * 4096 > inbound_state.eof) {
        return Null;
    }
    while {
        inbound_state.next_block += 1;
        if inbound_state.next_block * 4096 > inbound_state.eof {
            inbound_state.next_block = 0; }
        inbound_state.bitmap[inbound_state.next_block] } {
        }
    return json!(
        {"message_type": PLEASE_SEND_CONTENT,
        "content_id":  inbound_state.sha256,
        "content_offset":  inbound_state.next_block*4096,
        "content_length": 4096,
        }
    );
}

fn new_inbound_state(inbound_states: &mut HashMap<String, InboundState>, sha256: &str) -> () {
    fs::create_dir("./incoming");
    let path = "./incoming/".to_owned() + &sha256;
    let mut inbound_state = InboundState {
        file: OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap(),
        next_block: 0,
        bitmap: BitVec::new(),
        sha256: sha256.to_string(),
        eof: 1,
        blocks_complete: 0,
    };
    inbound_state.bitmap.resize(1, false);
    inbound_states.insert(sha256.to_string(), inbound_state);
}

struct InboundState {
    file: File,
    next_block: usize,
    bitmap: BitVec,
    sha256: String,
    eof: usize,
    blocks_complete: usize,
    // last host
}
