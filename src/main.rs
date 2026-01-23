use base64::{engine::general_purpose, Engine as _};
use bitvec::prelude::*;
use log::{debug, info, warn};
use serde_json::{json, Value, Value::Null};
//use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::collections::HashSet;
//use std::convert::TryInto;
use std::env;
//use std::fmt;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
//use std::io::copy;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::fs::FileExt;
//use std::path::Path;
use std::str;
use std::time::{Duration, SystemTime};
use std::vec;

const MESSAGE_TYPE: &str = "message_type";
const PLEASE_SEND_CONTENT: &str = "Please send content.";
const THESE_ARE_PEERS: &str = "These are peers.";
const PLEASE_SEND_PEERS: &str = "Please send peers.";
const HERE_IS_CONTENT: &str = "Here is content.";
fn walk_object(name: &str, x: &Value, result: &mut Vec<String>) {
    let Value::Object(x) = x else { return };
    debug!("name {:?}", name);
    debug!("value {:?}", x);
    result.push(name.to_string());
    for (name, field) in x {
        debug!("name {:?}", name);
        debug!("field {:?}", field);
        walk_object(&name, field, result);
    }
}

fn main() -> Result<(), std::io::Error> {
    env_logger::init();
    let mut peers: HashSet<SocketAddr> = HashSet::new();
    peers.insert("148.71.89.128:24254".parse().unwrap());
    peers.insert("159.69.54.127:24254".parse().unwrap());
    let socket = UdpSocket::bind("0.0.0.0:24254")?;
    fs::create_dir("./pejovu").ok();
    std::env::set_current_dir("./pejovu").unwrap();
    let mut args = env::args();
    args.next();
    let mut inbound_states: HashMap<String, InboundState> = HashMap::new();
    for v in args {
        info!("queing new {:?}", v);
        new_inbound_state(&mut inbound_states, v.as_str());
    }
    loop {
        let mut buf = [0; 0x10000];
        socket.set_read_timeout(Some(Duration::new(1, 0)))?;
        debug!("main loop");

        bump_inbounds(&mut inbound_states, &peers, &socket);
        let (_amt, src) = match socket.recv_from(&mut buf) {
            Ok(_r) => _r,
            Err(_e) => {
                warn!("too quiet, asking for more peers");
                for p in peers.iter() {
                    debug!("p loop");
                    let mut message_out: Vec<Value> = Vec::new();
                    message_out.push(json!({MESSAGE_TYPE:PLEASE_SEND_PEERS})); // let people know im here
                    let message_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
                    socket.send_to(&message_bytes, p).ok();
                }
                continue;
            }
        };
        let messages: Vec<Value> = match serde_json::from_slice(&buf[0.._amt]) {
            Ok(_r) => _r,
            _ => {
                warn!("could not deserialize an incoming message");
                continue;
            }
        };
        debug!("{:?} said something", src);
        peers.insert(src);
        let mut message_out: Vec<Value> = Vec::new();
        for message_in in &messages {
            debug!("message {}", message_in);
            debug!("type {}", message_in[MESSAGE_TYPE]);
            let reply = match message_in[MESSAGE_TYPE].as_str().unwrap() {
                PLEASE_SEND_PEERS => send_peers(&peers),
                THESE_ARE_PEERS => receive_peers(&mut peers, message_in),
                PLEASE_SEND_CONTENT => send_content(message_in),
                HERE_IS_CONTENT => receive_content(message_in, &mut inbound_states, &socket, &src),
                _ => Null,
            };
            if reply != Null {
                message_out.push(reply)
            };
            let mut result = vec![];
            walk_object("rot", message_in, &mut result);
            debug!("{:?}", result);
        }
        if message_out.len() == 0 {
            continue;
        }
        let message_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
        debug!("sending message {:?}", str::from_utf8(&message_bytes));
        socket.send_to(&message_bytes, src).ok();
    }
}

fn send_peers(peers: &HashSet<SocketAddr>) -> Value {
    debug!("sending peers {:?}", peers);
    let p: Vec<SocketAddr> = peers.into_iter().cloned().collect();
    return json!(
        {MESSAGE_TYPE: THESE_ARE_PEERS,
        "peers":  p});
}

fn receive_peers(peers: &mut HashSet<SocketAddr>, message: &Value) -> Value {
    for p in message["peers"].as_array().unwrap() {
        debug!(" a peer {:?}", p);
        let sa: SocketAddr = p.as_str().unwrap().parse().unwrap();
        peers.insert(sa);
    }
    return Null;
}

fn send_content(message_in: &Value) -> Value {
    let content_id = message_in["content_id"].as_str().unwrap();
    if content_id.find("/") != None || content_id.find("\\") != None {
        return Null;
    };
    debug!("going to send {:?}", content_id);
    let file = match File::open(content_id) {
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
        {MESSAGE_TYPE: HERE_IS_CONTENT,
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
    socket: &UdpSocket,
    src: &SocketAddr,
) -> Value {
    let content_id = message_in["content_id"].as_str().unwrap();
    if !inbound_states.contains_key(content_id) {
        return Null;
    }
    let inbound_state = inbound_states.get_mut(content_id).unwrap();
    if content_id.find("/") != None || content_id.find("\\") != None {
        return Null;
    };
    let offset = message_in["content_offset"].as_i64().unwrap() as usize;
    let block = (offset / 4096) as usize;
    if inbound_state.bitmap[block] {
        inbound_state.dups += 1;
        return Null;
    }
    let content_bytes = general_purpose::STANDARD_NO_PAD
        .decode(message_in["content_b64"].as_str().unwrap())
        .unwrap();
    inbound_state
        .file
        .write_at(
            &content_bytes,
            message_in["content_offset"].as_u64().unwrap(),
        )
        .unwrap();
    inbound_state.blocks_complete += 1;
    inbound_state.eof = message_in["content_eof"].as_i64().unwrap() as usize;
    let blocks = (inbound_state.eof + 4095) / 4096;
    inbound_state.bitmap.resize(blocks, false);
    inbound_state.bitmap.set(block, true);
    if offset + content_bytes.len() >= inbound_state.eof {
        inbound_state.next_block = 0;
    }
    if (inbound_state.next_block % 100) == 0 {
        // increase the amount of data in flight
        let mut message_out: Vec<Value> = Vec::new();
        message_out.push(request_content_block(inbound_state));
        let message_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
        socket.send_to(&message_bytes, src).ok();
    }
    return request_content_block(inbound_state);
}
//
fn request_content_block(inbound_state: &mut InboundState) -> Value {
    if inbound_state.blocks_complete * 4096 >= inbound_state.eof {
        return Null;
    }
    while {
        inbound_state.next_block += 1;
        if inbound_state.next_block * 4096 >= inbound_state.eof {
            inbound_state.next_block = 0;
        }
        inbound_state.bitmap[inbound_state.next_block]
    } {}
    return json!(
        {MESSAGE_TYPE: PLEASE_SEND_CONTENT,
        "content_id":  inbound_state.content_id,
        "content_offset":  inbound_state.next_block*4096,
        "content_length": 4096,
        }
    );
}

fn new_inbound_state(inbound_states: &mut HashMap<String, InboundState>, content_id: &str) -> () {
    fs::create_dir("./incoming").ok();
    let path = "./incoming/".to_owned() + &content_id;
    let mut inbound_state = InboundState {
        file: OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap(),
        next_block: 0,
        bitmap: BitVec::new(),
        content_id: content_id.to_string(),
        eof: 1,
        blocks_complete: 0,
        last_bumped: SystemTime::now() - Duration::from_secs(5),
        dups: 0,
    };
    inbound_state.bitmap.resize(1, false);
    inbound_states.insert(content_id.to_string(), inbound_state);
}

struct InboundState {
    file: File,
    next_block: usize,
    bitmap: BitVec,
    content_id: String,
    eof: usize,
    blocks_complete: usize,
    last_bumped: SystemTime,
    dups: usize,
    // last host
}

fn bump_inbounds(
    inbound_states: &mut HashMap<String, InboundState>,
    peers: &HashSet<SocketAddr>,
    socket: &UdpSocket,
) -> () {
    let mut to_remove = "".to_owned();
    for inbound_state in inbound_states.values_mut() {
        if inbound_state.last_bumped.elapsed().unwrap().as_secs() < 1 {
            continue;
        }
        inbound_state.last_bumped = SystemTime::now();
        debug!("is loop");
        if inbound_state.blocks_complete * 4096 >= inbound_state.eof {
            to_remove = inbound_state.content_id.as_str().to_owned();
            continue;
        }
        for p in peers.iter() {
            let mut message_out: Vec<Value> = Vec::new();
            message_out.push(request_content_block(inbound_state));
            let message_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
            socket.send_to(&message_bytes, p).ok();
        }
    }
    if to_remove != "" {
        println!(
            "{to_remove} complete {0} dups of {1} blocks",
            inbound_states[&to_remove].dups, inbound_states[&to_remove].blocks_complete
        );
        let path = "./incoming/".to_owned() + &to_remove;
        let new_path = "./".to_owned() + &to_remove;
        fs::rename(path, new_path).unwrap();
        inbound_states.remove(&to_remove);
    };
}
