use base64::{engine::general_purpose, Engine as _};

use bitvec::prelude::*;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
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
macro_rules! BLOCK_SIZE {
    () => {
        0x1000
    };
} // 4k
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
                info!("too quiet, asking for more peers");
                for p in &peers {
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
        if peers.insert(src) {
            warn!("new peer spotted {src}");
        }
        let mut message_out: Vec<Value> = Vec::new();
        for message_in in &messages {
            debug!("message {}", message_in);
            debug!("type {}", message_in[MESSAGE_TYPE]);
            let reply = match message_in[MESSAGE_TYPE].as_str().unwrap() {
                PLEASE_SEND_PEERS => send_peers(&peers),
                THESE_ARE_PEERS => receive_peers(&mut peers, message_in),
                PLEASE_SEND_CONTENT => send_content(message_in, &mut inbound_states),
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

#[derive(Serialize, Deserialize)]
struct TheseArePeers {
    message_type: String,
    peers: Vec<SocketAddr>,
 //   how_to_add_new_fields_without_error: Option<String>,
}

fn send_peers(peers: &HashSet<SocketAddr>) -> Value {
    debug!("sending peers {:?}", peers);
    let p: Vec<SocketAddr> = peers.into_iter().take(50).cloned().collect();
    return serde_json::to_value(TheseArePeers{
        message_type: THESE_ARE_PEERS.to_string(),
//    how_to_add_new_fields_without_error:Some("".to_string()),
    peers: p}).unwrap();
}

fn receive_peers(peers: &mut HashSet<SocketAddr>, message_in: &Value) -> Value {
    let m: TheseArePeers = serde_json::from_value(message_in.clone()).unwrap();
    println!("deserrialzed {0}", m.message_type);
    for p in m.peers {
        debug!(" a peer {:?}", p);
        let sa: SocketAddr = p;
        if peers.insert(sa) {
            warn!("new peer suggested {sa}");
        }
    }
    return Null;
}

#[derive(Serialize, Deserialize)]
struct PleaseSendContent {
    message_type: String,
    content_id: String,
    content_length: u64,
    content_offset: u64,
}

#[derive(Serialize, Deserialize)]
struct HereIsContent {
    message_type: String,
    content_id: String,
    content_offset: u64,
    content_b64: String,
    content_eof: u64,
}

fn send_content(message_in: &Value, inbound_states: &mut HashMap<String, InboundState>) -> Value {
    let m: PleaseSendContent = serde_json::from_value(message_in.clone()).unwrap();
    if m.content_id.find("/") != None || m.content_id.find("\\") != None {
        return Null;
    };
    let mut content_length = m.content_length;
    if content_length > (BLOCK_SIZE!()) {
        content_length = BLOCK_SIZE!()
    }

    let file: &File;
    let file_: File;
    if inbound_states.contains_key(&m.content_id)
        && m.content_offset + content_length < inbound_states[&m.content_id].eof
        && inbound_states[&m.content_id].bitmap[(m.content_offset / BLOCK_SIZE!())as usize ]
        && ((m.content_offset % BLOCK_SIZE!()) == 0)
    {
        file = &inbound_states[&m.content_id].file;
    } else {
        match File::open(&m.content_id) {
            Ok(_r) => {
                file_ = _r;
                file = &file_;
            }
            _ => return Null,
        }
    };

    debug!("going to send {:?}", m.content_id);

    let mut buf = vec![0; content_length as usize];
    content_length = file.read_at(&mut buf, m.content_offset as u64).unwrap() as u64;
    let (content, _) = buf.split_at(content_length as usize);
    let content_b64: String = general_purpose::STANDARD_NO_PAD.encode(content);
    return serde_json::to_value(HereIsContent{
        message_type: HERE_IS_CONTENT.to_string(),
        content_id:  m.content_id,
        content_offset:  m.content_offset,
        content_b64:  content_b64,
        content_eof: file.metadata().unwrap().len() , 
        }
    ).unwrap();
}

fn receive_content(
    message_in: &Value,
    inbound_states: &mut HashMap<String, InboundState>,
    socket: &UdpSocket,
    src: &SocketAddr,
) -> Value {
    let m: HereIsContent = serde_json::from_value(message_in.clone()).unwrap();
    if !inbound_states.contains_key(&m.content_id) {
        return Null;
    }
    let inbound_state = inbound_states.get_mut(&m.content_id).unwrap();
    let block = (m.content_offset / BLOCK_SIZE!()) as usize;
    if inbound_state.bitmap[block] {
        inbound_state.dups += 1;
        info!("dup {block}");
        return Null;
    }
    let content_bytes = general_purpose::STANDARD_NO_PAD
        .decode(m.content_b64)
        .unwrap();
    inbound_state
        .file
        .write_at(
            &content_bytes,
            m.content_offset,
        )
        .unwrap();
    inbound_state.blocks_complete += 1;
    let eof =m.content_eof;
    if eof > inbound_state.eof {
        inbound_state.eof = eof;
    }
    let blocks = (inbound_state.eof + BLOCK_SIZE!() - 1) / BLOCK_SIZE!();
    inbound_state.bitmap.resize(blocks as usize, false);
    inbound_state.bitmap.set(block, true);
    if m.content_offset + content_bytes.len() as u64 >= inbound_state.eof {
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
    if inbound_state.blocks_complete * BLOCK_SIZE!() >= inbound_state.eof {
        return Null;
    }
    while {
        inbound_state.next_block += 1;
        if inbound_state.next_block * BLOCK_SIZE!() >= inbound_state.eof {
            inbound_state.next_block = 0;
        }
        inbound_state.bitmap[inbound_state.next_block as usize]
    } {}
    debug!("requesting {0}", inbound_state.next_block);
    return serde_json::to_value(PleaseSendContent{
        message_type: PLEASE_SEND_CONTENT.to_string(),
        content_id:  inbound_state.content_id.to_owned(),
        content_offset:  inbound_state.next_block*BLOCK_SIZE!(),
        content_length: BLOCK_SIZE!(),
        }).unwrap();
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
    next_block: u64,
    bitmap: BitVec,
    content_id: String,
    eof: u64,
    blocks_complete: u64,
    last_bumped: SystemTime,
    dups: u64,
    // last host
}

fn bump_inbounds(
    inbound_states: &mut HashMap<String, InboundState>,
    peers: &HashSet<SocketAddr>,
    socket: &UdpSocket,
) -> () {
    let mut to_remove = "".to_owned();
    for mut inbound_state in inbound_states.values_mut() {
        if inbound_state.last_bumped.elapsed().unwrap().as_secs() < 1 {
            continue;
        }
        inbound_state.last_bumped = SystemTime::now();
        debug!("is loop");
        if inbound_state.blocks_complete * BLOCK_SIZE!() >= inbound_state.eof {
            to_remove = inbound_state.content_id.as_str().to_owned();
            continue;
        }
        for p in peers {
            let mut message_out: Vec<Value> = Vec::new();
            message_out.push(request_content_block(&mut inbound_state));
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
