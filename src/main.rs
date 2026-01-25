use base64::{engine::general_purpose, Engine as _};
use bitvec::prelude::*;
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
    fs::create_dir("./cjp2p").ok();
    std::env::set_current_dir("./cjp2p").unwrap();
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
        let (message_len, src) = match socket.recv_from(&mut buf) {
            Ok(_r) => _r,
            Err(_e) => {
                info!("too quiet, asking for more peers");
                for p in &peers {
                    debug!("p loop");
                    let mut message_out: Vec<Message> = Vec::new();
                    message_out.push(Message::PleaseSendPeers(PleaseSendPeers {})); // let people know im here
                    let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
                    trace!("sending message {:?}", str::from_utf8(&message_out_bytes));
                    socket.send_to(&message_out_bytes, p).ok();
                }
                continue;
            }
        };
        let message_in_bytes = &buf[0..message_len];
        let messages: Vec<Value> = match serde_json::from_slice(message_in_bytes) {
            Ok(_r) => _r,
            _ => {
                error!(
                    "could not deserialize an incoming message {:?}",
                    str::from_utf8(message_in_bytes).unwrap()
                );
                continue;
            }
        };
        trace!("incoming message {:?}", str::from_utf8(message_in_bytes));
        let mut result = vec![];
        walk_object(
            "rot",
            &serde_json::to_value(&messages).unwrap(),
            &mut result,
        );
        debug!("{:?}", result);
        trace!("{:?} said something", src);
        if peers.insert(src) {
            warn!("new peer spotted {src}");
        }
        let mut message_out: Vec<Message> = Vec::new();
        for message_in in messages {
            let message_in_enum: Message = match serde_json::from_value(message_in.clone()) {
                Ok(_r) => _r,
                _ => {
                    error!("could not deserialize an incoming message {:?}", message_in);
                    continue;
                }
            };
            let mut reply = match message_in_enum {
                Message::PleaseSendPeers(t) => t.send_peers(&peers),
                Message::TheseArePeers(t) => t.receive_peers(&mut peers),
                Message::PleaseSendContent(t) => t.send_content(&mut inbound_states),
                Message::HereIsContent(t) => t.receive_content(&mut inbound_states),
            };
            message_out.append(&mut reply)
        }
        if message_out.len() == 0 {
            continue;
        }
        let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
        trace!("sending message {:?}", str::from_utf8(&message_out_bytes));
        match socket.send_to(&message_out_bytes, src) {
            Ok(s) => debug!("sent {s}"),
            Err(e) => warn!("failed to send {0} {e}", message_out_bytes.len()),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TheseArePeers {
    peers: Vec<SocketAddr>,
    //   how_to_add_new_fields_without_error: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct PleaseSendPeers {}
impl PleaseSendPeers {
    fn send_peers(&self, peers: &HashSet<SocketAddr>) -> Vec<Message> {
        debug!("sending peers {:?}", peers);
        let p: Vec<SocketAddr> = peers.into_iter().take(50).cloned().collect();
        return vec![Message::TheseArePeers(TheseArePeers {
            //    how_to_add_new_fields_without_error:Some("".to_string()),
            peers: p,
        })];
    }
}

impl TheseArePeers {
    fn receive_peers(&self, peers: &mut HashSet<SocketAddr>) -> Vec<Message> {
        for p in &self.peers {
            debug!(" a peer {:?}", p);
            let sa: SocketAddr = *p;
            if peers.insert(sa) {
                warn!("new peer suggested {sa}");
            }
        }
        return vec![];
    }
}

#[derive(Serialize, Deserialize)]
struct PleaseSendContent {
    content_id: String,
    content_length: u64,
    content_offset: u64,
}

#[derive(Serialize, Deserialize)]
struct HereIsContent {
    content_id: String,
    content_offset: u64,
    content_b64: String,
    content_eof: u64,
}

impl PleaseSendContent {
    fn send_content(&self, inbound_states: &mut HashMap<String, InboundState>) -> Vec<Message> {
        if self.content_id.find("/") != None || self.content_id.find("\\") != None {
            return vec![];
        };
        let mut content_length = self.content_length;
        if content_length > (BLOCK_SIZE!()) {
            content_length = BLOCK_SIZE!()
        }

        let file: &File;
        let file_: File;
        if inbound_states.contains_key(&self.content_id)
            && self.content_offset + content_length < inbound_states[&self.content_id].eof
            && inbound_states[&self.content_id].bitmap
                [(self.content_offset / BLOCK_SIZE!()) as usize]
            && ((self.content_offset % BLOCK_SIZE!()) == 0)
        {
            file = &inbound_states[&self.content_id].file;
        } else {
            match File::open(&self.content_id) {
                Ok(_r) => {
                    file_ = _r;
                    file = &file_;
                }
                _ => return vec![],
            }
        };

        debug!("going to send {:?}", self.content_id);

        let mut buf = vec![0; content_length as usize];
        content_length = file.read_at(&mut buf, self.content_offset as u64).unwrap() as u64;
        let (content, _) = buf.split_at(content_length as usize);
        return vec![Message::HereIsContent(HereIsContent {
            content_id: self.content_id.clone(),
            content_offset: self.content_offset,
            content_b64: general_purpose::STANDARD_NO_PAD.encode(content),
            content_eof: file.metadata().unwrap().len(),
        })];
    }
}

impl HereIsContent {
    fn receive_content(&self, inbound_states: &mut HashMap<String, InboundState>) -> Vec<Message> {
        if !inbound_states.contains_key(&self.content_id) {
            return vec![];
        }
        let inbound_state = inbound_states.get_mut(&self.content_id).unwrap();
        let block = (self.content_offset / BLOCK_SIZE!()) as usize;
        if self.content_eof > inbound_state.eof {
            inbound_state.eof = self.content_eof;
        }
        let blocks = (inbound_state.eof + BLOCK_SIZE!() - 1) / BLOCK_SIZE!();
        inbound_state.bitmap.resize(blocks as usize, false);
        if inbound_state.bitmap[block] {
            inbound_state.dups += 1;
            info!("dup {block}");
            return vec![];
        }
        let content_bytes = general_purpose::STANDARD_NO_PAD
            .decode(&self.content_b64)
            .unwrap();
        inbound_state
            .file
            .write_at(&content_bytes, self.content_offset)
            .unwrap();
        inbound_state.blocks_complete += 1;
        inbound_state.bitmap.set(block, true);
        if self.content_offset + content_bytes.len() as u64 >= inbound_state.eof {
            inbound_state.next_block = 0;
        }
        let mut reply = request_content_block(inbound_state);
        if (inbound_state.blocks_complete % 300) == 0 {
            debug!("increasing window for {0} ",inbound_state.content_id);
            reply.append(&mut request_content_block(inbound_state));
        }
        return reply;
    }
}
//
fn request_content_block(inbound_state: &mut InboundState) -> Vec<Message> {
    if inbound_state.blocks_complete * BLOCK_SIZE!() >= inbound_state.eof {
        return vec![];
    }
    while {
        inbound_state.next_block += 1;
        if inbound_state.next_block * BLOCK_SIZE!() >= inbound_state.eof {
            info!("almost done with {0}",inbound_state.content_id);
                                    info!("pending blocks: ");

                        for i in inbound_state.bitmap.iter_zeros() {
                                   info!("{i}");
                                        }

            inbound_state.next_block = 0;
        }
        inbound_state.bitmap[inbound_state.next_block as usize]
    } {}
    debug!("requesting {0}", inbound_state.next_block);
    inbound_state.blocks_requested += 1;
    return vec![Message::PleaseSendContent(PleaseSendContent {
        content_id: inbound_state.content_id.to_owned(),
        content_offset: inbound_state.next_block * BLOCK_SIZE!(),
        content_length: BLOCK_SIZE!(),
    })];
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
        blocks_requested: 0,
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
    blocks_requested: u64,
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
            let mut message_out: Vec<Message> = Vec::new();
            message_out.append(&mut request_content_block(&mut inbound_state));
            let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
            trace!("sending message {:?}", str::from_utf8(&message_out_bytes));
            socket.send_to(&message_out_bytes, p).ok();
        }
    }
    if to_remove != "" {
        let i = &inbound_states[&to_remove];
        println!("{to_remove} complete ");
        info!(
            "{to_remove} complete {0} dups of {1} blocks {2}% loss",
            i.dups,
            i.blocks_complete,
            1.0 - ((i.blocks_complete + i.dups) as f64 / i.blocks_requested as f64)
        );
        let path = "./incoming/".to_owned() + &to_remove;
        let new_path = "./".to_owned() + &to_remove;
        fs::rename(path, new_path).unwrap();
        inbound_states.remove(&to_remove);
    };
}

#[derive(Serialize, Deserialize)]
enum Message {
    PleaseSendPeers(PleaseSendPeers),
    TheseArePeers(TheseArePeers),
    PleaseSendContent(PleaseSendContent),
    HereIsContent(HereIsContent),
}
