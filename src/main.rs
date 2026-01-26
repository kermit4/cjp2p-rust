use base64::{engine::general_purpose, Engine as _};
use bitvec::prelude::*;
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
//use sha2::{Digest, Sha256};
use std::collections::HashMap;
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
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::vec;

macro_rules! BLOCK_SIZE {
    () => {
        0x1000 // 4k
    };
}

struct PeerInfo {
    last_seen: SystemTime,
}

fn main() -> Result<(), std::io::Error> {
    env_logger::init();
    let mut peer_map: HashMap<SocketAddr, PeerInfo> = HashMap::new();
    peer_map.insert(
        "148.71.89.128:24254".parse().unwrap(),
        PeerInfo {
            last_seen: UNIX_EPOCH,
        },
    );
    peer_map.insert(
        "159.69.54.127:24254".parse().unwrap(),
        PeerInfo {
            last_seen: UNIX_EPOCH,
        },
    );
    let socket = UdpSocket::bind("0.0.0.0:24254")?;
    fs::create_dir("./cjp2p").ok();
    std::env::set_current_dir("./cjp2p").unwrap();
    let mut args = env::args();
    args.next();
    let mut inbound_states: HashMap<String, InboundState> = HashMap::new();
    for v in args {
        info!("queing inbound file {:?}", v);
        new_inbound_state(&mut inbound_states, v.as_str());
    }
    socket.set_read_timeout(Some(Duration::new(1, 0)))?;
    let mut last_maintenance = UNIX_EPOCH;
    loop {
        let mut buf = [0; 0x10000];
        socket.set_read_timeout(Some(Duration::new(1, 0)))?;
        if last_maintenance + Duration::from_secs(1) < SystemTime::now() {
            last_maintenance = SystemTime::now();
            maintenance(&mut inbound_states, &mut peer_map, &socket);
        }
        let (message_len, src) = match socket.recv_from(&mut buf) {
            Ok(_r) => _r,
            Err(_e) => {
                warn!("no one is talking!");
                continue;
            }
        };
        let message_in_bytes = &buf[0..message_len];
        let messages: Vec<Value> = match serde_json::from_slice(message_in_bytes) {
            Ok(_r) => _r,
            _ => {
                error!(
                    "could not deserialize an incoming message {:?}",
                    message_in_bytes
                );
                continue;
            }
        };
        trace!(
            "incoming message {:?} from {src}",
            str::from_utf8(message_in_bytes)
        );
        if peer_map
            .insert(
                src,
                PeerInfo {
                    last_seen: SystemTime::now(),
                },
            )
            .is_none()
        {
            warn!("new peer spotted {src}");
        }
        let mut message_out: Vec<Message> = Vec::new();
        debug!("received {:?} messages from {src}", messages.len());
        for message_in in messages {
            let message_in_enum: Message = match serde_json::from_value(message_in.clone()) {
                Ok(_r) => _r,
                _ => {
                    error!("could not deserialize an incoming message {:?}", message_in);
                    continue;
                }
            };
            let mut reply = match message_in_enum {
                Message::PleaseSendPeers(t) => t.send_peers(&peer_map),
                Message::TheseArePeers(t) => t.receive_peers(&mut peer_map),
                Message::PleaseSendContent(t) => t.send_content(&mut inbound_states),
                Message::HereIsContent(t) => t.receive_content(&mut inbound_states),
            };
            message_out.append(&mut reply);
        }
        if message_out.len() == 0 {
            continue;
        }
        let message_out_bytes = serde_json::to_vec(&message_out).unwrap();
        debug!("sending {:?} messages to {src}", message_out.len());
        trace!(
            "sending message {:?} to {src}",
            str::from_utf8(&message_out_bytes)
        );
        match socket.send_to(&message_out_bytes, src) {
            Ok(s) => trace!("sent {s}"),
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
    fn send_peers(&self, peer_map: &HashMap<SocketAddr, PeerInfo>) -> Vec<Message> {
        let p: Vec<SocketAddr> = peer_map
            .into_iter()
            .filter(|(_, pi)| pi.last_seen > UNIX_EPOCH)
            .map(|(k, _)| k)
            .take(50)
            .cloned()
            .collect();
        trace!("sending {:?}/{:?} peers {:?}", p.len(), peer_map.len(), p);
        debug!("sending {:?}/{:?} peers", p.len(), peer_map.len());
        return vec![Message::TheseArePeers(TheseArePeers {
            //    how_to_add_new_fields_without_error:Some("".to_string()),
            peers: p,
        })];
    }
}

impl TheseArePeers {
    fn receive_peers(&self, peer_map: &mut HashMap<SocketAddr, PeerInfo>) -> Vec<Message> {
        debug!("received  {:?} peers", self.peers.len());
        for p in &self.peers {
            let sa: SocketAddr = *p;
            if peer_map
                .insert(
                    sa,
                    PeerInfo {
                        last_seen: UNIX_EPOCH,
                    },
                )
                .is_none()
            {
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

        info!(
            "going to send {:?} at {:?}",
            self.content_id, self.content_offset
        );

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
        let block_number = (self.content_offset / BLOCK_SIZE!()) as usize;
        if !inbound_states.contains_key(&self.content_id) {
            return vec![];
        }
        let i = inbound_states.get_mut(&self.content_id).unwrap();
        debug!("received  {:?} block {:?}", self.content_id, block_number);
        if self.content_eof > i.eof {
            i.eof = self.content_eof;
        }
        let blocks = (i.eof + BLOCK_SIZE!() - 1) / BLOCK_SIZE!();
        i.bitmap.resize(blocks as usize, false);
        if i.blocks_complete * BLOCK_SIZE!() >= i.eof {
            println!("{0} complete ", i.content_id);
            info!(
                "{0} complete {1} dups of {2} blocks {3}% loss",
                i.content_id,
                i.dups,
                i.blocks_complete,
                1.0 - ((i.blocks_complete + i.dups) as f64 / i.blocks_requested as f64)
            );
            let path = "./incoming/".to_owned() + &i.content_id;
            let new_path = "./".to_owned() + &i.content_id;
            fs::rename(path, new_path).unwrap();
            inbound_states.remove(&self.content_id);
            return vec![];
        };

        if i.bitmap[block_number] {
            i.dups += 1;
            debug!("dup {block_number}");
            return vec![];
        }
        let content_bytes = general_purpose::STANDARD_NO_PAD
            .decode(&self.content_b64)
            .unwrap();
        i.file
            .write_at(&content_bytes, self.content_offset)
            .unwrap();
        i.blocks_complete += 1;
        i.bitmap.set(block_number, true);
        let mut reply = request_content_block(i);
        debug!("request  {:?} offset {:?}", i.content_id, i.next_block);
        i.next_block += 1;
        if (i.blocks_complete % 100) == 0 {
            reply.append(&mut request_content_block(i));
            debug!(
                "request  {:?} offset {:?} EXTRA",
                i.content_id, i.next_block
            );
            i.next_block += 1;
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
        if inbound_state.next_block * BLOCK_SIZE!() >= inbound_state.eof {
            info!("almost done with {0}", inbound_state.content_id);
            info!("pending blocks: ");

            for i in inbound_state.bitmap.iter_zeros() {
                info!("{i}");
            }

            inbound_state.next_block = 0;
        }
        inbound_state.bitmap[inbound_state.next_block as usize]
    } {
        inbound_state.next_block += 1;
    }
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
    dups: u64,
    // last host
}

fn maintenance(
    inbound_states: &mut HashMap<String, InboundState>,
    peer_map: &mut HashMap<SocketAddr, PeerInfo>,
    socket: &UdpSocket,
) -> () {
    for (sa, pi) in peer_map.iter_mut() {
        // TODO maybe not ask everyone every second huh?
        let mut message_out: Vec<Message> = Vec::new();
        message_out.push(Message::PleaseSendPeers(PleaseSendPeers {})); // let people know im here
        let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
        trace!("sending message {:?}", str::from_utf8(&message_out_bytes));
        socket.send_to(&message_out_bytes, sa).ok();
        *pi = PeerInfo {
            last_seen: UNIX_EPOCH,
        };
    }

    for (_, i) in inbound_states.iter_mut() {
        for (sa, _) in peer_map.iter_mut() {
            let mut message_out: Vec<Message> = Vec::new();
            message_out.append(&mut request_content_block(i));
            let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
            trace!("sending message {:?}", str::from_utf8(&message_out_bytes));
            debug!("sending {:?} bump to {sa}", message_out.len());
            socket.send_to(&message_out_bytes, sa).ok();
        }
        i.next_block += 1;
    }
}

#[derive(Serialize, Deserialize)]
enum Message {
    PleaseSendPeers(PleaseSendPeers),
    TheseArePeers(TheseArePeers),
    PleaseSendContent(PleaseSendContent),
    HereIsContent(HereIsContent),
}
