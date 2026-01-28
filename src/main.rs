use base64::{engine::general_purpose, Engine as _};
use bitvec::prelude::*;
use chrono::{Timelike, Utc};
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp;
use std::io::Write;
//use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
//use std::convert::TryInto;
use std::env;
//use std::fmt;
use std::f64;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
//use std::io::copy;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::fs::FileExt;
//use std::path::Path;
use rand::Rng;
use std::str;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::vec;

macro_rules! BLOCK_SIZE {
    () => {
        0x1000 // 4k
    };
}

#[derive(Clone, Serialize, Deserialize)]
struct PeerInfo {
    when_last_seen: SystemTime,
    delay: Duration,
}
struct PeerState {
    peer_map: HashMap<SocketAddr, PeerInfo>,
    peer_vec: Vec<(SocketAddr, PeerInfo)>,
    socket: UdpSocket,
}
impl PeerState {
    fn sort(&mut self) -> () {
        let now = SystemTime::now();
        self.peer_vec = self.peer_map.clone().into_iter().collect();
        self.peer_vec.sort_unstable_by(|a, b| {
            (now.duration_since(a.1.when_last_seen)
                .unwrap()
                .as_secs_f64()
                * a.1.delay.as_secs_f64())
            .total_cmp(
                &(now
                    .duration_since(b.1.when_last_seen)
                    .unwrap()
                    .as_secs_f64()
                    * b.1.delay.as_secs_f64()),
            )
        });
    }

    fn load_peers(&mut self) -> () {
        let file = OpenOptions::new().read(true).open("peers.json");
        if file.as_ref().is_ok() && file.as_ref().unwrap().metadata().unwrap().len() > 0 {
            let json: Vec<(SocketAddr, PeerInfo)> =
                serde_json::from_reader(&file.unwrap()).unwrap();
            let before = self.peer_map.len();
            self.peer_map.extend(json);
            info!("loaded {0} peers", self.peer_map.len() - before);
        }
    }
    fn save_peers(&self) -> () {
        debug!("saving peers");
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("peers.json")
            .unwrap()
            .write_all(
                &serde_json::to_vec_pretty(&self.peer_vec[..cmp::min(self.peer_vec.len(), 99)])
                    .unwrap(),
            )
            .ok();
    }

    fn best_peers(&self, how_many: i32, quality: i32) -> HashSet<SocketAddr> {
        let mut rng = rand::thread_rng();
        let result: &mut HashSet<SocketAddr> = &mut HashSet::new();
        for _ in 0..how_many {
            let i: usize = ((rng.gen_range(0.0..1.0) as f64).powi(quality)
                * (self.peer_vec.len() as f64)) as usize;
            if i >= self.peer_vec.len() {
                continue;
            }
            let p = &self.peer_vec[i];
            result.insert(p.0);
            debug!(
                "best peer(q:{quality}) {0} {1} {2} {3}",
                i,
                p.0,
                p.1.when_last_seen.elapsed().unwrap().as_secs_f64(),
                p.1.delay.as_secs_f64()
            );
        }
        result.clone()
    }
}
fn main() -> Result<(), std::io::Error> {
    env_logger::init();
    let mut ps: PeerState = PeerState {
        peer_map: HashMap::new(),
        peer_vec: Vec::new(),
        socket: UdpSocket::bind("0.0.0.0:24254")?,
    };
    ps.peer_map.insert(
        "148.71.89.128:24254".parse().unwrap(),
        PeerInfo {
            when_last_seen: UNIX_EPOCH,
            delay: Duration::new(1, 0),
        },
    );
    ps.peer_map.insert(
        "159.69.54.127:24254".parse().unwrap(),
        PeerInfo {
            when_last_seen: UNIX_EPOCH,
            delay: Duration::new(1, 0),
        },
    );
    fs::create_dir("./cjp2p").ok();
    std::env::set_current_dir("./cjp2p").unwrap();
    ps.load_peers();
    let mut args = env::args();
    args.next();
    let mut inbound_states: HashMap<String, InboundState> = HashMap::new();
    for v in args {
        info!("queing inbound file {:?}", v);
        InboundState::new_inbound_state(&mut inbound_states, v.as_str());
    }
    ps.socket.set_read_timeout(Some(Duration::new(1, 0)))?;
    let mut last_maintenance = UNIX_EPOCH;
    loop {
        if last_maintenance.elapsed().unwrap() > Duration::from_secs(3) {
            last_maintenance = SystemTime::now();
            maintenance(&mut inbound_states, &mut ps);
        }
        let mut buf = [0; 0x10000];
        let (message_len, src) = match ps.socket.recv_from(&mut buf) {
            Ok(_r) => _r,
            Err(_e) => {
                debug!("no messages for a second");
                continue;
            }
        };
        let message_in_bytes = &buf[0..message_len];
        let messages: Vec<Value> = match serde_json::from_slice(message_in_bytes) {
            Ok(_r) => _r,
            _ => {
                error!(
                    "could not deserialize an incoming message {:?}",
                    String::from_utf8_lossy(message_in_bytes)
                );
                continue;
            }
        };
        trace!(
            "incoming message {:?} from {src}",
            String::from_utf8_lossy(message_in_bytes)
        );
        match ps.peer_map.get_mut(&src) {
            Some(peer) => peer.when_last_seen = SystemTime::now(),
            _ => {
                ps.peer_map.insert(
                    src,
                    PeerInfo {
                        when_last_seen: SystemTime::now(),
                        delay: Duration::new(1, 0),
                    },
                );
                warn!("new peer spotted {src}");
            }
        };
        let mut message_out: Vec<serde_json::Value> = Vec::new();
        debug!("received {:?} messages from {src}", messages.len());
        for message_in in messages {
            if (message_in["PleaseReturnThisMessage"]) != Value::Null {
                // this isn't checked below
                // because we don't know it
                // structure so it may error
                message_out.push(
                    serde_json::json!({"ReturnedMessage":message_in["PleaseReturnThisMessage"]}),
                );
            } else {
                let message_in_enum: Message = match serde_json::from_value(message_in.clone()) {
                    Ok(_r) => _r,
                    _ => {
                        error!("could not deserialize an incoming message {:?}", message_in);
                        continue;
                    }
                };
                let reply = match message_in_enum {
                    Message::PleaseSendPeers(t) => t.send_peers(&ps),
                    Message::Peers(t) => t.receive_peers(&mut ps),
                    Message::PleaseSendContent(t) => t.send_content(&mut inbound_states),
                    Message::Content(t) => t.receive_content(&mut inbound_states, src, &mut ps),
                    Message::ReturnedMessage(t) => t.update_time(&mut ps, src),
                    _ => vec![],
                };
                for m in reply {
                    message_out.push(serde_json::to_value(m).unwrap());
                }
            }
        }
        if message_out.len() == 0 {
            continue;
        }
        let message_out_bytes = serde_json::to_vec(&message_out).unwrap();
        trace!(
            "sending message {:?} to {src}",
            String::from_utf8_lossy(&message_out_bytes)
        );
        match ps.socket.send_to(&message_out_bytes, src) {
            Ok(s) => trace!("sent {s}"),
            Err(e) => warn!("failed to send {0} {e}", message_out_bytes.len()),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Peers {
    peers: HashSet<SocketAddr>,
    //   how_to_add_new_fields_without_error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct PleaseSendPeers {}
impl PleaseSendPeers {
    fn send_peers(&self, ps: &PeerState) -> Vec<Message> {
        let p = ps.best_peers(50, 6);
        trace!(
            "sending {:?}/{:?} peers {:?}",
            p.len(),
            ps.peer_map.len(),
            p
        );
        debug!("sending {:?}/{:?} peers", p.len(), ps.peer_map.len());
        return vec![Message::Peers(Peers {
            //    how_to_add_new_fields_without_error:Some("".to_string()),
            peers: p,
        })];
    }
}

impl Peers {
    fn receive_peers(&self, ps: &mut PeerState) -> Vec<Message> {
        debug!("received  {:?} peers", self.peers.len());
        for p in &self.peers {
            let sa: SocketAddr = *p;
            if !ps.peer_map.contains_key(&sa) {
                warn!("new peer suggested {sa}");
                ps.peer_map.insert(
                    sa,
                    PeerInfo {
                        when_last_seen: UNIX_EPOCH,
                        delay: Duration::new(1, 0),
                    },
                );
            }
        }
        return vec![];
    }
}

#[derive(Serialize, Deserialize)]
struct PleaseSendContent {
    id: String,
    length: u64,
    offset: u64,
}

#[derive(Serialize, Deserialize)]
struct Content {
    id: String,
    offset: u64,
    base64: String,
    eof: u64,
}

impl PleaseSendContent {
    fn send_content(&self, inbound_states: &mut HashMap<String, InboundState>) -> Vec<Message> {
        if self.id.find("/") != None || self.id.find("\\") != None {
            return vec![];
        };
        let mut length = self.length;
        if length > (BLOCK_SIZE!()) {
            length = BLOCK_SIZE!()
        }

        let file: &File;
        let file_: File;
        if inbound_states.contains_key(&self.id)
            && self.offset + length < inbound_states[&self.id].eof
            && inbound_states[&self.id].bitmap[(self.offset / BLOCK_SIZE!()) as usize]
            && ((self.offset % BLOCK_SIZE!()) == 0)
        // TODO it is rude to ignore them just because they asked for a non-aligned block, but be sure im checking all blocks otherwise
        {
            file = &inbound_states[&self.id].file;
        } else {
            // if we're going to get it from ourselves, this is not the way to do it.  If we get here its probably for testing.
            if inbound_states.contains_key(&self.id) {
                return vec![];
            }

            match File::open(&self.id) {
                Ok(_r) => {
                    file_ = _r;
                    file = &file_;
                }
                _ => return vec![],
            }
        };

        debug!("going to send {:?} at {:?}", self.id, self.offset);

        let mut buf = vec![0; length as usize];
        length = file.read_at(&mut buf, self.offset as u64).unwrap() as u64;
        let (content, _) = buf.split_at(length as usize);
        return vec![Message::Content(Content {
            id: self.id.clone(),
            offset: self.offset,
            base64: general_purpose::STANDARD_NO_PAD.encode(content),
            eof: file.metadata().unwrap().len(),
        })];
    }
}

impl Content {
    fn receive_content(
        &self,
        inbound_states: &mut HashMap<String, InboundState>,
        src: SocketAddr,
        ps: &mut PeerState,
    ) -> Vec<Message> {
        let block_number = (self.offset / BLOCK_SIZE!()) as usize;
        if !inbound_states.contains_key(&self.id) {
            return vec![];
        }
        let i = inbound_states.get_mut(&self.id).unwrap();
        i.peers.insert(src);
        i.last_time_received = SystemTime::now();
        debug!("received  {:?} block {:?}", self.id, block_number);
        if self.eof > i.eof {
            i.eof = self.eof;
        }
        let blocks = (i.eof + BLOCK_SIZE!() - 1) / BLOCK_SIZE!();
        i.bitmap.resize(blocks as usize, false);
        if i.blocks_complete * BLOCK_SIZE!() >= i.eof {
            println!("{0} complete ", i.id);
            let path = "./incoming/".to_owned() + &i.id;
            let new_path = "./".to_owned() + &i.id;
            fs::rename(path, new_path).unwrap();
            inbound_states.remove(&self.id);
            return vec![];
        };

        if i.bitmap[block_number] {
            i.dups += 1;
            debug!("dup {block_number}");
        } else {
            let bytes = general_purpose::STANDARD_NO_PAD
                .decode(&self.base64)
                .unwrap();
            i.file.write_at(&bytes, self.offset).unwrap();
            i.blocks_complete += 1;
            i.bitmap.set(block_number, true);
        }
        i.next_block += 1;
        let mut message_out = i.request_block();
        debug!(
            "requesting {:?} offset {:?} window {:?}",
            i.id,
            i.next_block,
            i.next_block as i64 - i.bitmap.iter_ones().last().unwrap_or_default() as i64
        );
        if (i.blocks_complete % 100) == 0 {
            i.next_block += 1;
            i.grow_window(ps);
            message_out.push(Message::PleaseReturnThisMessage(PleaseReturnThisMessage {
                sent_at: UNIX_EPOCH.elapsed().unwrap().as_secs_f64(),
            }));
        }
        return message_out;
    }
}
//
struct InboundState {
    file: File,
    next_block: u64,
    bitmap: BitVec,
    id: String,
    eof: u64,
    blocks_complete: u64,
    dups: u64,
    peers: HashSet<SocketAddr>,
    last_time_received: SystemTime,
}

impl InboundState {
    fn new_inbound_state(inbound_states: &mut HashMap<String, InboundState>, id: &str) -> () {
        fs::create_dir("./incoming").ok();
        let path = "./incoming/".to_owned() + &id;
        let mut inbound_state = InboundState {
            file: OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open(path)
                .unwrap(),
            next_block: 0,
            bitmap: BitVec::new(),
            id: id.to_string(),
            eof: 1,
            blocks_complete: 0,
            peers: HashSet::new(),
            dups: 0,
            last_time_received: UNIX_EPOCH,
        };
        inbound_state.bitmap.resize(1, false);
        inbound_states.insert(id.to_string(), inbound_state);
    }

    fn request_block(&mut self) -> Vec<Message> {
        if self.blocks_complete * BLOCK_SIZE!() >= self.eof {
            return vec![];
        }
        while {
            if self.next_block * BLOCK_SIZE!() >= self.eof {
                info!("almost done with {0}", self.id);
                let should_have = self.bitmap.iter_ones().last().unwrap() + 1; // don't include the tail thats in flight for this calculation
                info!(
                    "{0} almost done {1} dups of, lost {2}% {3}/{4} blocks ",
                    self.id,
                    self.dups,
                    100.0 * (1.0 - (self.blocks_complete as f64 / should_have as f64)),
                    should_have as i64 - self.blocks_complete as i64,
                    should_have
                );

                info!("pending blocks: ");
                for i in self.bitmap.iter_zeros() {
                    info!("{i}");
                }

                self.next_block = 0;
            }
            self.bitmap[self.next_block as usize]
        } {
            self.next_block += 1;
        }
        return vec![Message::PleaseSendContent(PleaseSendContent {
            id: self.id.to_owned(),
            offset: self.next_block * BLOCK_SIZE!(),
            length: BLOCK_SIZE!(),
        })];
    }
    fn grow_window(&mut self, ps: &mut PeerState) {
        debug!("growing window for {0}", self.id);
        self.message_request_extra_block(ps, self.peers.clone());
    }
    fn search(&mut self, ps: &mut PeerState) {
        debug!("searching for {0}", self.id);
        self.message_request_extra_block(ps, ps.best_peers(50, 6));
    }
    fn message_request_extra_block(&mut self, ps: &mut PeerState, some_peers: HashSet<SocketAddr>) {
        for sa in some_peers {
            let mut message_out: Vec<Message> = Vec::new();
            message_out.append(&mut self.request_block());
            message_out.push(Message::PleaseReturnThisMessage(PleaseReturnThisMessage {
                sent_at: UNIX_EPOCH.elapsed().unwrap().as_secs_f64(),
            }));
            let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
            trace!("sending message {:?}", str::from_utf8(&message_out_bytes));
            debug!(
                "requesting  {:?} offset {:?} EXTRA from {:?}",
                self.id, self.next_block, sa
            );
            ps.socket.send_to(&message_out_bytes, sa).ok();
        }
    }
}

fn maintenance(inbound_states: &mut HashMap<String, InboundState>, ps: &mut PeerState) -> () {
    ps.sort();
    if Utc::now().second() + (Utc::now().minute() % 5) == 0 {
        ps.save_peers();
    }

    for sa in ps.best_peers(10, 3) {
        let mut message_out: Vec<Message> = Vec::new();
        message_out.push(Message::PleaseSendPeers(PleaseSendPeers {})); // let people know im here
        message_out.push(Message::PleaseReturnThisMessage(PleaseReturnThisMessage {
            sent_at: UNIX_EPOCH.elapsed().unwrap().as_secs_f64(),
        }));
        let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();

        ps.socket.send_to(&message_out_bytes, sa).ok();
    }

    for (_, i) in inbound_states.iter_mut() {
        i.grow_window(ps);
        if i.last_time_received.elapsed().unwrap() > Duration::from_secs(1) {
            i.search(ps);
            i.search(ps);
            i.search(ps);
            i.search(ps);
            i.search(ps);
            i.grow_window(ps);
            i.grow_window(ps);
            i.grow_window(ps);
            i.grow_window(ps);
        }
        i.search(ps);
    }
}

#[derive(Serialize, Deserialize)]
struct PleaseReturnThisMessage {
    sent_at: f64,
}

#[derive(Serialize, Deserialize)]
struct ReturnedMessage {
    sent_at: f64,
}
impl ReturnedMessage {
    fn update_time(&self, ps: &mut PeerState, src: SocketAddr) -> Vec<Message> {
        match ps.peer_map.get_mut(&src) {
            Some(peer) => {
                peer.delay = (UNIX_EPOCH + Duration::from_secs_f64(self.sent_at))
                    .elapsed()
                    .unwrap();
                debug!("measured {0} at {1}", src, peer.delay.as_secs_f64())
            }
            _ => (),
        };
        vec![]
    }
}

#[derive(Serialize, Deserialize)]
enum Message {
    PleaseSendPeers(PleaseSendPeers),
    Peers(Peers),
    PleaseSendContent(PleaseSendContent),
    Content(Content),
    PleaseReturnThisMessage(PleaseReturnThisMessage),
    ReturnedMessage(ReturnedMessage),
}
