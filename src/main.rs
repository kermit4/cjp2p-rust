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
use std::time::{Duration, Instant};
use std::vec;

macro_rules! BLOCK_SIZE {
    () => {
        0x1000 // 4k
    };
}

fn instant_default() -> Instant {
    Instant::now() - Duration::new(999000000, 00)
}

#[derive(Clone, Serialize, Deserialize)]
struct PeerInfo {
    #[serde(skip, default = "instant_default")]
    when_last_seen: Instant,
    delay: Duration,
}
struct PeerState {
    peer_map: HashMap<SocketAddr, PeerInfo>,
    peer_vec: Vec<(SocketAddr, PeerInfo)>,
    socket: UdpSocket,
    boot: Instant,
}
impl PeerState {
    fn probe(&self) -> () {
        for sa in self.best_peers(10, 3) {
            let mut message_out: Vec<Message> = Vec::new();
            message_out.push(Message::PleaseSendPeers(PleaseSendPeers {})); // let people know im here
            message_out.push(Message::PleaseReturnThisMessage(PleaseReturnThisMessage {
                sent_at: self.boot.elapsed().as_secs_f64(),
            }));
            let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();

            match self.socket.send_to(&message_out_bytes, sa) {
                Ok(s) => trace!("sent {s}"),
                Err(e) => warn!("failed to send {0} {e}", message_out_bytes.len()),
            }
        }
    }

    fn sort(&mut self) -> () {
        let now = Instant::now();
        self.peer_vec = self.peer_map.clone().into_iter().collect();
        self.peer_vec.sort_unstable_by(|a, b| {
            (now.duration_since(a.1.when_last_seen).as_secs_f64() * a.1.delay.as_secs_f64())
                .total_cmp(
                    &(now.duration_since(b.1.when_last_seen).as_secs_f64()
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
            let i = ((rng.gen_range(0.0..1.0) as f64).powi(quality) * (self.peer_vec.len() as f64))
                as usize;
            if i >= self.peer_vec.len() {
                continue;
            }
            let p = &self.peer_vec[i];
            result.insert(p.0);
            debug!(
                "best peer(q:{quality}) {0} {1} {2} {3}",
                i,
                p.0,
                p.1.when_last_seen.elapsed().as_secs_f64(),
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
        boot: Instant::now(),
    };
    ps.socket.set_broadcast(true).ok();
    ps.peer_map.insert(
        "148.71.89.128:24254".parse().unwrap(),
        PeerInfo {
            when_last_seen: Instant::now(),
            delay: Duration::new(1, 0),
        },
    );
    ps.peer_map.insert(
        "159.69.54.127:24254".parse().unwrap(),
        PeerInfo {
            when_last_seen: Instant::now(),
            delay: Duration::new(1, 0),
        },
    );
    ps.peer_map.insert(
        "192.168.1.255:24254".parse().unwrap(),
        PeerInfo {
            when_last_seen: Instant::now(),
            delay: Duration::new(1, 0),
        },
    );
    ps.peer_map.insert(
        "224.0.0.1:24254".parse().unwrap(),
        PeerInfo {
            when_last_seen: Instant::now(),
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
        InboundState::new(&mut inbound_states, v.as_str());
    }
    ps.socket.set_read_timeout(Some(Duration::new(1, 0)))?;
    let mut last_maintenance = Instant::now() - Duration::new(10, 0);
    loop {
        if last_maintenance.elapsed() > Duration::from_secs(3) {
            last_maintenance = Instant::now();
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
            Some(peer) => {
                if peer.when_last_seen.elapsed().as_secs_f64() > 99999999.0 {
                    warn!("new peer confirmed {src}");
                }
                peer.when_last_seen = Instant::now()
            }
            _ => {
                ps.peer_map.insert(
                    src,
                    PeerInfo {
                        when_last_seen: Instant::now(),
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
                    Message::PleaseSendContent(t) => t.send_content(&mut inbound_states, src),
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
                info!("new peer suggested {sa}");
                ps.peer_map.insert(
                    sa,
                    PeerInfo {
                        when_last_seen: Instant::now() - Duration::new(888000000, 00),
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
    length: usize,
    offset: usize,
}

#[derive(Serialize, Deserialize)]
struct Content {
    id: String,
    offset: usize,
    base64: String,
    eof: usize,
}

impl PleaseSendContent {
    fn send_content(
        &self,
        inbound_states: &mut HashMap<String, InboundState>,
        src: SocketAddr,
    ) -> Vec<Message> {
        if self.id.find("/") != None || self.id.find("\\") != None {
            return vec![];
        };
        let mut length = self.length;
        if length > 0xa000 {
            length = 0xa000;
        }

        let file: &File;
        let file_: File;
        if inbound_states.contains_key(&self.id)
            && self.offset + length < inbound_states[&self.id].eof
            && inbound_states[&self.id].bitmap[self.offset / BLOCK_SIZE!()]
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

        debug!(
            "going to send {:?} at {:?} to {:?}",
            self.id,
            self.offset / BLOCK_SIZE!(),
            src
        );

        let mut buf = vec![0; length];
        length = file.read_at(&mut buf, self.offset as u64).unwrap();
        let (content, _) = buf.split_at(length);
        return vec![Message::Content(Content {
            id: self.id.clone(),
            offset: self.offset,
            base64: general_purpose::STANDARD_NO_PAD.encode(content),
            eof: file.metadata().unwrap().len() as usize,
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
        if !inbound_states.contains_key(&self.id) {
            debug!(
                "spam, probably tail dups, for {0} block {1}",
                self.id,
                self.offset / BLOCK_SIZE!()
            );
            return vec![];
        }
        let i = inbound_states.get_mut(&self.id).unwrap();
        i.peers.insert(src);
        i.last_time_received = Instant::now();
        let block_number = self.offset / BLOCK_SIZE!();
        debug!("received  {:?} block {:?}", self.id, block_number);
        if self.eof > i.eof {
            i.eof = self.eof;
        }
        let blocks = (i.eof + BLOCK_SIZE!() - 1) / BLOCK_SIZE!();
        i.bitmap.resize(blocks, false);

        if i.bitmap[block_number] {
            i.dups += 1;
            debug!("dup {block_number}");
        } else {
            let bytes = general_purpose::STANDARD_NO_PAD
                .decode(&self.base64)
                .unwrap();
            i.file.write_at(&bytes, self.offset as u64).unwrap();
            if (i.blocks_complete + 1) * BLOCK_SIZE!() >= i.eof {
                println!("{0} complete ", i.id);
                let path = "./incoming/".to_owned() + &i.id;
                let new_path = "./".to_owned() + &i.id;
                fs::rename(path, new_path).unwrap();
                inbound_states.remove(&self.id);
                return vec![];
            };
            if bytes.len() == BLOCK_SIZE!() {
                // no reason someone would send a short block, but, just in case
                i.blocks_complete += 1;
                i.bitmap.set(block_number, true);
                if block_number > i.highest_block_received {
                    i.highest_block_received = block_number;
                }
                while i.bitmap[i.lowest_block_not_received]
                    && i.lowest_block_not_received < i.highest_block_received
                {
                    i.lowest_block_not_received += 1;
                }
            }
        }
        let mut message_out = i.request_block();
        debug!(
            "requesting {:?} offset {:?} window {:?} from {:?}",
            i.id,
            i.next_block,
            i.next_block as i64 - i.bitmap.iter_ones().last().unwrap_or_default() as i64,
            src
        );
        if (i.blocks_complete % 101) == 0 {
            i.request_more_in_transit(ps);
            message_out.push(Message::PleaseReturnThisMessage(PleaseReturnThisMessage {
                sent_at: ps.boot.elapsed().as_secs_f64(),
            }));
        }
        return message_out;
    }
}
//
struct InboundState {
    file: File,
    next_block: usize,
    highest_block_received: usize,
    lowest_block_not_received: usize,
    next_block_to_retry: usize,
    bitmap: BitVec,
    id: String,
    eof: usize,
    blocks_complete: usize,
    dups: usize,
    peers: HashSet<SocketAddr>,
    last_time_received: Instant,
}

impl InboundState {
    fn new(inbound_states: &mut HashMap<String, InboundState>, id: &str) -> () {
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
            highest_block_received: 0,
            lowest_block_not_received: 0,
            next_block_to_retry: 0,
            bitmap: BitVec::new(),
            id: id.to_string(),
            eof: 1,
            blocks_complete: 0,
            peers: HashSet::new(),
            dups: 0,
            last_time_received: Instant::now() - Duration::new(999, 00),
        };
        inbound_state.bitmap.resize(1, false);
        inbound_states.insert(id.to_string(), inbound_state);
    }

    fn request_block(&mut self) -> Vec<Message> {
        if self.blocks_complete * BLOCK_SIZE!() >= self.eof {
            return vec![];
        }
        while {
            self.next_block += 1;
            if self.next_block * BLOCK_SIZE!() >= self.eof {
                info!("almost done with {0}", self.id);
                info!(
                    "{0} almost done {1} dups of, lost {2}% {3}/{4} blocks ",
                    self.id,
                    self.dups,
                    100.0
                        * (1.0
                            - (self.blocks_complete as f64 / self.highest_block_received as f64)),
                    self.highest_block_received as i64 - self.blocks_complete as i64,
                    self.highest_block_received
                );

                info!(
                    "re-requesting unreceived blocks (the tail is probably in flight, not lost): "
                );
                for i in self.bitmap.iter_zeros() {
                    info!("{i}");
                }

                self.next_block = 0;
            }
            self.bitmap[self.next_block]
        } {}
        return vec![Message::PleaseSendContent(PleaseSendContent {
            id: self.id.to_owned(),
            offset: self.next_block * BLOCK_SIZE!(),
            length: BLOCK_SIZE!(),
        })];
    }
    fn request_more_in_transit(&mut self, ps: &mut PeerState) {
        debug!("growing window for {0}", self.id);
        self.retry_block(ps, self.peers.clone());
        self.next_block_to_retry += 1;
    }
    fn search(&mut self, ps: &mut PeerState) {
        debug!("searching for {0}", self.id);
        self.retry_block(ps, ps.best_peers(50, 6));
    }
    fn retry_block(&mut self, ps: &mut PeerState, some_peers: HashSet<SocketAddr>) {
        while {
            self.next_block_to_retry < self.highest_block_received
                && self.bitmap[self.next_block_to_retry]
        } {
            self.next_block_to_retry += 1;
        }
        if self.next_block_to_retry >= self.highest_block_received {
            self.next_block_to_retry = self.lowest_block_not_received
        }
        for sa in some_peers {
            let mut message_out: Vec<Message> =
                vec![Message::PleaseSendContent(PleaseSendContent {
                    id: self.id.to_owned(),
                    offset: self.next_block_to_retry * BLOCK_SIZE!(),
                    length: BLOCK_SIZE!(),
                })];
            message_out.push(Message::PleaseReturnThisMessage(PleaseReturnThisMessage {
                sent_at: ps.boot.elapsed().as_secs_f64(),
            }));
            debug!(
                "requesting  {:?} offset {:?} EXTRA from {:?}",
                self.id, self.next_block_to_retry, sa
            );
            let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
            trace!("sending message {:?}", str::from_utf8(&message_out_bytes));
            ps.socket.send_to(&message_out_bytes, sa).ok();
        }
    }
}

fn maintenance(inbound_states: &mut HashMap<String, InboundState>, ps: &mut PeerState) -> () {
    ps.sort();
    if Utc::now().second() / 3 + (Utc::now().minute() % 5) == 0 {
        ps.save_peers();
    }
    ps.probe();

    for (_, i) in inbound_states.iter_mut() {
        i.request_more_in_transit(ps);
        i.next_block_to_retry = i.lowest_block_not_received;
        if i.last_time_received.elapsed() > Duration::from_secs(3) {
            // stalled
            i.next_block = i.lowest_block_not_received;
            i.request_more_in_transit(ps);
            i.search(ps);
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
                peer.delay = (ps.boot + Duration::from_secs_f64(self.sent_at)).elapsed();
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
