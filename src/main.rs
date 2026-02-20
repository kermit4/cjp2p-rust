use base64::{engine::general_purpose, Engine as _};
use bitvec::prelude::*;
use chrono::{Timelike, Utc};
use log::{debug, error, info, log_enabled, trace, warn, Level};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::io;
use std::io::Write;
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
            trace!(
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
    fs::create_dir("./shared").ok();
    std::env::set_current_dir("./shared").unwrap();
    ps.load_peers();
    let mut args = env::args();
    args.next();
    let mut inbound_states: HashMap<String, InboundState> = HashMap::new();
    for v in args {
        info!("queing inbound file {:?}", v);
        InboundState::new(&mut inbound_states, v.as_str());
    }
    ps.socket.set_read_timeout(Some(Duration::new(1, 0)))?;
    let mut last_maintenance = Instant::now() - Duration::new(9999, 0);
    loop {
        if last_maintenance.elapsed() > Duration::from_secs(1) {
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
                warn!(
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
        debug!("received messages {:?} from {src}", messages.len());
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
                        warn!("could not deserialize an incoming message {:?}", message_in);
                        continue;
                    }
                };
                let reply = match message_in_enum {
                    Message::PleaseSendPeers(t) => t.send_peers(&ps),
                    Message::Peers(t) => t.receive_peers(&mut ps),
                    Message::PleaseSendContent(t) => t.send_content(&mut inbound_states, src),
                    Message::Content(t) => t.receive_content(&mut inbound_states, src, &mut ps),
                    Message::ReturnedMessage(t) => t.update_round_trip_time(&mut ps, src),
                    Message::MaybeTheyHaveSome(t) => {
                        t.add_content_peer_suggestions(&mut inbound_states)
                    }
                    _ => {
                        warn!("unknown message type ");
                        vec![]
                    }
                };
                for m in reply {
                    message_out.push(serde_json::to_value(m).unwrap());
                }
            }
        }
        if message_out.len() == 0 {
            continue;
        }
        if (rand::thread_rng().gen::<u32>() % 73) == 0 {
            message_out.push(
                serde_json::to_value(Message::PleaseReturnThisMessage(PleaseReturnThisMessage {
                    sent_at: ps.boot.elapsed().as_secs_f64(),
                }))
                .unwrap(),
            )
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
        trace!("received peers {:?} ", self.peers.len());
        for p in &self.peers {
            let sa: SocketAddr = *p;
            if !ps.peer_map.contains_key(&sa) {
                trace!("new peer suggested {sa}");
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
    eof: Option<usize>,
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
        let mut message_out: Vec<Message> = Vec::new();
        if inbound_states.contains_key(&self.id) {
            let i = inbound_states.get_mut(&self.id).unwrap();
            i.peers.insert(src);

            // this information should be sasved and sent even after a transfer
            if (rand::thread_rng().gen::<u32>() % 37) == 0 {
                message_out.push(Message::MaybeTheyHaveSome(MaybeTheyHaveSome {
                    id: self.id.to_owned(),
                    peers: i.peers.clone(),
                }));
            }
            // don't proceed to try to send out a file we're downloading even if we have it, as thats probably some testing situatoin not a real world situation
            //                push MaybeTheyHaveSome

            message_out.push(Message::MaybeTheyHaveSome(MaybeTheyHaveSome {
                id: self.id.to_owned(),
                peers: i.peers.clone(),
            }));
            return message_out;
        } else {
            // TODO we should have saved our peer list near the file to share with othhers
            match File::open(&self.id) {
                Ok(_r) => {
                    file_ = _r;
                    file = &file_;
                }
                // TODO even if we dont have and arent downloading the file, maybe we should be nice and keep track
                // of who's been looking and send them MaybeTheyHaveSome ..they would really
                // appreciate it i'm sure, and costs us very little
                _ => return message_out,
            }
        }

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
            base64: general_purpose::STANDARD.encode(content),
            eof: Some(file.metadata().unwrap().len() as usize),
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
            info!(
                "unwanted content, probably dups -- the tail still in flight after completion, for {0} block {1}",
                self.id,
                self.offset / BLOCK_SIZE!());
            return vec![];
        }
        let mut message_out;
        {
            {
                let i = inbound_states.get_mut(&self.id).unwrap();
                i.peers.insert(src);
                i.last_activity = Instant::now();
                let block_number = self.offset / BLOCK_SIZE!();
                debug!(
                    "\x1b[34mreceived block {:?} {:?} {:?} from {:?} window \x1b[7m{:}\x1b[m",
                    self.id,
                    block_number,
                    block_number * BLOCK_SIZE!(),
                    src,
                    i.next_block as i64 - block_number as i64
                );
                let bytes = general_purpose::STANDARD.decode(&self.base64).unwrap();
                let this_eof = match self.eof {
                    Some(n) => {
                        debug!("got eof {:?}", n);
                        n
                    }
                    None => self.offset + bytes.len() + 1,
                };

                if this_eof != i.eof {
                    i.eof = this_eof;
                    let blocks = (i.eof + BLOCK_SIZE!() - 1) / BLOCK_SIZE!();
                    i.bitmap.resize(blocks, false);
                }

                if i.bitmap[block_number] {
                    info!("dup {block_number}");
                    return vec![];
                }
                i.file.write_at(&bytes, self.offset as u64).unwrap();
                if bytes.len() == BLOCK_SIZE!()
                    || bytes.len() + block_number * BLOCK_SIZE!() == i.eof
                {
                    // no reason someone would send a short block, but, just in case
                    // i think this is a bug that will ignore the last block until the rest is done,
                    // unless its the usual block size, but that last block could grow so thats why
                    i.bytes_complete += bytes.len();
                    i.bitmap.set(block_number, true);
                }
                message_out = i.request_next_block();
                i.next_block += 1;
            }
            if (rand::thread_rng().gen::<u32>() % 101) == 0 {
                for (_, i) in inbound_states.iter_mut() {
                    if i.next_block * BLOCK_SIZE!() >= i.eof {
                        continue;
                    }
                    debug!("growing window for {0}", i.id);
                    let grow = i.request_next_block();
                    i.next_block += 1;
                    let message_out_bytes: Vec<u8> = serde_json::to_vec(&grow).unwrap();
                    ps.socket.send_to(&message_out_bytes, src).ok();
                    break;
                }
            }
            let i = inbound_states.get_mut(&self.id).unwrap();
            if i.bytes_complete == i.eof {
                //EOF if the sha matches its done,
                //not needed here then
                let mut hasher = Sha256::new();
                io::copy(&mut i.file, &mut hasher).ok();
                let hash = format!("{:x}", hasher.finalize());
                println!("{} sha256sum", hash);
                if hash == i.id.to_lowercase() {
                    info!("{0} finished ", i.id);
                    println!("{0} finished ", i.id);
                    let path = "./incoming/".to_owned() + &i.id;
                    let new_path = "./".to_owned() + &i.id;
                    fs::rename(path, new_path).unwrap();
                    inbound_states.remove(&self.id);
                } else {
                    error!("hash doesnt match!");
                    i.bitmap.fill(false);
                    i.next_block = 0;
                    i.bytes_complete = 0;
                };
            }
        }
        if message_out.len() == 0 {
            for (_, i) in inbound_states.iter_mut() {
                if i.next_block * BLOCK_SIZE!() >= i.eof {
                    continue;
                }
                message_out = i.request_next_block();
                i.next_block += 1;
                break;
            }
        }
        return message_out;
    }
}
//
struct InboundState {
    file: File,
    next_block: usize,
    bitmap: BitVec,
    id: String,
    eof: usize,
    bytes_complete: usize,
    peers: HashSet<SocketAddr>,
    last_activity: Instant,
}

impl InboundState {
    fn new(inbound_states: &mut HashMap<String, InboundState>, id: &str) -> () {
        fs::create_dir("./incoming").ok();
        let path = "./incoming/".to_owned() + &id;
        let mut i = InboundState {
            file: OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open(path)
                .unwrap(),
            next_block: 0,
            bitmap: BitVec::new(),
            id: id.to_string(),
            eof: 1 << 18,
            bytes_complete: 0,
            peers: HashSet::new(),
            last_activity: Instant::now() - Duration::new(999, 00),
        };
        i.bitmap
            .resize((i.eof + BLOCK_SIZE!() - 1) / BLOCK_SIZE!(), false);
        inbound_states.insert(id.to_string(), i);
    }

    fn request_next_block(&mut self) -> Vec<Message> {
        while {
            if self.next_block * BLOCK_SIZE!() >= self.eof {
                // %EOF
                info!(
                    "\x1b[36m{} almost done {}/{} blocks done (eof: {}) , \x1b[m",
                    self.id,
                    self.bytes_complete / BLOCK_SIZE!(),
                    (self.eof - self.bytes_complete) / BLOCK_SIZE!(),
                    self.eof,
                );

                if log_enabled!(Level::Trace) {
                    for i in self.bitmap.iter_zeros() {
                        trace!("{i}");
                    }
                }

                //                self.next_block = 0;
                return vec![];
            }
            self.bitmap[self.next_block]
        } {
            self.next_block += 1;
        }
        debug!(
            "\x1b[32;7mPleaseSendContent {} {} {} \x1b[m",
            self.id,
            self.next_block,
            self.next_block * BLOCK_SIZE!()
        );
        self.last_activity = Instant::now();
        return vec![Message::PleaseSendContent(PleaseSendContent {
            id: self.id.to_owned(),
            offset: self.next_block * BLOCK_SIZE!(),
            length: BLOCK_SIZE!(),
        })];
    }
    fn request_blocks(&mut self, ps: &mut PeerState, some_peers: HashSet<SocketAddr>) {
        let message_out = self.request_next_block();
        if message_out.len() < 1 {
            return;
        }
        let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
        for sa in some_peers {
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
        if i.last_activity.elapsed() > Duration::from_secs(1) && i.next_block != 0 {
            debug!("stalled {}", i.id);
            i.next_block = 0; // start over to catch any lost packets, as now we know there's
                              // probably not any still in flight
        }
    }
    for (_, i) in inbound_states.iter_mut() {
        if i.last_activity.elapsed() > Duration::from_secs(1) {
            debug!("restarting {}", i.id);
            i.request_blocks(ps, i.peers.clone()); // resume (un-stall)
        }
        debug!("searching for {}", i.id);
        i.request_blocks(ps, ps.best_peers(50, 6));
        break; // see how slow it would be fi i was doin gone by one 256k blocks to stream this
               // way ,then add a speedup by putting the request_more_in_flight call after one is
               // finished and on dups
    }
}

#[derive(Serialize, Deserialize)]
struct MaybeTheyHaveSome {
    id: String,
    peers: HashSet<SocketAddr>,
}

impl MaybeTheyHaveSome {
    fn add_content_peer_suggestions(
        self,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if !inbound_states.contains_key(&self.id) {
            return vec![];
        }
        let i = inbound_states.get_mut(&self.id).unwrap();
        for p in self.peers {
            i.peers.insert(p);
        }
        vec![]
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
    fn update_round_trip_time(&self, ps: &mut PeerState, src: SocketAddr) -> Vec<Message> {
        match ps.peer_map.get_mut(&src) {
            Some(peer) => {
                peer.delay = (ps.boot + Duration::from_secs_f64(self.sent_at)).elapsed();
                trace!("measured {0} at {1}", src, peer.delay.as_secs_f64())
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
    MaybeTheyHaveSome(MaybeTheyHaveSome),
}
