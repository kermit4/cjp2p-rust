//use base64::{engine::general_purpose, Engine as _};
use bitvec::prelude::*;
use chrono::{Timelike, Utc};
use enum_dispatch::enum_dispatch;
use hex;
use log::{debug, error, info, log_enabled, trace, warn, Level};
use memmap2::MmapMut;
//use nix::NixPath;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::{base64::Base64, serde_as, InspectError, VecSkipError};
use sha2::{Digest, Sha256};
use snow::Builder;
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::io::{BufReader, BufWriter, Seek, SeekFrom, Write};
//use std::convert::TryInto;
use std::env;
//use std::fmt;
use std::f64;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
//use std::io::copy;
use rand::Rng;
use std::net::TcpStream;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::fs::FileExt;
use std::str;
use std::time::{Duration, Instant};
use std::vec;

const NOISE_PARAMS: &str = "Noise_NK_25519_AESGCM_SHA256";

#[macro_export]
macro_rules! BLOCK_SIZE {
    () => {
        0x1000 // 4k
    };
}

// when this gets to millions of peers, consider keeping less info about the slower ones
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PeerInfo {
    pub delay: Duration,
    pub anti_ip_spoofing_cookie_they_expect: Option<String>,
    #[serde_as(as = "Option<Base64>")]
    pub ed25519: Option<Vec<u8>>,
    pub you_should_see_this: Option<YouSouldSeeThis>,
    pub i_just_saw_this: Option<IJustSawThis>,
}
impl PeerInfo {
    pub fn new() -> Self {
        return Self {
            delay: Duration::from_millis(120),
            anti_ip_spoofing_cookie_they_expect: None,
            ed25519: None,
            you_should_see_this: Some(YouSouldSeeThis {
                id: "43a39a05ce426151da3c706ab570932b550065ab4f9e521bb87615f841517cf1".to_owned(),
                length: 105277987,
            }),
            i_just_saw_this: None,
        };
    }
}
#[derive(Debug)]
pub struct OpenFile {
    pub file: File,
    pub eof: usize,
}
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct Keypair {
    #[serde_as(as = "Base64")]
    pub public: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub private: Vec<u8>,
}
impl Keypair {
    pub fn load_key() -> Self {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open("./cjp2p/state/key.json");
        if file.as_ref().is_ok() && file.as_ref().unwrap().metadata().unwrap().len() > 0 {
            let saved: Self = serde_json::from_reader(&file.unwrap()).unwrap();
            return Self {
                public: saved.public,
                private: saved.private,
            };
        } else {
            let keypair_ = Builder::new(NOISE_PARAMS.parse().unwrap())
                .generate_keypair()
                .unwrap();
            let keypair = Self {
                public: keypair_.public,
                private: keypair_.private,
            };
            file.as_ref()
                .unwrap()
                .write_all(&serde_json::to_vec_pretty(&keypair).unwrap())
                .ok();
            return keypair;
        }
    }
}

pub struct PeerState {
    pub peer_map: HashMap<SocketAddr, PeerInfo>,
    pub peer_vec: Vec<SocketAddr>,
    pub socket: UdpSocket,
    pub boot: Instant,
    pub keypair: Keypair,
    pub open_file_cache: HashMap<String, OpenFile>,
    pub list_results: HashMap<String, (i32, u64)>,
    pub list_time: Instant,
    pub p: PersistentState,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct PersistentState {
    pub you_should_see_this: Option<YouSouldSeeThis>,
    pub i_just_saw_this: Option<IJustSawThis>,
}
impl PersistentState {
    pub fn save(&self) {
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open("./cjp2p/state/persistent_state.json")
            .unwrap()
            .write_all(&serde_json::to_vec_pretty(&self).unwrap())
            .unwrap();
    }
    pub fn load() -> Self {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open("./cjp2p/state/persistent_state.json");
        if file.as_ref().is_ok() && file.as_ref().unwrap().metadata().unwrap().len() > 0 {
            return serde_json::from_reader(&file.unwrap()).unwrap();
        } else {
            return Self {
                you_should_see_this: None,
                i_just_saw_this: None,
            };
        }
    }
}
impl PeerState {
    pub fn new() -> Self {
        fs::create_dir("./cjp2p").ok();
        fs::create_dir("./cjp2p/public").ok();
        fs::create_dir("./cjp2p/metadata").ok();
        fs::create_dir("./cjp2p/state").ok();
        let mut ps = Self {
            peer_map: PeerState::load_peers(),
            peer_vec: vec![],
            socket: UdpSocket::bind("0.0.0.0:24254").unwrap(),
            boot: Instant::now(),
            keypair: Keypair::load_key(),
            open_file_cache: HashMap::new(),
            list_results: HashMap::new(),
            list_time: Instant::now(),
            p: PersistentState::load(),
        };
        ps.socket.set_broadcast(true).ok();
        ps.socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        for p in ["148.71.89.128:24254", "159.69.54.127:24254"] {
            ps.peer_map.insert(p.parse().unwrap(), PeerInfo::new());
        }
        return ps;
    }
    pub fn hash_ip(&self, src: SocketAddr) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.keypair.private[..8]);
        hasher.update(src.ip().to_string());
        return format!("{:x}", hasher.finalize())[..8].to_string();
    }

    pub fn check_key(&self, messages: &Vec<Message>, src: SocketAddr) -> bool {
        for message_in in messages {
            if let Message::AlwaysReturned(m) = message_in {
                let correct_hash = self.hash_ip(src);
                return correct_hash != m.cookie;
            }
        }
        return true;
    }
    pub fn please_always_return(&self, src: SocketAddr) -> Message {
        let correct_hash = self.hash_ip(src);
        return Message::PleaseAlwaysReturnThisMessage(PleaseAlwaysReturnThisMessage {
            cookie: correct_hash,
        });
    }

    pub fn always_returned(&self, sa: SocketAddr) -> Vec<Message> {
        trace!("always_returned for {sa}");
        match self.peer_map.get(&sa) {
            None => return vec![],
            Some(p) => match p.anti_ip_spoofing_cookie_they_expect.to_owned() {
                Some(cookie) => {
                    trace!("always_returned for {sa} found {cookie}");
                    return vec![Message::AlwaysReturned(AlwaysReturned{cookie:cookie })];
                }
                None => return vec![],
            },
        }
    }

    pub fn probe_interfaces(&mut self) -> () {
        let to_probe: &mut HashSet<SocketAddr> = &mut HashSet::new();
        let addrs = nix::ifaddrs::getifaddrs().unwrap();
        for ifaddr in addrs {
            match ifaddr.broadcast {
                Some(address) => match address.as_sockaddr_in() {
                    Some(addr) => {
                        let mut sa = SocketAddr::from(*addr);
                        sa.set_port(24254);
                        to_probe.insert(sa);
                        ()
                    }
                    None => (),
                },
                None => (),
            }
        }
        to_probe.insert("224.0.0.1:24254".parse().unwrap());
        for sa in to_probe.iter() {
            let message_out_bytes: Vec<u8> =
                serde_json::to_vec(&vec![Message::PleaseSendPeers(PleaseSendPeers {})]).unwrap();
            trace!( "sending message {:?} to {sa}", String::from_utf8_lossy(&message_out_bytes));
            self.socket.send_to(&message_out_bytes, sa).ok();
        }
    }
    pub fn probe(&mut self) -> () {
        for sa in self.best_peers(10, 3) {
            let peer_info = self.peer_map.get_mut(&sa).unwrap();
            peer_info.delay = peer_info.delay.saturating_add(peer_info.delay / 20);
            let mut message_out: Vec<Message> = Vec::new();
            message_out.push(Message::PleaseSendPeers(PleaseSendPeers {}));
            // let people know im here
            // im not sure if anyone cares about all this info from completely random contacts
            message_out.push(self.please_always_return(sa));
            if let Some(i_just_saw_this) = &self.p.i_just_saw_this {
                message_out.push(Message::IJustSawThis(i_just_saw_this.clone()));
            }
            if let Some(you_should_see_this) = &self.p.you_should_see_this {
                message_out.push(Message::YouSouldSeeThis(you_should_see_this.clone()));
            }
            message_out.push(Message::MyPublicKey(MyPublicKey {
                ed25519: self.keypair.public.clone(),
            }));
            message_out.append(&mut self.always_returned(sa));
            message_out.push(PleaseReturnThisMessage::new(self));
            let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();

            trace!( "sending message {:?} to {sa}", String::from_utf8_lossy(&message_out_bytes));
            match self.socket.send_to(&message_out_bytes, sa) {
                Ok(s) => trace!("sent {s}"),
                Err(e) => warn!("failed to send {0} {e}", message_out_bytes.len()),
            }
        }
    }

    pub fn sort(&mut self) -> () {
        let mut peers: Vec<_> = self
            .peer_map
            .iter()
            .map(|(k, v)| (k, v.delay.as_secs_f64()))
            .collect();
        peers.sort_unstable_by(|a, b| a.1.total_cmp(&b.1));
        self.peer_vec = peers.into_iter().map(|(addr, _)| *addr).collect();
    }

    pub fn load_peers() -> HashMap<SocketAddr, PeerInfo> {
        let file = OpenOptions::new()
            .read(true)
            .open("./cjp2p/state/peers.v6.json");
        let mut map = HashMap::<SocketAddr, PeerInfo>::new();
        if file.as_ref().is_ok() && file.as_ref().unwrap().metadata().unwrap().len() > 0 {
            let json: Vec<(SocketAddr, PeerInfo)> =
                serde_json::from_reader(&file.unwrap()).unwrap();
            map.extend(json);
        }
        return map;
    }
    pub fn save_peers(&self) -> () {
        debug!("saving peers");
        // not really sure how many, if any, of these peers or fields should be saved, or just a PleaseListContent of host:ips, but for the few users (1) of this so far, might as well save it all
        let mut peers_to_save: Vec<(SocketAddr, PeerInfo)> = Vec::new();
        for i in 0..cmp::min(self.peer_vec.len(), 99) {
            peers_to_save.push((self.peer_vec[i], self.peer_map[&self.peer_vec[i]].clone()))
        }

        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("./cjp2p/state/peers.v6.json")
            .unwrap()
            .write_all(&serde_json::to_vec_pretty(&peers_to_save).unwrap())
            .ok();
    }

    pub fn best_peers(&self, how_many: i32, quality: i32) -> HashSet<SocketAddr> {
        let mut rng = rand::thread_rng();
        let result: &mut HashSet<SocketAddr> = &mut HashSet::new();
        for _ in 0..how_many {
            let i = ((rng.gen_range(0.0..1.0) as f64).powi(quality) * (self.peer_vec.len() as f64))
                as usize;
            if i >= self.peer_vec.len() {
                continue;
            }
            let p = &self.peer_vec[i];
            result.insert(*p);
            trace!( "best peer(q:{quality}) {0} {1} {2}", i, p, self.peer_map[p].delay.as_secs_f64());
        }
        result.clone()
    }
    pub fn handle_messages(
        &mut self,
        messages: Vec<Message>,
        src: SocketAddr,
        might_be_ip_spoofing: bool,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        let mut message_out = vec![];
        for message_in_enum in messages {
            message_out.append(&mut message_in_enum.receive(
                self,
                src,
                might_be_ip_spoofing,
                inbound_states,
            ));
        }
        return message_out;
    }
}

pub fn handle_network(ps: &mut PeerState, inbound_states: &mut HashMap<String, InboundState>) {
    let mut buf = [0; 0x10000];

    let (message_in_len, src) = ps.socket.recv_from(&mut buf).unwrap();
    let message_in_bytes = &buf[0..message_in_len];
    trace!( "incoming message {:?} from {src}", String::from_utf8_lossy(message_in_bytes));
    let messages: Messages = match serde_json::from_slice(message_in_bytes) {
        Ok(r) => r,
        Err(e) => {
            warn!( "could not deserialize incoming messages  {e}  :  {}",
                    String::from_utf8_lossy(message_in_bytes));
            return;
        }
    };
    let messages = messages.0;
    if !ps.peer_map.contains_key(&src) {
        ps.peer_map.insert(src, PeerInfo::new());
        warn!("new peer spotted {src}");
    }
    // This ist a Vec<Value> because I don't know the structure of the Please*Returns
    let might_be_ip_spoofing = ps.check_key(&messages, src);
    let mut message_out = ps.handle_messages(messages, src, might_be_ip_spoofing, inbound_states);
    if message_out.len() == 0 {
        return;
    }
    message_out.append(&mut ps.always_returned(src));
    if might_be_ip_spoofing {
        trim_reply(&mut message_out, message_in_len);
    }
    if message_out.len() == 0 {
        warn!("ratio: none left!");
        return;
    }
    let message_out_bytes = serde_json::to_vec(&message_out).unwrap();
    trace!( "sending message {1:?} to {0}{src}", if might_be_ip_spoofing {
               "\x1b[7munverified\x1b[m "} else {""},  String::from_utf8_lossy(&message_out_bytes));
    // slow, even big blocks is 4x slower user time, with sys time 3x
    // 4k blocks 8x slower user, 5x net
    /*      if let Some(their_pub) = &ps.peer_map[&src].ed25519 {
                  message_out_bytes = serde_json::to_vec(
                      &(vec![
                          EncryptedMessages::new(their_pub, src, message_out_bytes),
                          ]),
                  ).unwrap();
              }
    */
    match ps.socket.send_to(&message_out_bytes, src) {
        Ok(s) => trace!("sent {s}"),
        Err(e) => warn!("failed to send {0} {e}", message_out_bytes.len()),
    }
}
pub fn trim_reply(message_out: &mut Vec<Message>, message_in_length: usize) {
    let mut ratio;
    let mut message_out_bytes;
    while {
        message_out_bytes = serde_json::to_vec(&message_out).unwrap();
        ratio = // 20 is IP header, 8 is UDP header
            (message_out_bytes.len() as f64 + 20.0 + 8.0) / (message_in_length  as f64 + 20.0 + 8.0);
        trace!("ratio: {ratio}");
        message_out.len() > 0 && ratio > 2.5
    } {
        let popped = message_out.pop();
        debug!("{ratio}x ratio: dropping part of response to unverified source IP, so that you are not used as a flood/stressor/DDOS. {:?}", popped);
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Peers {
    pub peers: HashSet<SocketAddr>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct AlwaysReturned {
    pub cookie: String,
}
impl Receive for AlwaysReturned {
    fn receive(
        self,
        _: &mut PeerState,
        _: SocketAddr,
        _: bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        //this is handled early
        vec![]
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PleaseAlwaysReturnThisMessage {
    pub cookie: String,
}
impl Receive for PleaseAlwaysReturnThisMessage {
    fn receive(
        self,
        ps: &mut PeerState,
        src: SocketAddr,
        _: bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        trace!("saving cookie {} for {src}",self.cookie);
        ps.peer_map
            .get_mut(&src)
            .unwrap()
            .anti_ip_spoofing_cookie_they_expect = Some(self.cookie);
        return vec![];
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct PleaseSendPeers {}
impl Receive for PleaseSendPeers {
    fn receive(
        self,
        ps: &mut PeerState,
        src: SocketAddr,
        might_be_ip_spoofing: bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        let p = ps.best_peers(1 + 45 * !might_be_ip_spoofing as i32, 6);
        trace!("sending {:?}/{:?} peers", p.len(), ps.peer_map.len());
        let mut message_out = vec![Message::Peers(Peers { peers: p })];
        if might_be_ip_spoofing {
            message_out.push(ps.please_always_return(src));
        }
        return message_out;
    }
}
impl Receive for Peers {
    fn receive(
        self,
        ps: &mut PeerState,
        _: SocketAddr,
        _: bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        trace!("received peers {:?} ", self.peers.len());
        for p in &self.peers {
            let sa: SocketAddr = *p;
            if !ps.peer_map.contains_key(&sa) {
                trace!("new peer suggested {sa}");
                ps.peer_map.insert(sa, PeerInfo::new());
            }
        }
        return vec![];
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct IJustSawThis {
    pub id: String,
    pub length: u64,
}
impl Receive for IJustSawThis {
    fn receive(
        self,
        ps: &mut PeerState,
        src: SocketAddr,
        might_be_ip_spoofing: bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if !might_be_ip_spoofing && src.port() == 24254 {
            ps.peer_map.get_mut(&src).unwrap().i_just_saw_this = Some(self);
        }
        vec![]
    }
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct YouSouldSeeThis {
    pub id: String,
    pub length: u64,
}
impl Receive for YouSouldSeeThis {
    fn receive(
        self,
        ps: &mut PeerState,
        src: SocketAddr,
        might_be_ip_spoofing: bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if !might_be_ip_spoofing && src.port() == 24254 {
            ps.peer_map.get_mut(&src).unwrap().you_should_see_this = Some(self);
        }
        vec![]
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct PleaseSendContent {
    pub id: String,
    pub length: usize,
    pub offset: usize,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct Content {
    pub id: String,
    pub offset: usize,
    #[serde_as(as = "Base64")]
    pub base64: Vec<u8>,
    pub eof: Option<usize>,
}

impl PleaseSendContent {
    pub fn new_messages(i: &mut InboundState) -> Vec<Message> {
        if i.http_socket.is_some()
            && (i.next_block * BLOCK_SIZE!() > i.http_end
                || i.next_block * BLOCK_SIZE!() < i.http_start)
        // try harder if user is waiting
        {
            info!("http trying harder!");
            i.next_block = i.http_start as usize / BLOCK_SIZE!();
        }
        while {
            if i.next_block * BLOCK_SIZE!() >= i.eof {
                // %EOF
                info!( "\x1b[36m{} almost done {}/{}/{}  blocks done/remaining/next \x1b[m", i.id, i.bytes_complete / BLOCK_SIZE!(), (i.eof - i.bytes_complete) / BLOCK_SIZE!(), i.next_block);
                if log_enabled!(Level::Trace) {
                    for i in i.bitmap.iter_zeros() {
                        trace!("{i}");
                    }
                } //this can cause window loss in debug build

                //                i.next_block = 0;
                return vec![];
            }
            i.bitmap[i.next_block]
        } {
            i.next_block += 1;
        }
        debug!( "\x1b[32;7mPleaseSendContent {} {} {} \x1b[m", i.id, i.next_block, i.next_block * BLOCK_SIZE!());
        i.last_activity = Instant::now();
        return vec![Message::PleaseSendContent(PleaseSendContent {
            id: i.id.to_owned(),
            offset: i.next_block * BLOCK_SIZE!(),
            length: BLOCK_SIZE!(),
        })];
    }
}
impl Receive for PleaseSendContent {
    fn receive(
        self,
        ps: &mut PeerState,
        src: SocketAddr,
        might_be_ip_spoofing: bool,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if self.id.find("/") != None || self.id.find("\\") != None {
            return vec![];
        };
        let mut message_out: Vec<Message> = Vec::new();
        if let Some(i) = inbound_states.get_mut(&self.id) {
            i.peers.insert(src);
            message_out.append(&mut i.send_content_peers(might_be_ip_spoofing, src));
        } else {
            message_out.append(&mut Content::new_block(&self, might_be_ip_spoofing, ps));
        }
        if message_out.len() == 0
            || (!might_be_ip_spoofing && rand::thread_rng().gen::<u32>() % 23 == 0)
        // if the file is small, they dont need more peers
        // and if its big they'll hit this random often
        {
            message_out.append(&mut InboundState::send_content_peers_from_disk(
                &self.id,
                might_be_ip_spoofing,
                &src,
            ));
        }
        if might_be_ip_spoofing && message_out.len() > 0 {
            message_out.push(ps.please_always_return(src));
        }
        return message_out;
    }
}

impl Content {
    pub fn new_block(
        req: &PleaseSendContent,
        might_be_ip_spoofing: bool,
        ps: &mut PeerState,
    ) -> Vec<Message> {
        if might_be_ip_spoofing && rand::thread_rng().gen::<u32>() % 27 == 0 {
            info!("randomly ignoring unverified source IPs for {} so ba dumb client doesn't get stuck in a loop",req.id);

            return vec![];
        }
        let length = if might_be_ip_spoofing {
            1
        } else if req.length > 0xa000 {
            0xa000
        } else {
            req.length
        };
        let ofr = if let Some(ofr) = ps.open_file_cache.get(&req.id) {
            ofr
        } else if let Ok(file) = File::open("./cjp2p/public/".to_owned() + &req.id) {
            let ofr = OpenFile {
                eof: file.metadata().unwrap().len() as usize,
                file: file,
            };
            ps.open_file_cache.insert(req.id.to_owned(), ofr);
            &ps.open_file_cache[&req.id]
        } else {
            return vec![];
        };
        debug!( "going to send {:?} at {:?}", req.id, req.offset / BLOCK_SIZE!());
        let mut buf = vec![0; length];
        let length = ofr.file.read_at(&mut buf, req.offset as u64).unwrap();
        buf.truncate(length);
        return vec![Message::Content(Self {
            id: req.id.clone(),
            offset: req.offset,
            base64: buf,
            eof: Some(ofr.eof),
        })];
    }
}
impl Receive for Content {
    fn receive(
        self,
        ps: &mut PeerState,
        src: SocketAddr,
        _: bool,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if !inbound_states.contains_key(&self.id) {
            debug!( "unwanted content, probably dups -- the tail still in flight after completion, for {0} block {1}",
                self.id, self.offset / BLOCK_SIZE!());
            return vec![];
        }
        let i = inbound_states.get_mut(&self.id).unwrap();
        if (rand::thread_rng().gen::<u32>() % (if i.http_socket.is_some() { 7 } else { 101 })) == 0
            || self.offset == 0
        {
            for (_, i) in inbound_states.iter_mut() {
                if i.next_block * BLOCK_SIZE!() >= i.eof {
                    continue;
                }
                debug!("growing window ({}) for {} at {}", i.next_block as i32 -self.offset as i32 /BLOCK_SIZE!(),i.id,i.next_block);
                i.request_blocks(ps, HashSet::from([src]));
                i.next_block += 1;
                break;
            }
        }
        let i = inbound_states.get_mut(&self.id).unwrap();
        i.peers.insert(src);
        let block_number = self.offset / BLOCK_SIZE!();
        debug!( "\x1b[34mreceived block {:?} {:?} {:?} from {:?} window \x1b[7m{:}\x1b[m", self.id, block_number, block_number * BLOCK_SIZE!(), src, i.next_block as i64 - block_number as i64);
        let mut message_out = i.receive_content(&self);
        if i.finished() {
            i.serve_http_if_any_is_ready(); // TODO force this to not care how much is left
            inbound_states.remove(&self.id);
        }
        if message_out.len() == 0 {
            for (_, i) in inbound_states.iter_mut() {
                if i.next_block * BLOCK_SIZE!() >= i.eof {
                    continue;
                }
                message_out = PleaseSendContent::new_messages(i);
                i.next_block += 1;
                break;
            }
        }
        if message_out.len() == 0 {
            if let Some(i) = inbound_states.get_mut(&self.id) {
                i.next_block = 0;
                message_out = PleaseSendContent::new_messages(i);
                i.next_block += 1;
            }
        }
        return message_out;
    }
}
//
#[derive(Debug)]
pub struct InboundState {
    pub mmap: Option<MmapMut>,
    pub next_block: usize,
    pub bitmap: BitVec,
    pub id: String,
    pub eof: usize,
    pub bytes_complete: usize,
    pub peers: HashSet<SocketAddr>,
    pub last_activity: Instant,
    pub hash_failures: i32,
    pub http_time: Instant,
    pub http_start: usize,
    pub http_end: usize,
    pub http_socket: Option<TcpStream>,
}

impl InboundState {
    pub fn new(id: &str, ps: &PeerState) -> Self {
        fs::create_dir("./incoming").ok();
        let mut peers = HashSet::new();
        for (k, v) in &ps.peer_map {
            if let Some(p) = &v.you_should_see_this {
                if p.id == id {
                    peers.insert(*k);
                }
            }
            if let Some(p) = &v.i_just_saw_this {
                if p.id == id {
                    peers.insert(*k);
                }
            }
        }
        return Self {
            mmap: None,
            next_block: 0,
            bitmap: bitvec![0;(1<<18)/BLOCK_SIZE!()],
            id: id.to_string(),
            eof: 1 << 18,
            bytes_complete: 0,
            peers: peers,
            last_activity: Instant::now() - Duration::from_secs(999),
            hash_failures: 0,
            http_time: Instant::now(),
            http_start: 0,
            http_end: 0,
            http_socket: None,
        };
    }

    fn receive_content(&mut self, content: &Content) -> Vec<Message> {
        let this_eof = match content.eof {
            Some(n) => n,
            None => content.offset + content.base64.len() + 1,
        };

        if this_eof != self.eof || self.mmap.is_none() {
            self.eof = this_eof;
            let blocks = (self.eof + BLOCK_SIZE!() - 1) / BLOCK_SIZE!();
            self.bitmap.resize(blocks, false);
            let file = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open("./incoming/".to_owned() + &self.id)
                .unwrap();
            file.set_len(self.eof as u64).unwrap();
            self.mmap = Some(unsafe { MmapMut::map_mut(&file).unwrap() });
        }

        if content.offset >= self.eof {
            return vec![];
        }
        let block_number = content.offset / BLOCK_SIZE!();
        if self.bitmap[block_number] {
            info!("dup {block_number}");
        } else if content.base64.len() == BLOCK_SIZE!()
            || content.base64.len() + content.offset == self.eof
        {
            self.mmap.as_mut().unwrap()[content.offset..content.base64.len() + content.offset]
                .copy_from_slice(content.base64.as_ref());
            self.bytes_complete += content.base64.len();
            self.bitmap.set(block_number, true);
            self.serve_http_if_any_is_ready();
        }
        self.last_activity = Instant::now();
        let message_out = PleaseSendContent::new_messages(self);
        self.next_block += 1;
        return message_out;
    }

    pub fn request_blocks(&mut self, ps: &PeerState, some_peers: HashSet<SocketAddr>) {
        for sa in some_peers {
            let mut message_out: Vec<Message> = Vec::new();
            for m in PleaseSendContent::new_messages(self) {
                message_out.push(m);
            }
            if message_out.len() < 1 {
                return;
            }
            message_out.append(&mut ps.always_returned(sa));

            let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
            debug!( "requesting additional blocks {:?} to {sa}", String::from_utf8_lossy(&message_out_bytes)
            );
            ps.socket.send_to(&message_out_bytes, sa).ok();
        }
    }
    pub fn save_content_peers(&self) -> () {
        debug!("saving inbound state peers");
        let filename = "./cjp2p/metadata/".to_owned() + &self.id + ".json";
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(filename)
            .unwrap()
            .write_all(
                serde_json::to_vec_pretty(&json!({"Peers":&self.peers}))
                    .unwrap()
                    .as_slice(),
            )
            .ok();
    }
    pub fn send_content_peers_from_disk(
        id: &String,
        might_be_ip_spoofing: bool,
        src: &SocketAddr,
    ) -> Vec<Message> {
        let filename = "./cjp2p/metadata/".to_owned() + &id + ".json";
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(false)
            .open(filename)
            .unwrap();

        let peers: &mut HashSet<SocketAddr> = &mut HashSet::new();
        if file.metadata().unwrap().len() > 0 {
            let json: serde_json::Value = serde_json::from_reader(BufReader::new(&file)).unwrap();
            let loaded_peers: HashSet<SocketAddr> =
                serde_json::from_value(json["Peers"].clone()).unwrap();
            peers.extend(loaded_peers);
        }
        if peers.insert(*src) {
            file.seek(SeekFrom::Start(0)).ok();
            serde_json::to_writer_pretty(BufWriter::new(file), &json!({"Peers":&peers})).unwrap();
        }
        peers.remove(&src);
        if peers.len() == 0 {
            return vec![];
        }
        let at_most = 3 + 45 * !might_be_ip_spoofing as usize;

        // TODO check peer_map, unless im already saving those to disk
        return vec![Message::MaybeTheyHaveSome(MaybeTheyHaveSome {
            id: id.to_owned(),
            peers: peers.iter().take(at_most).cloned().collect(),
        })];
    }
    pub fn send_content_peers(&self, might_be_ip_spoofing: bool, src: SocketAddr) -> Vec<Message> {
        debug!("{} sending peers", self.id);
        let at_most = 3 + 45 * !might_be_ip_spoofing as usize;
        let mut peers: HashSet<SocketAddr> = self.peers.iter().take(at_most).cloned().collect();
        peers.remove(&src);
        if peers.len() == 0 {
            return vec![];
        }
        return vec![Message::MaybeTheyHaveSome(MaybeTheyHaveSome {
            id: self.id.clone(),
            peers: peers,
        })];
    }
    pub fn finished(&mut self) -> bool {
        // yes this could sha as it goes, but then its not testing as much as it could, for
        // little real improvement, so dont do that
        if self.bytes_complete != self.eof {
            return false;
        }
        let mut hasher = Sha256::new();
        info!("{} starting sha256sum", self.id);
        hasher.update(self.mmap.as_mut().unwrap());
        let hash = format!("{:x}", hasher.finalize());
        info!("{} sha256sum", hash);
        if hash == self.id.to_lowercase() {
            info!("{0} finished {1} bytes", self.id, self.eof);
            println!("{0} finished {1} bytes", self.id, self.eof);
            let path = "./incoming/".to_owned() + &self.id;
            let new_path = "./cjp2p/public/".to_owned() + &self.id;
            fs::rename(path, new_path).unwrap();
            self.save_content_peers();
            return true;
        }
        error!("{} hash doesnt match! restarting", self.id);
        self.hash_failures += 1;
        if self.hash_failures > 2 {
            error!("{} hash failed 3 times, giving up!", self.id);
            return true;
        }

        self.bitmap.fill(false);
        self.mmap = None;
        self.next_block = 0;
        self.bytes_complete = 0;
        return false;
    }
    pub fn serve_http_if_any_is_ready(&mut self) -> bool {
        if self.http_socket.is_none() {
            return true;
        }
        if self.eof < self.http_end {
            self.http_end = self.eof;
        }
        if self.bitmap[(self.http_start / BLOCK_SIZE!())..((self.http_end + 4095) / BLOCK_SIZE!())]
            .first_zero()
            .is_some()
        {
            return false;
        }
        let waited = self.http_time.elapsed();
        if waited > Duration::from_millis(120) {
            warn!("\x1b[7;31m {} relaying inbound state to http {} {} THEY WAITED {:?}\x1b[m",self.id,self.http_start ,self.http_end,waited);
        } else if waited > Duration::from_millis(60) {
            info!("{} relaying inbound state to http {} {} THEY WAITED {:?}\x1b[m",self.id,self.http_start ,self.http_end,waited);
        } else if waited > Duration::from_millis(2) {
            debug!("{} relaying inbound state to http {} {} THEY WAITED {:?}\x1b[m",self.id,self.http_start ,self.http_end,waited);
        }
        let mut response = format!(
                            "HTTP/1.1 206 Partial Content\r\n\
                             Content-Length: {}\r\n\
                             Content-Disposition: inline\r\n\
                            Content-Range: bytes {}-{}/{}\r\n"
            ,self.http_end-self.http_start,self.http_start,self.http_end-1, self.eof);
        match infer::get_from_path("incoming/".to_string() + &self.id) {
            Ok(Some(t)) => response += &format!("Content-Type: {}\r\n",t.mime_type()),
            _ => warn!("HTTP unknown mime type for {}",&self.id),
        }
        response += "\r\n";
        debug!("http response {}",response);
        self.http_socket
            .as_mut()
            .unwrap()
            .write_all(response.as_bytes())
            .ok();
        self.http_socket
            .as_mut()
            .unwrap()
            .write_all(&self.mmap.as_mut().unwrap()[self.http_start..self.http_end])
            .ok();
        self.http_socket = None;
        return true;
    }
}

pub fn maintenance(inbound_states: &mut HashMap<String, InboundState>, ps: &mut PeerState) -> () {
    ps.sort();
    if Utc::now().second() / 3 + (Utc::now().minute() % 5) == 0 {
        ps.save_peers();
        ps.p.save();
    }
    ps.probe_interfaces();
    ps.probe();
    ps.open_file_cache = HashMap::new(); // clear the cache
    for (_, i) in inbound_states.iter_mut() {
        if i.last_activity.elapsed() <= Duration::from_secs(1) {
            continue;
        }
        if i.next_block != 0 {
            debug!("stalled {}", i.id);
        }
        i.next_block = 0;
    }
    for (_, i) in inbound_states.iter_mut() {
        if i.last_activity.elapsed() <= Duration::from_secs(1) {
            continue;
        }
        debug!("restarting {}", i.id);
        i.request_blocks(ps, i.peers.clone()); // resume (un-stall)
        i.request_blocks(ps, ps.best_peers(50, 6));
        if rand::thread_rng().gen::<u32>() % 2 == 0 {
            break;
        }
    }
    if ps.list_time + Duration::from_secs(1) < Instant::now() {
        let mut sorted_list_results: Vec<_> = ps.list_results.iter().collect();
        sorted_list_results.sort_by_key(|&(_, b)| b.0);
        for (k, v) in &sorted_list_results {
            println!("{} {} {}",v.0,k,v.1);
        }
        ps.list_time += Duration::from_secs(60 * 60 * 24 * 365 * 99);
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MaybeTheyHaveSome {
    pub id: String,
    pub peers: HashSet<SocketAddr>,
}

impl Receive for MaybeTheyHaveSome {
    fn receive(
        self,
        ps: &mut PeerState,
        _: SocketAddr,
        _: bool,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if !inbound_states.contains_key(&self.id) {
            return vec![];
        }
        let i = inbound_states.get_mut(&self.id).unwrap();
        for p in self.peers {
            if i.peers.insert(p) {
                // new possible source? try it
                i.request_blocks(ps, HashSet::from([p]));
            }
        }
        return vec![];
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct PleaseReturnThisMessage {
    pub cookie: String,
}
impl Receive for PleaseReturnThisMessage {
    fn receive(
        self,
        _: &mut PeerState,
        _: SocketAddr,
        _: bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        vec![Message::ReturnedMessage(ReturnedMessage { cookie: self.cookie, })]
    }
}
impl PleaseReturnThisMessage {
    pub fn new(ps: &PeerState) -> Message {
        Message::PleaseReturnThisMessage(Self {
            cookie: ps.boot.elapsed().as_secs_f64().to_string(),
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReturnedMessage {
    pub cookie: String,
}
impl Receive for ReturnedMessage {
    fn receive(
        self,
        ps: &mut PeerState,
        src: SocketAddr,
        _: bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        match ps.peer_map.get_mut(&src) {
            Some(peer) => {
                peer.delay =
                    (ps.boot + Duration::from_secs_f64(self.cookie.parse().unwrap())).elapsed();
                trace!("measured {0} at {1}", src, peer.delay.as_secs_f64())
            }
            _ => (),
        };
        return vec![];
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct MyPublicKey {
    #[serde_as(as = "Base64")]
    pub ed25519: Vec<u8>,
}
impl Receive for MyPublicKey {
    fn receive(
        self,
        ps: &mut PeerState,
        src: SocketAddr,
        _: bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        ps.peer_map.get_mut(&src).unwrap().ed25519 = Some(self.ed25519.clone());
        return vec![];
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChatMessage {
    pub message: String,
}
impl ChatMessage {
    pub fn new(ps: &PeerState, src: SocketAddr, message: String) -> Vec<Message> {
        let mut message_out = vec![
            PleaseReturnThisMessage::new(ps),
            Message::MyPublicKey(MyPublicKey { ed25519: ps.keypair.public.clone(), }),
            Message::ChatMessage(Self { message: message }),
        ];
        if let Some(their_pub) = &ps.peer_map[&src].ed25519 {
            message_out = vec![
                EncryptedMessages::new(their_pub, src, serde_json::to_vec(&message_out).unwrap()),
                ];
        }
        return message_out;
    }
}
impl Receive for ChatMessage {
    fn receive(
        self,
        ps: &mut PeerState,
        src: SocketAddr,
        _: bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        println!("\x1b[7m{} {src} 0x{} from {:?} away said \x07\x1b[33m{}\x1b[m",
            Utc::now().to_rfc3339(),
            hex::encode(&ps.peer_map[&src].ed25519.clone().unwrap_or_default()),
            ps.peer_map[&src].delay,
            self.message
        );
        if self.message.starts_with("/version") {
            return Self::new(
                ps,
                src,
                format!("VERSION Rust {}\n",env!("CARGO_PKG_VERSION")),
            );
        }
        if self.message.starts_with("/ping") {
            return Self::new(ps, src, "PONG\n".to_string());
        }
        return vec![];
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct PleaseListContent {}
impl Receive for PleaseListContent {
    fn receive(
        self,
        _: &mut PeerState,
        _: SocketAddr,
        might_be_ip_spoofing: bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        let mut results: Vec<(String, u64)> = vec![];
        for path in fs::read_dir("./cjp2p/public").unwrap() {
            let p = path.unwrap().path();
            let length = File::open(&p).unwrap().metadata().unwrap().len();
            if p.file_name().unwrap().len() != 64 || length == 1 << 18 {
                continue;
            }
            results.push((p.file_name().unwrap().to_str().unwrap().to_string(), length));
            if results.len() > 70 * !might_be_ip_spoofing as usize + 1 {
                break;
            }
        }
        if results.len() == 0 {
            return vec![];
        }
        return vec![
            Message::ContentList(ContentList { results: results }),
        ];
    }
}
impl PleaseListContent {
    pub fn new(ps: &PeerState) -> Vec<Message> {
        let message_out = vec![
            PleaseReturnThisMessage::new(ps),
            Message::PleaseListContent(Self {}),
        ];
        return message_out;
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ContentList {
    pub results: Vec<(String, u64)>,
}
impl Receive for ContentList {
    fn receive(
        self,
        ps: &mut PeerState,
        src: SocketAddr,
        _: bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        // TODO call maybetheyhavesome?
        for (id, size) in &self.results {
            trace!("\x1b[7m{} {src} 0x{} from {:?} has \x07\x1b[32m{:?}\x1b[m",
            Utc::now().to_rfc3339(),
            hex::encode(&ps.peer_map[&src].ed25519.clone().unwrap_or_default()),
            ps.peer_map[&src].delay,
            self.results
        );
            match ps.list_results.get_mut(&id.to_owned()) {
                Some(h) => h.0 += 1,
                None => {
                    ps.list_results.insert(id.to_owned(), (1, *size));
                    ()
                }
            }
        }
        return vec![];
    }
}
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedMessages {
    #[serde_as(as = "Base64")]
    pub base64: Vec<u8>,
    pub noise_params: String,
}
impl EncryptedMessages {
    pub fn new(their_pub: &Vec<u8>, src: SocketAddr, message: Vec<u8>) -> Message {
        let mut noise = Builder::new(NOISE_PARAMS.parse().unwrap())
            .remote_public_key(their_pub)
            .build_initiator()
            .unwrap();
        let mut buf = [0u8; 99999];
        let len = noise.write_message(&message, &mut buf).unwrap();
        let message_out = Message::EncryptedMessages(Self {
            base64: buf[..len].to_vec(),
            noise_params: NOISE_PARAMS.to_string(),
        });
        trace!("sending encrypted msg to {src}");
        return message_out;
    }
}
impl Receive for EncryptedMessages {
    fn receive(
        self,
        ps: &mut PeerState,
        src: SocketAddr,
        mut might_be_ip_spoofing: bool,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        let mut noise = Builder::new(NOISE_PARAMS.parse().unwrap())
            .local_private_key(&ps.keypair.private)
            .build_responder()
            .unwrap();
        let mut buf = [0u8; 99999];
        if let Ok(len) = noise.read_message(&self.base64, &mut buf) {
            trace!("handling decrypted message from {src}: {}",
             String::from_utf8_lossy(&buf[..len]));
            let messages = serde_json::from_slice(&buf[..len]).unwrap();
            might_be_ip_spoofing &= ps.check_key(&messages, src);
            return ps.handle_messages(messages, src, might_be_ip_spoofing, inbound_states);
        } else {
            info!("failed to decrypt a message from {src}");
        }
        return vec![];
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[enum_dispatch]
pub enum Message {
    PleaseSendPeers(PleaseSendPeers),
    Peers(Peers),
    PleaseSendContent(PleaseSendContent),
    Content(Content),
    PleaseReturnThisMessage(PleaseReturnThisMessage),
    ReturnedMessage(ReturnedMessage),
    MaybeTheyHaveSome(MaybeTheyHaveSome),
    PleaseAlwaysReturnThisMessage(PleaseAlwaysReturnThisMessage),
    AlwaysReturned(AlwaysReturned),
    MyPublicKey(MyPublicKey),
    ChatMessage(ChatMessage),
    EncryptedMessages(EncryptedMessages),
    PleaseListContent(PleaseListContent),
    ContentList(ContentList),
    YouSouldSeeThis(YouSouldSeeThis),
    IJustSawThis(IJustSawThis),
}

// this struct only exists to be able to get that VecSkipError in there.
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct Messages(#[serde_as(as = "VecSkipError<_,ErrorInspector>")] Vec<Message>);

pub struct ErrorInspector;

impl InspectError for ErrorInspector {
    fn inspect_error(error: impl serde::de::Error) {
        warn!( "could not deserialize an incoming message {error}");
    }
}

#[enum_dispatch(Message)]
trait Receive {
    fn receive(
        self,
        ps: &mut PeerState,
        src: SocketAddr,
        might_be_ip_spoofing: bool,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message>;
}
