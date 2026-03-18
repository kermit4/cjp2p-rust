//use base64::{engine::general_purpose, Engine as _};
use bitvec::prelude::*;
use chrono::{Timelike, Utc};
use env_logger::fmt::TimestampPrecision;
use hex;
use log::{debug, error, info, log_enabled, trace, warn, Level};
use memmap2::MmapMut;
use nix::NixPath;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::{base64::Base64, serde_as, InspectError, VecSkipError};
use sha2::{Digest, Sha256};
use snow::Builder;
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
//use std::convert::TryInto;
use std::env;
//use std::fmt;
use std::f64;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
//use std::io::copy;
use nix::sys::select::{select, FdSet};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
//use std::path::Path;
use rand::Rng;
use scanf::sscanf;
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};
use std::vec;
use std::{io, str};
const NOISE_PARAMS: &str = "Noise_NK_25519_AESGCM_SHA256";

macro_rules! BLOCK_SIZE {
    () => {
        0x1000 // 4k
    };
}

// when this gets to millions of peers, consider keeping less info about the slower ones
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
struct PeerInfo {
    delay: Duration,
    anti_ip_spoofing_cookie_they_expect: Option<String>,
    #[serde_as(as = "Option<Base64>")]
    ed25519: Option<Vec<u8>>,
    you_should_see_this: Option<YouSouldSeeThis>,
    i_just_saw_this: Option<IJustSawThis>,
}
impl PeerInfo {
    fn new() -> Self {
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
struct OpenFile {
    file: File,
    eof: usize,
}
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct Keypair {
    #[serde_as(as = "Base64")]
    public: Vec<u8>,
    #[serde_as(as = "Base64")]
    private: Vec<u8>,
}
impl Keypair {
    fn load_key() -> Keypair {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open("state/key.json");
        if file.as_ref().is_ok() && file.as_ref().unwrap().metadata().unwrap().len() > 0 {
            let saved: Keypair = serde_json::from_reader(&file.unwrap()).unwrap();
            return Keypair {
                public: saved.public,
                private: saved.private,
            };
        } else {
            let keypair_ = Builder::new(NOISE_PARAMS.parse().unwrap())
                .generate_keypair()
                .unwrap();
            let keypair = Keypair {
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

struct PeerState {
    peer_map: HashMap<SocketAddr, PeerInfo>,
    peer_vec: Vec<SocketAddr>,
    socket: UdpSocket,
    boot: Instant,
    keypair: Keypair,
    open_file_cache: HashMap<String, OpenFile>,
    list_results: HashMap<String, (i32, u64)>,
    list_time: Instant,
    you_should_see_this: Option<YouSouldSeeThis>,
    i_just_saw_this: Option<IJustSawThis>,
}
impl PeerState {
    fn new() -> Self {
        let mut ps = Self {
            peer_map: HashMap::new(),
            peer_vec: Vec::new(),
            socket: UdpSocket::bind("0.0.0.0:24254").unwrap(),
            boot: Instant::now(),
            keypair: Keypair::load_key(),
            open_file_cache: HashMap::new(),
            list_results: HashMap::new(),
            list_time: Instant::now(),
            you_should_see_this: None,
            i_just_saw_this: None,
        };
        ps.socket.set_broadcast(true).ok();
        ps.socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        for p in ["148.71.89.128:24254", "159.69.54.127:24254"] {
            ps.peer_map.insert(p.parse().unwrap(), PeerInfo::new());
        }
        ps.load_peers();
        return ps;
    }
    fn save_key(&mut self, src: SocketAddr, cookie: String) -> Vec<Message> {
        trace!("saving cookie {cookie} for {src}");
        self.peer_map
            .get_mut(&src)
            .unwrap()
            .anti_ip_spoofing_cookie_they_expect = Some(cookie);
        return vec![];
    }
    fn hash_ip(&self, src: SocketAddr) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.keypair.private[..8]);
        hasher.update(src.ip().to_string());
        return format!("{:x}", hasher.finalize())[..8].to_string();
    }

    fn check_key(&self, messages: &Vec<Message>, src: SocketAddr) -> bool {
        for message_in in messages {
            if let Message::AlwaysReturned(m) = message_in {
                let correct_hash = self.hash_ip(src);
                return correct_hash != m.cookie;
            }
        }
        return true;
    }
    fn please_always_return(&self, src: SocketAddr) -> Message {
        let correct_hash = self.hash_ip(src);
        return Message::PleaseAlwaysReturnThisMessage(PleaseAlwaysReturnThisMessage {
            cookie: correct_hash,
        });
    }

    fn always_returned(&self, sa: SocketAddr) -> Vec<Message> {
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

    fn probe_interfaces(&mut self) -> () {
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
    fn probe(&mut self) -> () {
        for sa in self.best_peers(10, 3) {
            let peer_info = self.peer_map.get_mut(&sa).unwrap();
            peer_info.delay = peer_info.delay.saturating_add(peer_info.delay / 20);
            let mut message_out: Vec<Message> = Vec::new();
            message_out.push(Message::PleaseSendPeers(PleaseSendPeers {}));
            // let people know im here
            // im not sure if anyone cares about all this info from completely random contacts
            message_out.push(self.please_always_return(sa));
            if let Some(i_just_saw_this) = &self.i_just_saw_this {
                message_out.push(Message::IJustSawThis(i_just_saw_this.clone()));
            }
            if let Some(you_should_see_this) = &self.you_should_see_this {
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

    fn sort(&mut self) -> () {
        let mut peers: Vec<_> = self
            .peer_map
            .iter()
            .map(|(k, v)| (k, v.delay.as_secs_f64()))
            .collect();
        peers.sort_unstable_by(|a, b| a.1.total_cmp(&b.1));
        self.peer_vec = peers.into_iter().map(|(addr, _)| *addr).collect();
    }

    fn load_peers(&mut self) -> () {
        let file = OpenOptions::new().read(true).open("state/peers.v6.json");
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
        // not really sure how many, if any, of these peers or fields should be saved, or just a PleaseListContent of host:ips, but for the few users (1) of this so far, might as well save it all
        let mut peers_to_save: Vec<(SocketAddr, PeerInfo)> = Vec::new();
        for i in 0..cmp::min(self.peer_vec.len(), 99) {
            peers_to_save.push((self.peer_vec[i], self.peer_map[&self.peer_vec[i]].clone()))
        }

        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("state/peers.v6.json")
            .unwrap()
            .write_all(&serde_json::to_vec_pretty(&peers_to_save).unwrap())
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
            result.insert(*p);
            trace!( "best peer(q:{quality}) {0} {1} {2}", i, p, self.peer_map[p].delay.as_secs_f64());
        }
        result.clone()
    }
    fn handle_messages(
        &mut self,
        messages: Vec<Message>,
        src: SocketAddr,
        might_be_ip_spoofing: bool,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        let mut message_out = vec![];
        for message_in_enum in messages {
            message_out.append(&mut match message_in_enum {
                // checked before this loop because we want to know first if the source IP is
                // verified
                Message::AlwaysReturned(_) => vec![],

                Message::PleaseSendPeers(t) => t.send_peers(&self, might_be_ip_spoofing, src),
                Message::Peers(t) => t.receive_peers(self),
                Message::PleaseSendContent(t) =>
                    t.send_content(inbound_states, src, might_be_ip_spoofing, self),
                Message::Content(t) => t.receive_content(inbound_states, src, self),
                Message::ReturnedMessage(t) => t.update_round_trip_time(self, src),
                Message::MaybeTheyHaveSome(t) =>
                    t.add_content_peer_suggestions(self, inbound_states),
                Message::MyPublicKey(t) => t.save_public_key(self, src),
                Message::IJustSawThis(t) => {
                    if !might_be_ip_spoofing && src.port() == 24254 {
                        self.peer_map.get_mut(&src).unwrap().i_just_saw_this = Some(t);
                    }
                    vec![]
                }
                Message::YouSouldSeeThis(t) => {
                    if !might_be_ip_spoofing && src.port() == 24254 {
                        self.peer_map.get_mut(&src).unwrap().you_should_see_this = Some(t);
                    }
                    vec![]
                }
                Message::ChatMessage(t) => t.receive(self, src),
                Message::PleaseListContent(t) => t.receive(self, src, might_be_ip_spoofing),
                Message::ContentList(t) => t.receive(self, src),
                Message::PleaseAlwaysReturnThisMessage(t) => self.save_key(src, t.cookie.clone()),
                Message::PleaseReturnThisMessage(t) =>
                    vec![Message::ReturnedMessage(ReturnedMessage { cookie: t.cookie, })],
                Message::EncryptedMessages(t) =>
                    t.receive(self, src, might_be_ip_spoofing, inbound_states),
            })
        }
        return message_out;
    }
}

#[derive(Debug)]
struct HttpRequest {
    path: String,
    headers: HashMap<String, String>,
}

fn parse_header(stream: &mut TcpStream) -> Option<HttpRequest> {
    let mut buf = [0; 4096];
    let len = stream.read(&mut buf).ok()?;
    let request_str = String::from_utf8_lossy(&buf[..len]);

    let mut lines = request_str.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();

    let _ = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(": ") {
            headers.insert(key.to_lowercase(), value.to_string());
        }
    }

    Some(HttpRequest { path, headers })
}

fn main() -> Result<(), std::io::Error> {
    fs::create_dir("./shared").ok();
    std::env::set_current_dir("./shared").unwrap();
    fs::create_dir("./metadata").ok();
    fs::create_dir("./state").ok();
    env_logger::builder()
        .format_timestamp(Some(TimestampPrecision::Millis))
        .init();
    println!("logging level: {}", log::max_level());
    let mut ps: PeerState = PeerState::new();
    let web_server = TcpListener::bind("0.0.0.0:24254").unwrap();
    println!("your ed25519 public key, stored in shared/state/key.json, is:  0x{}",hex::encode(&ps.keypair.public));
    let mut args = env::args();
    args.next();
    let mut inbound_states: HashMap<String, InboundState> = HashMap::new();
    for v in args {
        info!("queing inbound file {:?}", v);
        inbound_states.insert(v.to_string(), InboundState::new(&v, &ps));
    }
    let mut next_maintenance = Instant::now() - Duration::from_secs(99999);

    loop {
        let mut read_fds = FdSet::new();
        if next_maintenance.elapsed() > Duration::ZERO {
            maintenance(&mut inbound_states, &mut ps);
            next_maintenance =
                Instant::now() + Duration::from_millis(rand::thread_rng().gen_range(1111..1234));
        }
        read_fds.insert(ps.socket.as_fd());
        read_fds.insert(web_server.as_fd());
        let stdin = std::io::stdin();
        read_fds.insert(stdin.as_fd());

        match select(
            None,
            &mut read_fds,
            None,
            None,
            &mut (nix::sys::time::TimeVal::new(1, 0)),
        ) {
            Ok(n) => {
                trace!("select: {n}");
            }
            Err(e) => {
                warn!("select {:?}",e);
                continue;
            }
        }

        if read_fds.contains(stdin.as_fd()) {
            handle_stdin(&mut ps, &mut inbound_states);
        } else if read_fds.contains(web_server.as_fd()) {
            handle_web_request(&web_server, &mut inbound_states, &ps);
        } else if read_fds.contains(ps.socket.as_fd()) {
            handle_network(&mut ps, &mut inbound_states);
        }
    }
}
fn handle_stdin(ps: &mut PeerState, inbound_states: &mut HashMap<String, InboundState>) {
    let mut line = String::new();
    io::stdin().read_line(&mut line).unwrap();
    if line.len() > 1 {
        let mut arg: String = "".to_string();
        let mut arg2: String = "".to_string();
        if sscanf!(line.as_str(), "/get {}",arg).is_ok() {
            ps.i_just_saw_this = Some(IJustSawThis {
                id: arg.to_owned(),
                length: File::open(&arg).unwrap().metadata().unwrap().len(),
            });
            println!("QUEING FILE {arg}");
            inbound_states.insert(arg.clone(), InboundState::new(&arg, &ps));
        } else if sscanf!(line.as_str(), "/msg 0x{} {}",arg,arg2).is_ok() {
            let to = hex::decode(&arg).unwrap();
            let mut who: HashSet<SocketAddr> = HashSet::new();
            for (k, v) in &ps.peer_map {
                if let Some(key) = &v.ed25519 {
                    if *key == to {
                        who.insert(*k);
                    }
                }
            }
            if who.len() > 0 {
                let message_out =
                    ChatMessage::new(&ps, who.clone().into_iter().next().unwrap(), arg2.clone());
                if let Message::EncryptedMessages(_) = message_out[0] {
                    let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
                    trace!( "sending message {:?} to {arg}", String::from_utf8_lossy(&message_out_bytes));
                    for sa in who {
                        ps.socket.send_to(&message_out_bytes, sa).ok();
                    }
                } else {
                    println!("refusing to send unencrypted 1:1 message.  This probably shouldn't happen.");
                }
            } else {
                println!("not found");
            }
        } else if sscanf!(line.as_str(), "/msg {} {}",arg,arg2).is_ok() {
            let message_out = ChatMessage::new(&ps, arg.parse().unwrap(), arg2.clone());
            if let Message::EncryptedMessages(_) = message_out[0] {
                let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
                trace!( "sending message {:?} to {arg}", String::from_utf8_lossy(&message_out_bytes));
                ps.socket.send_to(&message_out_bytes, arg).ok();
            } else {
                warn!("refusing to send unencrypted 1:1 message.  This probably shouldn't happen.");
            }
        } else if line == "/peers\n" {
            for v in &ps.peer_vec[..33] {
                println!("{} {:?}",v,ps.peer_map[v].delay);
            }
            println!("{} total peers",ps.peer_map.len());
            let mut count = 0;
            let mut unique_ips = HashSet::new();
            for (k, _) in &ps.peer_map {
                if unique_ips.insert(k.ip()) {
                    count += 1;
                }
            }
            println!("{} total unique IP peers",count);
        } else if sscanf!(line.as_str(), "/recommend {}",arg).is_ok() {
            ps.you_should_see_this = Some(YouSouldSeeThis {
                id: arg.to_owned(),
                length: File::open(&arg).unwrap().metadata().unwrap().len(),
            });
        } else if line == "/trending\n" {
            let mut trending: HashMap<String, (i32, u64)> = HashMap::new();
            for (_, v) in &ps.peer_map {
                if let Some(p) = &v.i_just_saw_this {
                    match trending.get_mut(&p.id) {
                        Some(h) => h.0 += 1,
                        None => {
                            trending.insert(p.id.to_owned(), (1, p.length));
                            ()
                        }
                    }
                }
            }
            let mut sorted_list_results: Vec<_> = trending.iter().collect();
            sorted_list_results.sort_by_key(|&(_, b)| b.0);
            for (k, v) in &sorted_list_results {
                println!("{} {} {}",v.0,k,v.1);
            }
        } else if line == "/recommended\n" {
            let mut highly_recommended_content: HashMap<String, (i32, u64)> = HashMap::new();
            for (_, v) in &ps.peer_map {
                if let Some(p) = &v.you_should_see_this {
                    match highly_recommended_content.get_mut(&p.id) {
                        Some(h) => h.0 += 1,
                        None => {
                            highly_recommended_content.insert(p.id.to_owned(), (1, p.length));
                            ()
                        }
                    }
                }
            }
            let mut sorted_list_results: Vec<_> = highly_recommended_content.iter().collect();
            sorted_list_results.sort_by_key(|&(_, b)| b.0);
            for (k, v) in &sorted_list_results {
                println!("{} {} {}",v.0,k,v.1);
            }
        } else if line == "/list\n" {
            ps.list_results = HashMap::new();
            ps.list_time = Instant::now();
            println!("searching");
            for sa in &ps.peer_vec {
                let mut message_out = ps.always_returned(*sa);
                for v in PleaseListContent::new(&ps) {
                    message_out.push(v);
                }
                let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
                trace!( "sending message {:?} to {sa}", String::from_utf8_lossy(&message_out_bytes));
                ps.socket.send_to(&message_out_bytes, sa).ok();
            }
        } else {
            for sa in ps.best_peers(100, 5) {
                let message_out = ChatMessage::new(&ps, sa, line.clone());
                let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
                trace!( "sending message {:?} to {sa}", String::from_utf8_lossy(&message_out_bytes));
                ps.socket.send_to(&message_out_bytes, sa).ok();
            }
        }
    }
}
fn handle_web_request(
    web_server: &TcpListener,
    inbound_states: &mut HashMap<String, InboundState>,
    ps: &PeerState,
) {
    if let Ok((mut stream, _)) = web_server.accept() {
        if let Some(req) = parse_header(&mut stream) {
            let mut start: usize = 0;
            let mut end: usize = 0;
            if let Some(range) = req.headers.get("range") {
                info!("got ranged http req {} range {:?}",req.path,range);
                sscanf!(range, "bytes={}-{}",start,end).ok();
            } else {
                info!("got unranged http req {} {:?} ",req.path,req.headers);
            }

            let id = &req.path[1..];
            if id.find("/") != None || id.find("\\") != None || id == "favicon.ico" {
                return;
            }
            debug!("http start end {start} {end}");
            if end == 0 {
                end = start + 0x40000;
            }

            if let Ok(file) = File::open(&id) {
                let mut buf = vec![0; end-start ];
                let length = file.read_at(&mut buf, start as u64).unwrap();
                let mut response = format!(
                            "HTTP/1.1 206 Partial Content\r\n\
                             Content-Length: {}\r\n\
                            Content-Range: bytes {}-{}/{}\r\n"
                            ,length,start,start+length-1,
                            file.metadata().unwrap().len());
                match infer::get_from_path(&id) {
                    Ok(Some(t)) => response += &format!("Content-Type: {}\r\n",t.mime_type()),
                    _ => warn!("HTTP unknown mime type for {}",&id),
                }
                response += "\r\n";
                debug!("http response {}",response);
                //stream.set_write_timeout(Some(Duration::new(1, 0)))?
                // it should fit in the buffer though
                stream.write_all(response.as_bytes()).ok();
                stream.write_all(&buf).ok();
            } else {
                let i = match inbound_states.get_mut(id) {
                    Some(i) => i,
                    _ => {
                        let new_i = InboundState::new(id, &ps);
                        info!("http queing inbound file {:?}", id);
                        inbound_states.insert(id.to_string(), new_i);
                        inbound_states.get_mut(id).unwrap()
                    }
                };
                i.http_time = Instant::now();
                i.http_start = start;
                i.http_end = end;
                i.http_socket = Some(stream);
                if i.eof >= i.http_end && !i.serve_http_if_any_is_ready() {
                    info!("http scheduling inbound file {:?}", id);
                    i.next_block = start as usize / BLOCK_SIZE!();
                    for _ in 1..9 {
                        i.request_blocks(ps, i.peers.clone());
                    }
                }

                //but now we have to block but not block until content is hree if its not
                // but why if  im doing 256k blocks anyway, or b locks of 256k blocks
                //bit its still sorta the same, the bits are just 256k not 4k
                //so write it and add the layer in after
                //if each seek needs 256k though and the window is 0.. thats like 1.5s
                //seek.ok display before done, just dont RELAY before done.
                //but if its in motion, no, our window is huge
            }
        }
    }
}

fn handle_network(ps: &mut PeerState, inbound_states: &mut HashMap<String, InboundState>) {
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
fn trim_reply(message_out: &mut Vec<Message>, message_in_length: usize) {
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
struct Peers {
    peers: HashSet<SocketAddr>,
}
#[derive(Serialize, Deserialize, Debug)]
struct AlwaysReturned {
    cookie: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PleaseAlwaysReturnThisMessage {
    cookie: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PleaseSendPeers {}
impl PleaseSendPeers {
    fn send_peers(
        &self,
        ps: &PeerState,
        might_be_ip_spoofing: bool,
        src: SocketAddr,
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

impl Peers {
    fn receive_peers(&self, ps: &mut PeerState) -> Vec<Message> {
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
struct IJustSawThis {
    id: String,
    length: u64,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
struct YouSouldSeeThis {
    id: String,
    length: u64,
}
#[derive(Serialize, Deserialize, Debug)]
struct PleaseSendContent {
    id: String,
    length: usize,
    offset: usize,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct Content {
    id: String,
    offset: usize,
    #[serde_as(as = "Base64")]
    base64: Vec<u8>,
    eof: Option<usize>,
}

impl PleaseSendContent {
    fn new_messages(i: &mut InboundState) -> Vec<Message> {
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
    fn send_content(
        &self,
        inbound_states: &mut HashMap<String, InboundState>,
        src: SocketAddr,
        might_be_ip_spoofing: bool,
        ps: &mut PeerState,
    ) -> Vec<Message> {
        if self.id.find("/") != None || self.id.find("\\") != None {
            return vec![];
        };
        let mut message_out: Vec<Message> = Vec::new();
        if let Some(i) = inbound_states.get_mut(&self.id) {
            i.peers.insert(src);
            message_out.append(&mut i.send_content_peers(might_be_ip_spoofing, src));
        } else {
            message_out.append(&mut Content::new_messages(&self, might_be_ip_spoofing, ps));
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
    fn new_messages(
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
        } else if let Ok(file) = File::open(&req.id) {
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
    fn receive_content(
        &self,
        inbound_states: &mut HashMap<String, InboundState>,
        src: SocketAddr,
        ps: &mut PeerState,
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
struct InboundState {
    mmap: Option<MmapMut>,
    next_block: usize,
    bitmap: BitVec,
    id: String,
    eof: usize,
    bytes_complete: usize,
    peers: HashSet<SocketAddr>,
    last_activity: Instant,
    hash_failures: i32,
    http_time: Instant,
    http_start: usize,
    http_end: usize,
    http_socket: Option<TcpStream>,
}

impl InboundState {
    fn new(id: &str, ps: &PeerState) -> Self {
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
        let block_number = content.offset / BLOCK_SIZE!();
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

    fn request_blocks(&mut self, ps: &PeerState, some_peers: HashSet<SocketAddr>) {
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
            debug!( "sending message {:?} to {sa}", String::from_utf8_lossy(&message_out_bytes)
            );
            ps.socket.send_to(&message_out_bytes, sa).ok();
        }
    }
    fn save_content_peers(&self) -> () {
        debug!("saving inbound state peers");
        let filename = "./metadata/".to_owned() + &self.id + ".json";
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
    fn send_content_peers_from_disk(
        id: &String,
        might_be_ip_spoofing: bool,
        src: &SocketAddr,
    ) -> Vec<Message> {
        let filename = "./metadata/".to_owned() + &id + ".json";
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
    fn send_content_peers(&self, might_be_ip_spoofing: bool, src: SocketAddr) -> Vec<Message> {
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
    fn finished(&mut self) -> bool {
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
            let new_path = "./".to_owned() + &self.id;
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
    fn serve_http_if_any_is_ready(&mut self) -> bool {
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

fn maintenance(inbound_states: &mut HashMap<String, InboundState>, ps: &mut PeerState) -> () {
    ps.sort();
    if Utc::now().second() / 3 + (Utc::now().minute() % 5) == 0 {
        ps.save_peers();
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
struct MaybeTheyHaveSome {
    id: String,
    peers: HashSet<SocketAddr>,
}

impl MaybeTheyHaveSome {
    fn add_content_peer_suggestions(
        self,
        ps: &mut PeerState,
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
struct PleaseReturnThisMessage {
    cookie: String,
}
impl PleaseReturnThisMessage {
    fn new(ps: &PeerState) -> Message {
        Message::PleaseReturnThisMessage(Self {
            cookie: ps.boot.elapsed().as_secs_f64().to_string(),
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ReturnedMessage {
    cookie: String,
}
impl ReturnedMessage {
    fn update_round_trip_time(&self, ps: &mut PeerState, src: SocketAddr) -> Vec<Message> {
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
struct MyPublicKey {
    #[serde_as(as = "Base64")]
    ed25519: Vec<u8>,
}
impl MyPublicKey {
    fn save_public_key(&self, ps: &mut PeerState, src: SocketAddr) -> Vec<Message> {
        ps.peer_map.get_mut(&src).unwrap().ed25519 = Some(self.ed25519.clone());
        return vec![];
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ChatMessage {
    message: String,
}
impl ChatMessage {
    fn new(ps: &PeerState, src: SocketAddr, message: String) -> Vec<Message> {
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
    fn receive(&self, ps: &mut PeerState, src: SocketAddr) -> Vec<Message> {
        println!("\x1b[7m{} {src} 0x{} from {:?} away said \x07\x1b[33m{}\x1b[m",
            Utc::now().to_rfc3339(),
            hex::encode(&ps.peer_map[&src].ed25519.clone().unwrap_or_default()),
            ps.peer_map[&src].delay,
            self.message
        );
        if self.message.starts_with("/ping") {
            return Self::new(ps, src, "PONG\n".to_string());
        }
        return vec![];
    }
}
#[derive(Serialize, Deserialize, Debug)]
struct PleaseListContent {}
impl PleaseListContent {
    fn new(ps: &PeerState) -> Vec<Message> {
        let message_out = vec![
            PleaseReturnThisMessage::new(ps),
            Message::PleaseListContent(Self {}),
        ];
        return message_out;
    }
    fn receive(
        &self,
        ps: &mut PeerState,
        src: SocketAddr,
        might_be_ip_spoofing: bool,
    ) -> Vec<Message> {
        println!("\x1b[7m{} {src} 0x{} from {:?} away searched\x1b[m",
            Utc::now().to_rfc3339(),
            hex::encode(&ps.peer_map[&src].ed25519.clone().unwrap_or_default()),
            ps.peer_map[&src].delay,
        );
        return ContentList::new(might_be_ip_spoofing);
    }
}
#[derive(Serialize, Deserialize, Debug)]
struct ContentList {
    results: Vec<(String, u64)>,
}
impl ContentList {
    fn new(might_be_ip_spoofing: bool) -> Vec<Message> {
        let mut results: Vec<(String, u64)> = vec![];
        for path in fs::read_dir("./").unwrap() {
            let p = path.unwrap().path();
            let length = File::open(&p).unwrap().metadata().unwrap().len();
            if p.len() != 66 || length == 1 << 18 {
                continue;
            }
            results.push((p.to_string_lossy()[2..].to_string(), length));
            if results.len() > 70 * !might_be_ip_spoofing as usize + 1 {
                break;
            }
        }
        if results.len() == 0 {
            return vec![];
        }
        let message_out = vec![
            Message::ContentList(Self { results: results }),
        ];
        return message_out;
    }
    fn receive(&self, ps: &mut PeerState, src: SocketAddr) -> Vec<Message> {
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
struct EncryptedMessages {
    #[serde_as(as = "Base64")]
    base64: Vec<u8>,
    noise_params: String,
}
impl EncryptedMessages {
    fn new(their_pub: &Vec<u8>, src: SocketAddr, message: Vec<u8>) -> Message {
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
    fn receive(
        &self,
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
enum Message {
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
struct Messages(#[serde_as(as = "VecSkipError<_,ErrorInspector>")] Vec<Message>);

struct ErrorInspector;

impl InspectError for ErrorInspector {
    fn inspect_error(error: impl serde::de::Error) {
        warn!( "could not deserialize an incoming message {error}");
    }
}
