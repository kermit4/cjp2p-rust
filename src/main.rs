use igd::{search_gateway, PortMappingProtocol, SearchOptions};
use socket2::SockRef;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::thread;
use tungstenite::{accept, WebSocket};
//use base64::{engine::general_purpose, Engine as _};
use bitvec::prelude::*;
use chrono::{Timelike, Utc};
use enum_dispatch::enum_dispatch;
use env_logger::fmt::TimestampPrecision;
use hex;
use log::{debug, error, info, log_enabled, trace, warn, Level};
use memmap2::MmapMut;
use std::net::IpAddr;
//use nix::NixPath;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use serde_with::{base64::Base64, serde_as, InspectError, VecSkipError};
use sha2::{Digest, Sha256};
use snow::Builder;
//use std::cmp;
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
use rand::Rng;
use scanf::sscanf;
use std::net::{SocketAddr, UdpSocket};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
use std::time::{Duration, Instant};
use std::vec;
use std::{io, str};
//use base64::{engine::general_purpose, Engine as _};
//use nix::NixPath;
use std::path::Path;
//use std::convert::TryInto;
//use std::fmt;
//use std::io::copy;

const NOISE_PARAMS: &str = "Noise_IK_25519_AESGCM_SHA256";
#[derive(Clone, Serialize, Deserialize, Debug)]
enum Source {
    // <'a> {
    None, // W(&'a WebSocket<TcpStream>), // borrow checker, this really has to be the index, or taken out of peerstate, or maybe just pass the IP/port of the websocket instead of an index, make that the index
    S(SocketAddr),
}

macro_rules! BLOCK_SIZE {
    () => {
        0x1000 // 4k
    };
}

// when this gets to millions of peers, consider keeping less info about the slower ones
use serde_with::hex::Hex;
#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
struct PeerInfo {
    delay: Duration,
    anti_ip_spoofing_cookie_they_expect: Option<String>,
    #[serde_as(as = "Option<Hex>")]
    ed25519: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ed25519_eth_signed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ed25519_eth_signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    you_should_see_this: Option<YouSouldSeeThis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    i_just_saw_this: Option<IJustSawThis>,
}
impl PeerInfo {
    fn new() -> Self {
        return Self {
            delay: Duration::from_millis(200),
            anti_ip_spoofing_cookie_they_expect: None,
            ed25519: None,
            ed25519_eth_signed: None,
            ed25519_eth_signer: None,
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
    public: [u8; 32],
    #[serde_as(as = "Base64")]
    private: [u8; 32],
    public_hex: Option<String>,
    private_hex: Option<String>,
}
impl Keypair {
    fn load_key() -> Self {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open("./cjp2p/state/key.json");
        if file.as_ref().is_ok() && file.as_ref().unwrap().metadata().unwrap().len() > 0 {
            let mut f = file.as_ref().unwrap();
            let mut saved: Self = serde_json::from_reader(f).unwrap();
            if saved.public_hex.is_none() {
                saved.public_hex = Some(hex::encode(saved.public.to_owned()));
                saved.private_hex = Some(hex::encode(saved.private.to_owned()));
                f.seek(SeekFrom::Start(0)).ok();
                f.write_all(&serde_json::to_vec_pretty(&saved).unwrap())
                    .ok();
            }
            return saved;
        }
        let keypair_ = Builder::new(NOISE_PARAMS.parse().unwrap())
            .generate_keypair()
            .unwrap();
        let keypair = Self {
            public: keypair_.public.clone().as_slice().try_into().unwrap(),
            private: keypair_.private.clone().as_slice().try_into().unwrap(),
            public_hex: Some(hex::encode(keypair_.public)),
            private_hex: Some(hex::encode(keypair_.private)),
        };
        file.as_ref()
            .unwrap()
            .write_all(&serde_json::to_vec_pretty(&keypair).unwrap())
            .ok();
        return keypair;
    }
}

struct PeerState {
    peer_map: HashMap<SocketAddr, PeerInfo>,
    peer_map_by_pub: HashMap<[u8; 8], Source>,
    peer_vec: Vec<SocketAddr>,
    recent_peers: HashSet<SocketAddr>,
    recent_peer_timer: Instant,
    recent_peer_counter_max: usize,
    socket: UdpSocket,
    boot: Instant,
    keypair: Keypair,
    open_file_cache: HashMap<String, OpenFile>,
    list_results: HashMap<String, (i32, u64)>,
    list_time: Instant,
    p: PersistentState,
    next_maintenance: Instant,
    last_upnp: std::time::SystemTime,
    recorded_chats: HashMap<String, Vec<String>>,
    all_chats: Vec<(String, String)>,
    ws_vec: Vec<WebSocket<TcpStream>>,
    http_clients: Vec<TcpStream>,
    content_gateways: Vec<ContentGateway>,
}
#[derive(Serialize, Deserialize, Debug)]
struct PersistentState {
    you_should_see_this: Option<YouSouldSeeThis>,
    i_just_saw_this: Option<IJustSawThis>,
    #[serde(default)]
    my_ed25519_signed_by_web_wallet: Option<String>,
}
impl PersistentState {
    fn save(&self) {
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
    fn load() -> Self {
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
                my_ed25519_signed_by_web_wallet: None,
            };
        }
    }
}
impl PeerState {
    fn new() -> Self {
        fs::create_dir("./cjp2p").ok();
        fs::create_dir("./cjp2p/public").ok();
        fs::create_dir("./cjp2p/metadata").ok();
        fs::create_dir("./cjp2p/state").ok();
        use std::net::Ipv6Addr;
        let mut ps = Self {
            peer_map: PeerState::load_peers(),
            peer_map_by_pub: HashMap::new(),
            peer_vec: vec![],
            recent_peers: HashSet::new(),
            recent_peer_timer: Instant::now(),
            recent_peer_counter_max: 0,
            socket: UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 24254)).unwrap(),
            boot: Instant::now(),
            keypair: Keypair::load_key(),
            open_file_cache: HashMap::new(),
            list_results: HashMap::new(),
            list_time: Instant::now(),
            p: PersistentState::load(),
            next_maintenance: Instant::now() - Duration::from_secs(99999),
            last_upnp: std::time::SystemTime::now(),
            recorded_chats: HashMap::new(),
            all_chats: Vec::new(),
            ws_vec: Vec::new(),
            http_clients: Vec::new(),
            content_gateways: Vec::new(),
        };
        for (k, v) in &ps.peer_map {
            if let Some(ed25519) = v.ed25519 {
                ps.peer_map_by_pub
                    .insert(ed25519[..8].try_into().unwrap(), Source::S(k.to_owned()));
            }
        }

        ps.socket.set_broadcast(true).ok();
        ps.socket.set_nonblocking(true).unwrap();
        SockRef::from(&ps.socket)
            .set_recv_buffer_size(0x100000)
            .ok();
        ps.socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        for bootstrap in [
            "148.71.89.128:24254",
            "159.69.54.127:24254",
            "[2a01:4f8:c013:5bc5::1]:24254",
            "[2001:818:e876:f700:e008:c723:26f1:561f]:24254",
        ] {
            let mut pi = PeerInfo::new();
            pi.delay = Duration::from_millis(20);
            let sa: SocketAddr = bootstrap.parse().unwrap();
            if !ps.peer_map.contains_key(&sa) {
                ps.peer_map.insert(bootstrap.parse().unwrap(), pi);
            }
        }
        ps.upnp();
        return ps;
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
                        trace!("broadcastingto {}",sa);
                        to_probe.insert(sa);
                        ()
                    }
                    None => (),
                },
                None => (),
            }
        }
        to_probe.insert("224.0.0.1:24254".parse().unwrap());
        to_probe.insert("[ff02::1]:24254".parse().unwrap());
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
            peer_info.delay = peer_info
                .delay
                .saturating_add(peer_info.delay / 3 + Duration::from_millis(1));
            let mut message_out: Vec<Message> = Vec::new();
            message_out.push(Message::PleaseSendPeers(PleaseSendPeers {}));
            // let people know im here
            // im not sure if anyone cares about all this info from completely random contacts
            message_out.push(self.please_always_return(sa));
            if let Some(v) = &self.p.i_just_saw_this {
                message_out.push(Message::IJustSawThis(v.clone()));
            }
            if let Some(v) = &self.p.you_should_see_this {
                message_out.push(Message::YouSouldSeeThis(v.clone()));
            }
            message_out.push(MyPublicKey::new(self));
            message_out.append(&mut self.always_returned(sa));
            message_out.push(PleaseReturnThisMessage::new(self));
            let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();

            trace!( "sending message {:?} to {sa}", String::from_utf8_lossy(&message_out_bytes));
            match self.socket.send_to(&message_out_bytes, sa) {
                Ok(s) => trace!("sent {s}"),
                Err(e) => {
                    if e.raw_os_error() == Some(11) {
                        warn!("EWOULDBLOCK failed to send (your wifi/mobile connection is probably backing up) {0} {e}", message_out_bytes.len());
                    } else {
                        // upnp can hang for 10 seconds so dont make faster, also ipv6 now causes this to happen a lot
                        // self.next_upnp = std::time::SystemTime::now();
                        debug!("failed to send to {sa} {0} bytes: {e} ", message_out_bytes.len());
                    }
                }
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

    fn load_peers() -> HashMap<SocketAddr, PeerInfo> {
        let file = OpenOptions::new()
            .read(true)
            .open("./cjp2p/state/peers.v7.json");
        let mut map = HashMap::<SocketAddr, PeerInfo>::new();
        if file.as_ref().is_ok() && file.as_ref().unwrap().metadata().unwrap().len() > 0 {
            let json: Vec<(SocketAddr, PeerInfo)> =
                serde_json::from_reader(&file.unwrap()).unwrap();
            map.extend(json);
        }

        return map;
    }
    fn save_peers(&self) -> () {
        debug!("saving peers");
        // not really sure how many, if any, of these peers or fields should be saved, or just a PleaseListContent of host:ips, but for the few users (1) of this so far, might as well save it all
        let mut peers_to_save: Vec<(SocketAddr, PeerInfo)> = Vec::new();
        for (_, src) in &self.peer_map_by_pub {
            if let Source::S(ssrc) = src {
                peers_to_save.push((ssrc.clone(), self.peer_map[ssrc].clone()))
            }
        }

        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("./cjp2p/state/peers.v7.json")
            .unwrap()
            .write_all(&serde_json::to_vec_pretty(&peers_to_save).unwrap())
            .ok();
    }

    fn best_peers(&self, how_many: i32, quality: i32) -> HashSet<SocketAddr> {
        let mut rng = rand::rng();
        let result: &mut HashSet<SocketAddr> = &mut HashSet::new();
        for _ in 0..how_many {
            let i = ((rng.random_range(0.0..1.0) as f64).powi(quality)
                * (self.peer_vec.len() as f64)) as usize;
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
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        let mut message_out = vec![];
        for message_in_enum in messages {
            message_out.append(&mut message_in_enum.receive(
                self,
                &src,
                might_be_ip_spoofing,
                inbound_states,
            ));
        }
        return message_out;
    }
    fn serve_http_content(
        &mut self,
        inbound_states: &mut HashMap<String, InboundState>,
        cg_index: usize,
    ) {
        let cg = &(self.content_gateways[cg_index]);
        if cg.http_done {
            warn!("is this code ever called? why?");
            return;
        }

        if !std::env::var("SKIP_LOCAL").is_ok() {
            if let Ok(file) = OpenOptions::new()
                .read(true)
                .write(true)
                .open("./cjp2p/public/".to_owned() + &cg.id)
            {
                let cg = &mut (self.content_gateways[cg_index]);
                cg.serve_content_from_disk(&file);

                if cg.http_done {
                    let cg_ = self.content_gateways.remove(cg_index);
                    self.http_clients.push(cg_.http_socket);
                }
                return;
            }
        }
        let id = cg.id.clone();
        let i = match inbound_states.get_mut(&id) {
            Some(i) => i,
            _ => {
                let mut new_i = InboundState::new(&id);
                info!("http scheduling inbound file {:?}", id);
                for _ in 0..(1 + 5 / (1 + new_i.peers.len())) {
                    new_i.request_blocks(self, new_i.peers.clone()); // resume (un-stall)
                }
                new_i.request_blocks(self, self.best_peers(250, 6));
                inbound_states.insert(id.to_string(), new_i);
                inbound_states.get_mut(&id).unwrap()
            }
        };

        let cg = &mut (self.content_gateways[cg_index]);
        cg.serve_content_from_inbound_state(i);
        let cg = &mut (self.content_gateways[cg_index]);
        if cg.http_done {
            let cg_ = self.content_gateways.remove(cg_index);
            self.http_clients.push(cg_.http_socket);
        }
    }

    fn handle_websocket2(
        &mut self,
        index: usize,
        inbound_states: &mut HashMap<String, InboundState>,
    ) {
        debug!("handling {} websockets",self.ws_vec.len());
        match self.ws_vec[index].read() {
            Ok(buf) => {
                //dbg!(msg);
                debug!("websocket sent: {}",buf);
                let message_in_bytes = buf.into_data();
                if message_in_bytes.len() > 0 {
                    let messages: Messages = match serde_json::from_slice(&message_in_bytes) {
                        Ok(r) => r,
                        Err(e) => {
                            debug!( "could not deserialize incoming messages from websocket {e}  :  {}",
                    String::from_utf8_lossy(&message_in_bytes));
                            return;
                        }
                    };
                    let messages = messages.0;

                    let message_out =
                        self.handle_messages(messages, &Source::None, &mut false, inbound_states);
                    if message_out.len() == 0 {
                        return;
                    }
                    let message_out_string = serde_json::to_string(&message_out).unwrap();
                    info!( "sending reply message {:?} to websocket",  message_out_string);
                    let ws = &mut self.ws_vec[index];
                    match ws.write(tungstenite::Message::Text(message_out_string.into())) {
                        Ok(_) => {
                            ws.flush().ok();
                        }
                        _ => {
                            self.ws_vec.remove(index);
                        }
                    }
                }
            }
            _ => {
                self.ws_vec.remove(index);
            }
        }
    }
    fn upnp(&self) {
        let local_port: u16 = 24254;
        let external_port: u16 =
            (((self.keypair.public[0] as u16) << 8) + self.keypair.public[1] as u16) | 0x401;
        let lease_duration: u32 = 3600; // 0 = permanent
        let protocol = PortMappingProtocol::UDP;
        let description = "cjp2p";
        thread::spawn(move || {
            if let Ok(gateway) = search_gateway(SearchOptions {
                ..Default::default()
            }) {
                info!("UPNP Found gateway: {}", gateway.addr);
                let local_ip = get_local_ip_for_gateway(gateway.addr.ip().clone());
                let local_addr = SocketAddrV4::new(local_ip, local_port);
                info!("UPNP Local addr: {local_addr}");
                info!("UPNP exterrnal port requested base based on your public key: {}",external_port);
                match gateway.add_port(
                    protocol,
                    external_port,
                    local_addr,
                    lease_duration,
                    description,
                ) {
                    Ok(()) =>
                        for index in 0..99 {
                            match gateway.get_generic_port_mapping_entry(index) {
                            Ok(entry) => {
                                if entry.external_port == external_port
                                    && entry.protocol == protocol
                                {
                                    info!("UPNP Found mapping at index {index}");
                                    info!("UPNP Real lease: {}s", entry.lease_duration);
                                    info!("UPNP Internal: {}:{}", entry.internal_client, entry.internal_port);
                                    info!("UPNP Desc: {}", entry.port_mapping_description);
                                    if entry.lease_duration != lease_duration {
                                        info!("UPNP router Clamped from {lease_duration} to {}", entry.lease_duration);
                                    }
                                    break;
                                }
                            }
                            Err(
                                igd::GetGenericPortMappingEntryError::SpecifiedArrayIndexInvalid,
                            ) => {
                                info!("UPNP Mapping not found. Router didn't create it or deleted it.");
                                break;
                            }
                            Err(e) => {
                                info!("UPNP Error reading router index {index}: {:?}", e);
                                break;
                            }
                        }
                        },
                    Err(e) => {
                        warn!("UPNP add_port failed: {e}");
                    }
                }

                if let Ok(ip) = gateway.get_external_ip() {
                    info!("Your gateway's IP: {ip}");
                }
            } else {
                info!("UPNP no gateway found");
            }
        });
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
    if !buf.is_ascii() {
        warn!("garbage on http port, closing");
        return None;
    }

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
fn get_local_ip_for_gateway(gateway_ip: Ipv4Addr) -> Ipv4Addr {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind failed");
    socket.connect((gateway_ip, 1900)).expect("connect failed");
    socket
        .local_addr()
        .expect("local_addr failed")
        .ip()
        .to_string()
        .parse()
        .expect("parse failed")
}

fn main() -> Result<(), std::io::Error> {
    env_logger::builder()
        .format_timestamp(Some(TimestampPrecision::Millis))
        .init();
    println!("logging level: {}", log::max_level());
    let mut ps: PeerState = PeerState::new();
    let web_server = if Path::new(".allow_remote_http").exists() {
        TcpListener::bind("0.0.0.0:24255").unwrap()
    } else {
        TcpListener::bind("127.0.0.1:24255").unwrap()
    };
    SockRef::from(&web_server)
        .set_send_buffer_size(0x400000)
        .ok();
    let sndbuf = SockRef::from(&web_server).send_buffer_size().unwrap();
    if sndbuf < 0x40000 {
        warn!("sndbuf  = {:?}",sndbuf);
    }
    println!("your ed25519 public key, stored in cjp2p/state/key.json, is:  0x{}",ps.keypair.public_hex.clone().unwrap());
    println!("web console at        http://127.0.0.1:24255/");
    let mut args = env::args();
    args.next();
    let mut inbound_states: HashMap<String, InboundState> = HashMap::new();
    for v in args {
        info!("queing inbound file {:?}", v);
        inbound_states.insert(v.to_string(), InboundState::new(&v));
    }

    'main: loop {
        let mut read_fds = FdSet::new();
        let mut write_fds = FdSet::new();
        maintenance(&mut inbound_states, &mut ps);
        read_fds.insert(ps.socket.as_fd());
        read_fds.insert(web_server.as_fd());
        let stdin = std::io::stdin();
        read_fds.insert(stdin.as_fd());
        let mut error_fds = read_fds.clone();

        for cg in &ps.content_gateways {
            let fd = cg.http_socket.as_fd();
            if cg.waiting_for_browser {
                write_fds.insert(fd);
            }
        }
        for hc in &ps.http_clients {
            read_fds.insert(hc.as_fd());
        }
        for ws in &ps.ws_vec {
            read_fds.insert(ws.get_ref().as_fd());
        }
        let tv_1 = &mut (nix::sys::time::TimeVal::new(1, 0));
        select(None, &mut read_fds, &mut write_fds, &mut error_fds, tv_1).unwrap();

        for (index, cg) in ps.content_gateways.iter().enumerate() {
            if write_fds.contains(cg.http_socket.as_fd()) {
                info!("handling cg {} {} {} ",cg.http_done,cg.waiting_for_browser,cg.sent_header);
                ps.serve_http_content(&mut inbound_states, index);
                continue 'main;
            }
        }

        for (k, ws) in ps.ws_vec.iter().enumerate() {
            if read_fds.contains(ws.get_ref().as_fd()) {
                debug!("handling ws vec");
                ps.handle_websocket2(k, &mut inbound_states);
                continue 'main;
            }
        }

        if read_fds.contains(stdin.as_fd()) {
            info!("handling stdin");
            handle_stdin(&mut ps, &mut inbound_states);
            continue 'main;
        }
        if read_fds.contains(web_server.as_fd()) {
            debug!("handling new http");
            if let Ok((stream, _)) = web_server.accept() {
                stream.set_nonblocking(true).unwrap();
                ps.http_clients.push(stream);
            }
            continue 'main;
        }
        for (k, hc) in ps.http_clients.iter().enumerate() {
            if read_fds.contains(hc.as_fd()) {
                debug!("handling http");
                handle_web_request(k, &mut inbound_states, &mut ps);
                continue 'main;
            }
        }
        if read_fds.contains(ps.socket.as_fd()) || error_fds.contains(ps.socket.as_fd()) {
            trace!("handling network");
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
            println!("QUEING FILE {arg}");
            inbound_states.insert(arg.clone(), InboundState::new(&arg));
        } else if sscanf!(line.as_str(), "/msg 0x{} {}",arg,arg2).is_ok() {
            chat_to_pub(ps, &arg, &arg2);
        } else if line == "/quit\n" {
            ps.save_peers();
            ps.p.save();
            std::process::exit(0);
        } else if line == "/save\n" {
            ps.save_peers();
            ps.p.save();
        } else if sscanf!(line.as_str(), "/addpeer {}",arg).is_ok() {
            let mut pi = PeerInfo::new();
            pi.delay = Duration::ZERO;
            ps.peer_map.insert(arg.parse().unwrap(), pi);
        } else if sscanf!(line.as_str(), "/msg {} {}",arg,arg2).is_ok() {
            let mut message_out = ChatMessage::new(&ps, arg2.clone());
            let dst = arg.parse().unwrap();
            message_out.append(&mut ps.always_returned(dst));
            // encrypt if we know the key
            if let Some(pi) = &ps.peer_map.get(&dst) {
                if let Some(their_pub) = &pi.ed25519 {
                    message_out = vec![
                        EncryptedMessages::new(ps,their_pub, serde_json::to_vec(&message_out).unwrap()),
                        ];
                }
            }
            if let Message::EncryptedMessages(_) = message_out[0] {
                let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
                trace!( "sending message {:?} to {arg}", String::from_utf8_lossy(&message_out_bytes));
                ps.socket.send_to(&message_out_bytes, arg).ok();
            } else {
                warn!("refusing to send unencrypted 1:1 message.  This probably shouldn't happen.");
            }
        } else if line == "/peers\n" {
            println!("========== active peer/ports");
            for v in ps.peer_vec.iter().rev() {
                let d = ps.peer_map[v].delay;
                if d < Duration::from_secs(1) {
                    println!("{:21?} {}",
                            d,
                            v);
                }
            }
            println!("{} total peers",ps.peer_map.len());
            let mut unique_ips = HashSet::new();
            //            println!("========== all IPs");
            for (k, _) in &ps.peer_map {
                if unique_ips.insert(k.ip()) {
                    // this will hang everything doing rev dns
                    //                    println!("{:21} {}",k.ip(),if let Ok(hn)= dns_lookup::lookup_addr(&k.ip()) { hn } else { k.ip().to_string()});
                }
            }
            println!("{} total unique IP peers.  ",unique_ips.len());
        } else if sscanf!(line.as_str(), "/recommend {}",arg).is_ok() {
            ps.p.you_should_see_this = Some(YouSouldSeeThis {
                id: arg.to_owned(),
                length: File::open("./cjp2p/public/".to_owned() + &arg)
                    .unwrap()
                    .metadata()
                    .unwrap()
                    .len(),
            });
        } else if line == "/pending\n" {
            println!("{} pending",inbound_states.len());
            for (_, i) in inbound_states.iter_mut() {
                println!("pending {} {}/{}",i.id,i.bytes_complete,i.eof);
            }
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
        } else if line == "/help\n" {
            println!("
                        - /ping
                        - /get hash
                        - /addpeer 1.2.3.4:5678
                        - /save  (because an on-exit handler looks hard)
                        - /quit
                        - /list
                        - /recommend hash
                        - /recommended
                        - /trending
                        - /pending
                        - /peers
                        - /msg [ip:port or 0xPubKey] msg
                        - /version
                        - /help
                ");
        } else {
            for sa in ps.best_peers(100, 5) {
                let mut message_out = ChatMessage::new(&ps, line.clone());
                message_out.append(&mut ps.always_returned(sa));
                // no point in encrypting spam
                let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
                trace!( "sending message {:?} to {sa}", String::from_utf8_lossy(&message_out_bytes));
                ps.socket.send_to(&message_out_bytes, sa).ok();
            }
        }
    }
}
fn status_page(inbound_states: &HashMap<String, InboundState>, ps: &PeerState, stream: TcpStream) {
    let public_key_hex = hex::encode(ps.keypair.public);
    let all_chats = ps.all_chats.clone();
    let current_dir = std::env::current_dir().unwrap().display().to_string();

    let inbound_info: Vec<(String, usize, usize)> = inbound_states
        .values()
        .map(|i| (i.id.clone(), i.bytes_complete, i.eof))
        .collect();

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

    let total_peers = ps.peer_map.len();

    let mut seen_pubs: HashSet<[u8; 32]> = HashSet::new();
    let mut active_peers: Vec<(SocketAddr, [u8; 32])> = Vec::new();
    for (k, v) in &ps.peer_map {
        if v.delay < Duration::from_millis(250) {
            if let Some(pub_) = v.ed25519 {
                if seen_pubs.insert(pub_) {
                    active_peers.push((*k, pub_));
                }
            }
        }
    }

    let mut seen_ips: HashSet<IpAddr> = HashSet::new();
    let mut all_ips: Vec<IpAddr> = Vec::new();
    for (k, _) in &ps.peer_map {
        if seen_ips.insert(k.ip()) {
            all_ips.push(k.ip());
        }
    }
    let unique_ips_count = all_ips.len();

    let fast_peers: Vec<(Duration, SocketAddr)> = ps
        .peer_vec
        .iter()
        .map(|v| (ps.peer_map[v].delay, *v))
        .filter(|(d, _)| *d < Duration::from_millis(119))
        .collect();

    thread::spawn(move || {
        let mut stream = stream;
        let mut page = format!("HTTP/1.0 200 OK\r\nContent-type: text/html\r\n\r\n<html><head><meta http-equiv=refresh content=4><title>cjp2p status {}</title></head><body>\n\
            {}\n\n\
            <p>
            <p> your public key {}
            <p>
            <div style='height: 200px; overflow: auto; border: 1px solid #ccc;'>",
            env!("BUILD_VERSION"),
            env!("BUILD_VERSION"),
            public_key_hex);

        for (their_pub_hex, msg) in all_chats.iter().rev() {
            page += &format!("<p><a href=/C5.html?{} target=_blank>0x{}</a> {}</p>\n",
                their_pub_hex,
                their_pub_hex,
                msg);
        }

        page += &format!("</div>");
        page += &format!("<a href=/C5.html>chat interface</a>");
        page += &format!("
          <pre> start a download (it will be in {}/cjp2p/public/ when done, \nalso put stuff there by its sha256 to share): <form><input name=get></form>\n\n", current_dir);
        for (id, bytes_complete, eof) in &inbound_info {
            page += &format!("{} {}/{}\n", id, bytes_complete, eof);
        }

        let mut sorted_list_results: Vec<_> = highly_recommended_content.iter().collect();
        sorted_list_results.sort_by_key(|&(_, b)| b.0);
        page += &format!("most recommended content (results of '/recommend sha256' in the CLI):\n");
        for (k, v) in &sorted_list_results {
            page += &format!("<a href={}>{}</a> {} {}\n",k,k,v.0,v.1);
        }

        let mut sorted_list_results: Vec<_> = trending.iter().collect();
        sorted_list_results.sort_by_key(|&(_, b)| b.0);
        page += &format!("most recently downloaded content:\n");
        for (k, v) in sorted_list_results.into_iter().rev() {
            page += &format!("<a href={}>{}</a> {} {}\n",k,k,v.0,v.1);
        }

        page += &format!("\n{} total peers\n", total_peers);
        page += &format!("--- active public keys (recently responding in under than 250ms).  Click on one to open an encrypted 2-way chat.\n\
            Note that unless they have a tab open with you, they'll only see it in the console or status page: \n");
        for (sa, pub_) in &active_peers {
            let their_pub_hex = hex::encode(pub_);
            page += &format!("{:21} <a href=/chat/{} target=_blank>0x{}</a> {}\n", sa.ip(),
                their_pub_hex,
                their_pub_hex,
                if let Ok(hn) = dns_lookup::lookup_addr(&sa.ip()) { hn } else { sa.ip().to_string() },
            );
        }
        page += &format!("--- all IPs: <table>\n");
        for ip in &all_ips {
            page += &format!("<tr><td align=right>{:21}</td><td width=30px></td><td>{}</td></tr>\n", ip,
                if let Ok(hn) = dns_lookup::lookup_addr(ip) { hn } else { ip.to_string() });
        }
        page +=
            &format!("</table>{} total unique IP peers\n--- active peers: \n", unique_ips_count);
        for (d, v) in &fast_peers {
            page += &format!("{:21?} {:21}\n", d, v);
        }
        page += &format!("</pre><body></html>");
        stream.write_all(page.as_bytes()).ok();
    });
}
fn handle_web_request(
    index: usize,
    inbound_states: &mut HashMap<String, InboundState>,
    ps: &mut PeerState,
) {
    let mut stream = ps.http_clients.remove(index);
    let mut buf = [0; 16];
    if let Ok(len) = stream.peek(&mut buf) {
        if len < 7 {
            warn!("got short http request, {len} bytes, discarding");
            return;
        }
        if buf.starts_with(b"GET /wt") {
            let mut ws = accept(stream).unwrap();
            info!("websocket connected");
            let message_out_string = if ps.p.my_ed25519_signed_by_web_wallet.is_none() {
                format!("[{{\"PleaseSignYourPub\":{{\"ed25519\":\"{}\"}}}}]",ps.keypair.public_hex.clone().unwrap())
            } else {
                format!("[{{\"YourEd25519\":{{\"ed25519\":\"{}\"}}}}]",ps.keypair.public_hex.clone().unwrap())
            };
            info!("sending websocktet: {}",message_out_string);
            ws.write(tungstenite::Message::Text(message_out_string.into()))
                .unwrap();
            ws.flush().ok();
            ps.ws_vec.push(ws);
            return;
        }

        let mut page = format!("");
        // just connecting to the http port and not saying anything DOS's this whole thing, and
        // occationally browsers seem to do that.
        if let Some(req) = parse_header(&mut stream) {
            let mut start: usize = 0;
            let mut end: usize = 0;
            if req.path == "/" {
                status_page(inbound_states, ps, stream);
                return;
            }
            info!("got http request for {}",req.path);

            if req.path.starts_with("/chat/") {
                if stream.peer_addr().unwrap().ip()
                    != "127.0.0.1:1".parse::<SocketAddr>().unwrap().ip()
                {
                    let page = format!("HTTP/1.0 403 OK\r\n\n");
                    stream.write_all(page.as_bytes()).ok();
                    return;
                }

                let v = &req.path[6..];
                let their_pub = v.split('?').next().unwrap();
                page += &format!("HTTP/1.0 200 OK\r\nContent-type: text/html\r\n\r\n<html><head><meta http-equiv=refresh content='6; url=/chat/{}' ><title>cjp2p chat {}</title></head><body><pre>\n\
                    try /ping or /version. \n\
                If they can't find you through main page, the URL they need to get here (not the same as yours) is 
                <a href=http://127.0.0.1:24255/chat/{}>http://127.0.0.1:24255/chat/{}</a>
                    <br><a href=/video.html?ed25519={}>click here</a> for high quality video call (just mute the video for audio only)</a>\n
                    <br><a href=/pong.html?ed25519={}>click here</a> to play pong</a>\n
                    send a message (type fast before the next page refresh) : <form><input name=line_chat_msg></form>\n\n\
                    <a href=/C5.html?{}>click here</a> to switch to character-by-character mode\n\
                    "
                    ,their_pub
                    ,their_pub
                    ,hex::encode(&ps.keypair.public)
                    ,hex::encode(&ps.keypair.public)
                    ,their_pub
                    ,their_pub
                    ,their_pub
                    );
                if !ps.recorded_chats.get_mut(their_pub).is_some() {
                    let mut past_chats = vec![];
                    for (their_pub_hex, msg) in &ps.all_chats {
                        if their_pub_hex == their_pub {
                            past_chats.push(msg.to_string());
                        }
                    }
                    ps.recorded_chats.insert(their_pub.to_string(), past_chats);
                }
                for m in (&ps.recorded_chats[their_pub]).into_iter().rev() {
                    page += &format!("{}\n",m);
                }

                if req.path.contains("?line_chat_msg=") {
                    let mut parts = v.split("?line_chat_msg=");
                    let _ = parts.next().unwrap().to_string();
                    let msg_ = parts.next().unwrap().to_string();
                    let msg = urlencoding::decode(&msg_).unwrap().to_string();
                    chat_to_pub(ps, &their_pub.to_string(), &msg);
                    page += &format!("\n\n{} sent..",msg);
                    ps.recorded_chats.get_mut(their_pub).unwrap().push(msg);
                }
                stream.write_all(page.as_bytes()).ok();
                return;
            }
            let id = &req.path[1..].split('?').next().unwrap();
            let id = &id.split('/').next().unwrap();
            if id.find("/") != None
                || id.find("\\") != None
                || *id == "favicon.ico"
                || id.starts_with(".")
            {
                return;
            }
            if req.path.starts_with("/?get=") {
                let v = &req.path[6..];
                inbound_states.insert(v.to_string(), InboundState::new(v));
                println!("http requested ordinary download of {}",v);
                let response = format!(
                            "HTTP/1.0 301 OK\r\n\
                             Location: /\r\n\r\n");
                stream.write_all(response.as_bytes()).ok();
                return;
            }

            if let Some(range) = req.headers.get("range") {
                info!("got ranged http req {} range {:?}",req.path,range);
                sscanf!(range, "bytes={}-{}",start,end).ok();
            } else {
                info!("got unranged http req {} start/end {} {} {:?} ",req.path,start,end,req.headers);
            }

            info!("http start end {start} {end}");
            let index = ps.content_gateways.len();
            let cg = ContentGateway {
                id: id.to_string(),
                //                http_time: Instant::now(),
                http_start: start,
                http_end: end,
                http_socket: stream,
                waiting_for_browser: false,
                http_done: false,
                sent_header: false,
                eof: 0,
            };
            ps.content_gateways.push(cg);
            ps.serve_http_content(inbound_states, index);
        }
    }
}
fn handle_network(ps: &mut PeerState, inbound_states: &mut HashMap<String, InboundState>) {
    let mut buf = [0; 0x10000];

    let (message_in_len, src) = ps.socket.recv_from(&mut buf).unwrap();

    let src = match src {
        SocketAddr::V4(_) => src,
        SocketAddr::V6(v6) => match v6.ip().to_ipv4() {
            Some(ip) => SocketAddr::new(std::net::IpAddr::V4(ip), src.port()),
            _ => src,
        },
    };

    let message_in_bytes = &buf[0..message_in_len];
    trace!( "incoming message {} from {src}", String::from_utf8_lossy(message_in_bytes));
    if !ps.peer_map.contains_key(&src) {
        let mut pi = PeerInfo::new();
        pi.delay = Duration::from_millis(120);
        ps.peer_map.insert(src, pi);
        info!("new peer spotted {src}");
    }
    ps.recent_peers.insert(src);
    if ps.ws_vec.len() > 0 {
        let message_out_string = serde_json::to_string(&json![
            [Message::Forwarded(Forwarded{src:src,from_ed25519:None,
        maybe_ed25519: if let Some(their_pub) = &ps.peer_map[&src].ed25519 { Some(hex::encode(their_pub))} else { None }
            ,
                messages: String::from_utf8_lossy(&message_in_bytes).to_string(),})]]).unwrap();
        trace!( "sending raw message {} to {} websocket(s)", message_out_string,ps.ws_vec.len());
        for ws in &mut ps.ws_vec {
            if ws
                .write(tungstenite::Message::Text(
                    message_out_string.clone().into(),
                ))
                .is_ok()
            {
                ws.flush().ok();
            }
        }
    }
    let messages: Messages = match serde_json::from_slice(message_in_bytes) {
        Ok(r) => r,
        Err(e) => {
            debug!( "could not deserialize incoming messages from {} {e}  :  {}",src,
                    String::from_utf8_lossy(message_in_bytes));
            return;
        }
    };
    let messages = messages.0;
    // This ist a Vec<Value> because I don't know the structure of the Please*Returns
    let mut might_be_ip_spoofing = ps.check_key(&messages, src);
    let mut message_out = ps.handle_messages(
        messages,
        &Source::S(src),
        &mut might_be_ip_spoofing,
        inbound_states,
    );
    if message_out.len() == 0 {
        trace!("no reply");
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
    /*    if let Some(their_pub) = &ps.peer_map[&src].ed25519 {
        message_out_bytes = serde_json::to_vec(
            &(vec![
                          EncryptedMessages::new(ps,their_pub, message_out_bytes),
                          ]),
        )
        .unwrap();
    } */
    match ps.socket.send_to(&message_out_bytes, src) {
        Ok(s) => trace!("sent {s}"),
        Err(e) => warn!("failed to reply to {0} {e}", message_out_bytes.len()),
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
impl Receive for AlwaysReturned {
    fn receive(
        self,
        _: &mut PeerState,
        _: &Source,
        _: &mut bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        //this is handled early
        return vec![];
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct PleaseAlwaysReturnThisMessage {
    cookie: String,
}
impl Receive for PleaseAlwaysReturnThisMessage {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        _: &mut bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if let Source::S(src) = *src {
            // not even needed for websockets
            trace!("saving cookie {} for {:?}",self.cookie,src);
            ps.peer_map
                .get_mut(&src)
                .unwrap()
                .anti_ip_spoofing_cookie_they_expect = Some(self.cookie);
        }
        return vec![];
    }
}
#[derive(Serialize, Deserialize, Debug)]
struct PleaseSendPeers {}
impl Receive for PleaseSendPeers {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        let p = ps.best_peers(1 + 45 * !*might_be_ip_spoofing as i32, 6);
        trace!("sending {:?}/{:?} peers", p.len(), ps.peer_map.len());
        let mut message_out = vec![Message::Peers(Peers { peers: p })];
        if *might_be_ip_spoofing {
            if let Source::S(src) = src {
                message_out.push(ps.please_always_return(*src));
            }
        }
        return message_out;
    }
}
impl Receive for Peers {
    fn receive(
        self,
        ps: &mut PeerState,
        _: &Source,
        _: &mut bool,
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
struct IJustSawThis {
    id: String,
    length: u64,
}
impl Receive for IJustSawThis {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if self.id.find("/") != None
            || self.id.find("\\") != None
            || self.id == "favicon.ico"
            || self.id.starts_with(".")
        {
            return vec![];
        }
        if let Source::S(src) = *src {
            if let Some(i) = inbound_states.get_mut(&self.id) {
                i.peers.insert(src);
            } else {
                InboundState::send_content_peers_from_disk(&self.id, 1, &src);
            }
            if !*might_be_ip_spoofing && src.port() == 24254 {
                ps.peer_map.get_mut(&src).unwrap().i_just_saw_this = Some(self);
            }
        }
        return vec![];
    }
}
#[derive(Clone, Serialize, Deserialize, Debug)]
struct YouSouldSeeThis {
    id: String,
    length: u64,
}
impl Receive for YouSouldSeeThis {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if self.id.find("/") != None
            || self.id.find("\\") != None
            || self.id == "favicon.ico"
            || self.id.starts_with(".")
        {
            return vec![];
        }
        if let Source::S(src) = *src {
            if let Some(i) = inbound_states.get_mut(&self.id) {
                i.peers.insert(src);
            } else {
                InboundState::send_content_peers_from_disk(&self.id, 1, &src);
            }
            if !*might_be_ip_spoofing && src.port() == 24254 {
                ps.peer_map.get_mut(&src).unwrap().you_should_see_this = Some(self);
            }
        }
        return vec![];
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    eof: Option<usize>,
}

impl PleaseSendContent {
    fn new_messages(i: &mut InboundState, ps: &PeerState) -> Vec<Message> {
        for cg in &ps.content_gateways {
            let new_next_block = cg.http_start as usize / BLOCK_SIZE!();
            if !cg.http_done && !cg.waiting_for_browser && cg.id == i.id {
                if new_next_block != i.next_block
                    && (i.next_block * BLOCK_SIZE!() < cg.http_start
                        || i.next_block * BLOCK_SIZE!() >= cg.http_start + 0x400000
                        || i.next_block * BLOCK_SIZE!() > cg.http_end)
                {
                    info!("http {} ressetting next_block from {} to {} !",line!(), i.next_block,new_next_block);
                    i.next_block = new_next_block;
                }
                break;
            }
        }
        while {
            if i.next_block * BLOCK_SIZE!() >= i.eof && i.bytes_complete > 0 {
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
            i.bytes_complete > 0 && i.bitmap[i.next_block]
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
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if self.id.find("/") != None
            || self.id.find("\\") != None
            || self.id.starts_with(".")
            || self.id.len() == 0
        {
            return vec![];
        };
        let mut message_out: Vec<Message> = Vec::new();
        if let Source::S(src) = *src {
            if let Some(i) = inbound_states.get_mut(&self.id) {
                i.peers.insert(src);
                message_out.append(&mut i.send_content_peers(*might_be_ip_spoofing, src));
            }
        }
        message_out.append(&mut Content::new_block(&self, might_be_ip_spoofing, ps));
        if let Source::S(src) = *src {
            if message_out.len() == 0
                || (!*might_be_ip_spoofing && rand::rng().random::<u32>() % 43 == 0)
            {
                message_out.append(&mut InboundState::send_content_peers_from_disk(
                    &self.id,
                    3 + 45 * !*might_be_ip_spoofing as usize,
                    &src,
                ));
            }
            if *might_be_ip_spoofing && message_out.len() > 0 {
                message_out.push(ps.please_always_return(src));
            }
        }
        return message_out;
    }
}

impl Content {
    fn new_block(
        req: &PleaseSendContent,
        might_be_ip_spoofing: &mut bool,
        ps: &mut PeerState,
    ) -> Vec<Message> {
        if *might_be_ip_spoofing && rand::rng().random::<u32>() % 27 == 0 {
            info!("randomly ignoring unverified source IPs for {} so ba dumb client doesn't get stuck in a loop",req.id);
            return vec![];
        }

        let length = if *might_be_ip_spoofing {
            1
        } else if req.length > 0xa000 {
            0xa000
        } else {
            req.length
        };
        if std::env::var("SKIP_LOCAL").is_ok() {
            return vec![];
        }
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
        src: &Source,
        _: &mut bool,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if let Source::S(src) = *src {
            if !inbound_states.contains_key(&self.id) {
                debug!( "unwanted content, probably dups -- the tail still in flight after completion, for {0} block {1}",
                self.id, self.offset / BLOCK_SIZE!());
                return vec![];
            }
            //if (rand::rng().random::<u32>() % (if cg.http_socket.is_some() { 7 } else { 101 })) == 0 ||
            if (rand::rng().random::<u32>() % 101) == 0 {
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
            let mut message_out = i.receive_content(&self, ps);
            if self.eof.is_some() && hex::decode(self.id.to_owned()).is_ok() {
                ps.p.i_just_saw_this = Some(IJustSawThis {
                    id: self.id.to_owned(),
                    length: self.eof.unwrap() as u64,
                });
            }
            if i.finished() {
                for (index, cg) in (&mut (ps.content_gateways)).into_iter().enumerate() {
                    if cg.id == self.id {
                        cg.serve_content_from_inbound_state(i);
                        if cg.http_done {
                            let cg = ps.content_gateways.remove(index);
                            ps.http_clients.push(cg.http_socket);
                            break;
                        }
                    }
                }
                inbound_states.remove(&self.id);
            }
            if message_out.len() == 0 {
                for (_, i) in inbound_states.iter_mut() {
                    if i.next_block * BLOCK_SIZE!() >= i.eof {
                        continue;
                    }
                    message_out = PleaseSendContent::new_messages(i, ps);
                    i.next_block += 1;
                    break;
                }
            }
            if message_out.len() == 0 {
                if let Some(i) = inbound_states.get_mut(&self.id) {
                    i.next_block = 0;
                    message_out = PleaseSendContent::new_messages(i, ps);
                    i.next_block += 1;
                }
            }
            return message_out;
        }
        return vec![];
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
}
struct ContentGateway {
    id: String,
    ///http_time: Instant,
    http_start: usize,
    http_end: usize,
    http_socket: TcpStream,
    waiting_for_browser: bool,
    http_done: bool,
    sent_header: bool,
    eof: usize,
}
impl ContentGateway {
    fn serve_content_from_disk(&mut self, file: &File) {
        if self.eof == 0 {
            self.eof = file.metadata().unwrap().len() as usize;
        }
        if self.http_end == 0 || self.eof < self.http_end {
            self.http_end = self.eof;
        }
        // i couldnt figure out how to get serve_mmap to take both Mmap or MmapMut.
        let mmap = unsafe { MmapMut::map_mut(file).unwrap() };
        self.serve_mmap(&mmap, self.http_end);
    }

    fn serve_content_from_inbound_state(&mut self, i: &mut InboundState) {
        if self.http_done || i.bytes_complete == 0 {
            self.waiting_for_browser = false;
            return;
        }
        self.eof = i.eof;
        if self.http_end == 0 || self.eof < self.http_end {
            self.http_end = self.eof;
        }
        let mut available_end = self.http_end;
        if let Some(not_available) = i.bitmap[(self.http_start / BLOCK_SIZE!())
            ..((self.http_end + (BLOCK_SIZE!() - 1)) / BLOCK_SIZE!())]
            .first_zero()
        {
            available_end = (not_available + self.http_start / BLOCK_SIZE!()) * BLOCK_SIZE!();
        }
        if available_end <= self.http_start {
            self.waiting_for_browser = false;
            return;
        }
        let mmap = &i.mmap.as_mut().unwrap();
        self.serve_mmap(mmap, available_end);
    }
    fn serve_mmap(&mut self, mmap: &MmapMut, available_end: usize) {
        if !self.sent_header {
            let mime_type = mimetype_detector::detect(&mmap[0..]);
            let response = format!(
                                "HTTP/1.1 206 Partial Content\r\n\
                                 Content-Length: {}\r\n\
                                 Content-Disposition: inline\r\n\
                                 Accept-Range: bytes\r\n\
                                 Content-Range: bytes {}-{}/{}\r\n\
                                 Content-Type: {}\r\n\r\n"
            ,self.http_end-self.http_start,self.http_start,self.http_end-1, self.eof, mime_type.mime());
            match self.http_socket.write_all(response.as_bytes()) {
                Ok(_) => (),
                Err(e) => {
                    warn!("http failed to write header {}",e);
                    self.http_done = true; // give up, that shouldnt happen
                    self.waiting_for_browser = false;
                }
            }
            self.sent_header = true;
        }

        match self
            .http_socket
            .write(&mmap[self.http_start..available_end])
        {
            Ok(sent) => self.http_start += sent,
            Err(err) => {
                warn!("http client error {err}");
                self.http_done = true;
                self.waiting_for_browser = false;
                return;
            }
        }
        if self.http_start != available_end {
            debug!("http sent up to {} ..wanted to send up to {}",self.http_start,available_end);
        } else {
            debug!("http sent up to {} ",self.http_start);
        }
        self.http_done = self.http_start == self.http_end;
        self.waiting_for_browser = self.http_start != available_end;
    }
}
impl InboundState {
    fn new(id: &str) -> Self {
        fs::create_dir("./cjp2p/incoming").ok();
        let mut peers: HashSet<SocketAddr> = HashSet::new();
        let peers_from_disk = InboundState::send_content_peers_from_disk(
            &id.to_string(),
            999999999,
            &"127.0.0.1:24254".parse().unwrap(),
        );
        if peers_from_disk.len() > 0 {
            if let Message::MaybeTheyHaveSome(p) = &peers_from_disk[0] {
                peers.extend(&p.peers);
                info!("{} loadedd {} peers frorm disk",id,p.peers.len());
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
        };
    }

    fn receive_content(&mut self, content: &Content, ps: &mut PeerState) -> Vec<Message> {
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
                .open("./cjp2p/incoming/".to_owned() + &self.id)
                .unwrap();
            file.set_len(self.eof as u64).unwrap();
            self.mmap = Some(unsafe { MmapMut::map_mut(&file).unwrap() });
        }

        if content.offset >= self.eof {
            warn!("{} got data at {}, past EOF {}!",self.id,content.offset,self.eof);
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
            for (index, cg) in (&mut (ps.content_gateways)).into_iter().enumerate() {
                if cg.id == self.id {
                    cg.serve_content_from_inbound_state(self);
                    if cg.http_done {
                        let cg = ps.content_gateways.remove(index);
                        ps.http_clients.push(cg.http_socket);
                        break;
                    }
                }
            }
        }
        self.last_activity = Instant::now();
        let message_out = PleaseSendContent::new_messages(self, ps);
        self.next_block += 1;
        return message_out;
    }

    fn request_blocks(&mut self, ps: &mut PeerState, some_peers: HashSet<SocketAddr>) {
        for sa in some_peers {
            let mut message_out: Vec<Message> = Vec::new();
            for m in PleaseSendContent::new_messages(self, ps) {
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
    fn save_content_peers(&self) -> () {
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
    fn send_content_peers_from_disk(id: &String, at_most: usize, src: &SocketAddr) -> Vec<Message> {
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
            let json: Value = serde_json::from_reader(BufReader::new(&file)).unwrap();
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
            let path = "./cjp2p/incoming/".to_owned() + &self.id;
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
}

fn maintenance(inbound_states: &mut HashMap<String, InboundState>, ps: &mut PeerState) -> () {
    if ps.next_maintenance.elapsed() <= Duration::ZERO {
        return;
    }
    if ps.recent_peer_timer.elapsed() > Duration::from_secs(5 * 60) {
        if ps.recent_peers.len() < ps.recent_peer_counter_max * 4 / 5 {
            error!("apocalypse? only {} peers in 5 minutes, vs max of {}",ps.recent_peers.len(),ps.recent_peer_counter_max);
        }
        if ps.recent_peers.len() > ps.recent_peer_counter_max * 4 / 5 {
            ps.recent_peer_counter_max = ps.recent_peers.len()
        }
        ps.recent_peer_timer = Instant::now();
        ps.recent_peers = HashSet::new();
    }
    if let Ok(dur) = ps.last_upnp.elapsed() {
        if dur > Duration::from_secs(1200) {
            ps.last_upnp = std::time::SystemTime::now();
            ps.upnp();
        }
    }
    debug!("maintenance");
    let mut to_remove = vec![];
    for (index, cg) in ps.content_gateways.iter().enumerate() {
        if cg.http_done {
            to_remove.push(index);
        }
    }
    for tr in to_remove.iter().rev() {
        warn!("removing cg");
        ps.content_gateways.remove(*tr);
    }
    ps.next_maintenance =
        Instant::now() + Duration::from_millis(rand::rng().random_range(911..1234));
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
        info!("{} stalled, restarting", i.id);
        let mut try_harder = 1;
        for cg in &ps.content_gateways {
            // try harder if user is actively waiting
            if !cg.http_done && cg.id == i.id {
                try_harder = 5;
                break;
            }
        }
        for _ in 0..(1 + try_harder / (1 + i.peers.len())) {
            i.request_blocks(ps, i.peers.clone()); // resume (un-stall)
        }
        i.request_blocks(ps, ps.best_peers(50 * try_harder as i32, 6));
        // TODO the longer its been stuck, the more it should be ignored to try others, instead of
        // this pure random
        if rand::rng().random::<u32>() % 2 == 0 {
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

impl Receive for MaybeTheyHaveSome {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        _: &mut bool,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if !inbound_states.contains_key(&self.id) {
            return vec![];
        }
        let i = inbound_states.get_mut(&self.id).unwrap();
        for p in self.peers {
            if i.peers.insert(p) {
                // new possible source? try it
                info!("{} trying new peer {} suggested by {:?}",self.id,p,src);
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
impl Receive for PleaseReturnThisMessage {
    fn receive(
        self,
        _: &mut PeerState,
        _: &Source,
        _: &mut bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        return vec![Message::ReturnedMessage(ReturnedMessage { cookie: self.cookie, })];
    }
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
impl Receive for ReturnedMessage {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if let Source::S(src) = *src {
            if !*might_be_ip_spoofing {
                if let Some(peer) = ps.peer_map.get_mut(&src) {
                    peer.delay =
                        (ps.boot + Duration::from_secs_f64(self.cookie.parse().unwrap())).elapsed();
                    trace!("measured {0} at {1}", src, peer.delay.as_secs_f64())
                }
            };
        }
        return vec![];
    }
}
//        socket.send(JSON.stringify([{GetPubByEth:{eth_addr:their_eth_addr}}]));
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
struct GetPubByEth {
    eth_addr: String,
}
impl Receive for GetPubByEth {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        _: &mut bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        for (k, p) in &ps.peer_map {
            if let Some(signer) = &p.ed25519_eth_signer {
                if let Some(ed25519) = &p.ed25519 {
                    if *signer == self.eth_addr {
                        let mpk = MyPublicKey {
                            ed25519h: ed25519.clone(),
                            ed25519_eth_signed: p.ed25519_eth_signed.clone(),
                        };
                        let message_out = vec![Message::MyPublicKey(mpk)];
                        let from_ed25519 = Some(hex::encode(ed25519));
                        let maybe_ed25519 = None;

                        let messages = serde_json::to_string(&message_out).unwrap();
                        info!("sending {:?} ed25519 {} for eth addr {} to ",src,from_ed25519.clone().unwrap(),signer);
                        let src = *k;
                        return vec![Message::Forwarded(Forwarded{src,from_ed25519,maybe_ed25519,messages})];
                    }
                }
            }
        }
        warn!("failed to find ed25519 of requested eth addr {}, searching..",self.eth_addr);
        for k in 0..1000 {
            if let Some(v) = ps.peer_vec.get(k) {
                let mut message_out = vec![Message::GetPubByEth(self.clone())];
                message_out.push(ps.please_always_return(v.clone()));
                let message_out_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
                ps.socket.send_to(&message_out_bytes, v).ok();
            }
        }
        return vec![];
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct SignedPub {
    signature: String,
}
impl Receive for SignedPub {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        _: &mut bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if let Source::S(_) = src {
            return vec![];
        }
        info!("websocket used old SignedPub (just use MyPublicKey now) sent signed {:?} to ",
            &self.signature);
        ps.p.my_ed25519_signed_by_web_wallet = Some(self.signature);
        return vec![];
    }
}
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct Forwarded {
    src: SocketAddr,
    from_ed25519: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    maybe_ed25519: Option<String>,
    messages: String,
}
impl Receive for Forwarded {
    fn receive(
        self,
        _: &mut PeerState,
        _: &Source,
        _: &mut bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        return vec![];
    }
}
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct Forward {
    to_ed25519: String,
    messages: Vec<Value>,
}
impl Receive for Forward {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        _: &mut bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if let Source::S(_) = src {
            // we could allow this, i dont see why not, though theres not a currrent use
            // case..maybe dual-nat issues if they're encountered, or web socket clients to
            // gateways if gateways with mulitple clients becomes a use case,
            // with web sockets like light nodes stuck behind unusually difficult NAT
            // but better to just leave it off for now, its not clear yet if the webclient
            // is always a trusted localhost or a random
            return vec![];
        }
        debug!("websocket asked me to forward {:?} to {} ",
            &self.messages
            ,&self.to_ed25519);
        msgs_to_pub(ps, &self.to_ed25519, &self.messages);
        return vec![];
    }
}
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct MyPublicKey {
    #[serde_as(as = "Hex")]
    ed25519h: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none")]
    ed25519_eth_signed: Option<String>,
}
impl MyPublicKey {
    fn new(ps: &PeerState) -> Message {
        return Message::MyPublicKey(Self {
            ed25519h: ps.keypair.public.clone(),
            ed25519_eth_signed: ps.p.my_ed25519_signed_by_web_wallet.clone(),
        });
    }
}
impl Receive for MyPublicKey {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        _: &mut bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        use alloy::signers::Signature;
        use std::str::FromStr;
        let mut recovered_address: Option<String> = None;
        let ed25519h_hex = hex::encode(&self.ed25519h);
        ps.peer_map_by_pub
            .insert(self.ed25519h[..8].try_into().unwrap(), src.to_owned());
        if let Some(sig) = &self.ed25519_eth_signed {
            if let Ok(sig) = Signature::from_str(sig.as_str()) {
                // takes 0.0003s so do this in advance
                if let Ok(address) = sig
                    .recover_address_from_msg(format!("my ed25519 public key is {}",ed25519h_hex))
                {
                    debug!("Recovered address: {}", address);
                    // comes out like 0x9aE035dEE8318A9b9fD080Dda31D7524098f65EF
                    // address
                    recovered_address = Some(address.to_string());
                } else {
                    warn!("eth signature failed recover from {:?}",src);
                    return vec![];
                }
            } else {
                warn!("eth signature failed from {:?}",src);
                return vec![];
            }
        }
        if let Source::S(src) = *src {
            let pi = ps.peer_map.get_mut(&src).unwrap();
            if let Some(a) = recovered_address {
                pi.ed25519_eth_signer = Some(a);
                pi.ed25519_eth_signed = self.ed25519_eth_signed;
            }
            pi.ed25519 = Some(self.ed25519h);
        } else {
            info!("websocket sent signed {} to ", ed25519h_hex);
            if ed25519h_hex == ps.keypair.public_hex.clone().unwrap() {
                if let Some(ed25519_eth_signed) = self.ed25519_eth_signed {
                    info!("websocket signature saved");
                    ps.p.my_ed25519_signed_by_web_wallet = Some(ed25519_eth_signed);
                    ps.p.save();
                }
            } else {
                warn!("why is websocket eth signing someone else's ed25519 pub");
            }
        }
        return vec![];
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ChatMessage {
    message: String,
}
impl ChatMessage {
    fn new(ps: &PeerState, message: String) -> Vec<Message> {
        let message_out = vec![
            PleaseReturnThisMessage::new(ps),
            MyPublicKey::new(ps),
            Message::ChatMessage(Self { message: message }),
        ];
        return message_out;
    }
}
impl Receive for ChatMessage {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        _: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if let Source::S(src) = *src {
            if *might_be_ip_spoofing {
                info!("unusual that a chat messagge was received from an unconfirmed source ({}), so it is being dropped. it was: {}",src,self.message);
                return vec![];
            }
            println!("\x1b[7m{} {src} 0x{} from {:?} away said \x1b[33m{}\x1b[m",
                Utc::now().to_rfc3339(),
                hex::encode(&ps.peer_map[&src].ed25519.clone().unwrap_or_default()),
                ps.peer_map[&src].delay,
                self.message
            );
            let their_pub_hex = hex::encode(&ps.peer_map[&src].ed25519.clone().unwrap_or_default());
            if (ps.all_chats.len() == 0
                || ps.all_chats.last().unwrap().0 != their_pub_hex
                || ps.all_chats.last().unwrap().1 != self.message)
                && self.message.len() > 0
            {
                ps.all_chats
                    .push((their_pub_hex.to_string(), self.message.to_owned()));
            }
            if let Some(v) = ps.recorded_chats.get_mut(&their_pub_hex) {
                if (v.len() == 0 || v.last().unwrap() != &self.message)
                    && self.message.clone().len() > 0
                {
                    v.push(self.message.to_owned());
                }
            }
            if self.message.starts_with("/version") {
                // encrypt if we know the key
                let mut message_out = Self::new(ps, format!("VERSION {}\n",env!("BUILD_VERSION")));
                if let Some(pi) = &ps.peer_map.get(&src) {
                    if let Some(their_pub) = &pi.ed25519 {
                        message_out = vec![
                EncryptedMessages::new(ps,their_pub, serde_json::to_vec(&message_out).unwrap()),
                ];
                    }
                }
                return message_out;
            }
            if self.message.starts_with("/ping") {
                let mut message_out = Self::new(ps, "PONG".to_string());
                // encrypt if we know the key
                if let Some(pi) = &ps.peer_map.get(&src) {
                    if let Some(their_pub) = &pi.ed25519 {
                        message_out = vec![
                EncryptedMessages::new(ps,their_pub, serde_json::to_vec(&message_out).unwrap()),
                ];
                    }
                }

                return message_out;
            }
        }
        return vec![];
    }
}
#[derive(Serialize, Deserialize, Debug)]
struct PleaseListContent {}
impl Receive for PleaseListContent {
    fn receive(
        self,
        _: &mut PeerState,
        _: &Source,
        might_be_ip_spoofing: &mut bool,
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
            if results.len() > 70 * !*might_be_ip_spoofing as usize + 1 {
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
    fn new(ps: &PeerState) -> Vec<Message> {
        let message_out = vec![
            PleaseReturnThisMessage::new(ps),
            Message::PleaseListContent(Self {}),
        ];
        return message_out;
    }
}
#[derive(Serialize, Deserialize, Debug)]
struct ContentList {
    results: Vec<(String, u64)>,
}
impl Receive for ContentList {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        _: &mut bool,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if let Source::S(src) = *src {
            for (id, size) in &self.results {
                trace!("\x1b[7m{} {src} 0x{} from {:?} has \x07\x1b[32m{:?}\x1b[m",
                    Utc::now().to_rfc3339(),
                    hex::encode(&ps.peer_map[&src].ed25519.clone().unwrap_or_default()),
                    ps.peer_map[&src].delay,
                    self.results
                );
                if id.find("/") != None
                    || id.find("\\") != None
                    || id == "favicon.ico"
                    || id.starts_with(".")
                {
                    return vec![];
                }
                if let Some(i) = inbound_states.get_mut(id) {
                    i.peers.insert(src);
                } else {
                    InboundState::send_content_peers_from_disk(&id, 1, &src);
                }
                match ps.list_results.get_mut(&id.to_owned()) {
                    Some(h) => h.0 += 1,
                    None => {
                        ps.list_results.insert(id.to_owned(), (1, *size));
                        ()
                    }
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
    fn new(ps: &PeerState, their_pub: &[u8; 32], message: Vec<u8>) -> Message {
        let mut noise = Builder::new(NOISE_PARAMS.parse().unwrap())
            .local_private_key(&ps.keypair.private)
            .remote_public_key(their_pub)
            .build_initiator()
            .unwrap();
        let mut buf = [0u8; 99999];
        let len = noise.write_message(&message, &mut buf).unwrap();
        let message_out = Message::EncryptedMessages(Self {
            base64: buf[..len].to_vec(),
            noise_params: NOISE_PARAMS.to_string(),
        });
        return message_out;
    }
}
impl Receive for EncryptedMessages {
    fn receive(
        self,
        ps: &mut PeerState,
        src_: &Source,
        might_be_ip_spoofing: &mut bool,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message> {
        if let Source::S(src) = *src_ {
            let mut noise = Builder::new(NOISE_PARAMS.parse().unwrap())
                .local_private_key(&ps.keypair.private)
                .build_responder()
                .unwrap();
            let mut message_in_bytes = vec![0u8; 99999];
            if let Ok(len) = noise.read_message(&self.base64, &mut message_in_bytes) {
                let their_pub: [u8; 32] = noise.get_remote_static().unwrap().try_into().unwrap();
                ps.peer_map_by_pub
                    .insert(their_pub[..8].try_into().unwrap(), src_.clone());
                let pi = ps.peer_map.get_mut(&src).unwrap();
                pi.ed25519 = Some(their_pub);

                let their_pub_hex = hex::encode(their_pub);
                message_in_bytes.truncate(len);
                trace!("handling decrypted message from {src} {their_pub_hex}: {}",
                     String::from_utf8_lossy(&message_in_bytes));
                let messages: Messages = match serde_json::from_slice(&message_in_bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        debug!( "could not deserialize incoming messages from {} {e}  :  {}",src,
                    String::from_utf8_lossy(&message_in_bytes));
                        return vec![];
                    }
                };
                let messages = messages.0;

                *might_be_ip_spoofing &= ps.check_key(&messages, src);
                let message_out_string = serde_json::to_string(&json![
                        [Message::Forwarded(Forwarded{
                            src:src,
                            from_ed25519:Some(their_pub_hex),
                            maybe_ed25519:None,
                            messages: String::from_utf8_lossy(&message_in_bytes).to_string(),})]])
                .unwrap();
                if ps.ws_vec.len() > 0 {
                    trace!( "sending decrypted message {} to {} websockets", message_out_string,ps.ws_vec.len());
                }
                for ws in &mut ps.ws_vec {
                    if ws
                        .write(tungstenite::Message::Text(
                            message_out_string.clone().into(),
                        ))
                        .is_ok()
                    {
                        ws.flush().ok();
                    }
                }
                return ps.handle_messages(
                    messages,
                    &Source::S(src),
                    might_be_ip_spoofing,
                    inbound_states,
                );
            } else {
                info!("failed to decrypt a message from {src}");
            }
        }
        return vec![];
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[enum_dispatch]
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
    Forward(Forward),
    Forwarded(Forwarded),
    SignedPub(SignedPub),
    GetPubByEth(GetPubByEth),
}

// this struct only exists to be able to get that VecSkipError in there.
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct Messages(#[serde_as(as = "VecSkipError<_,ErrorInspector>")] Vec<Message>);

struct ErrorInspector;

impl InspectError for ErrorInspector {
    fn inspect_error(error: impl serde::de::Error) {
        debug!( "could not deserialize an incoming message {error}");
    }
}

#[enum_dispatch(Message)]
trait Receive {
    fn receive(
        self,
        ps: &mut PeerState,
        src: &Source,
        might_be_ip_spoofing: &mut bool,
        inbound_states: &mut HashMap<String, InboundState>,
    ) -> Vec<Message>;
}

fn msgs_to_pub(ps: &mut PeerState, their_pub_hex_: &String, messages: &Vec<Value>) -> () {
    let their_pub_hex = their_pub_hex_.strip_prefix("0x").unwrap_or(their_pub_hex_);
    if let Ok(to__) = hex::decode(their_pub_hex) {
        let to_: Result<[u8; 32], _> = to__.try_into();
        if let Ok(to) = to_ {
            if let Some(Source::S(sa)) = ps.peer_map_by_pub.get(&to[..8]) {
                if let Some(pi) = ps.peer_map.get(&sa) {
                    if let Some(key) = &pi.ed25519 {
                        if *key == to {
                            let mut message_out: Vec<Value> = vec![];
                            if rand::rng().random::<u32>() % 37 == 0 {
                                message_out.push(
                                    serde_json::to_value(PleaseReturnThisMessage::new(ps)).unwrap(),
                                );
                            } else if rand::rng().random::<u32>() % 5 == 0
                                && ps.p.my_ed25519_signed_by_web_wallet.is_some()
                            {
                                message_out
                                    .push(serde_json::to_value(MyPublicKey::new(ps)).unwrap());
                            }
                            // an optimization would be to skip serde once we know where
                            // it should go and just copy the message bytes
                            for m in messages {
                                message_out.push(serde_json::to_value(m).unwrap());
                            }
                            message_out = vec![
                                serde_json::to_value(&EncryptedMessages::new(ps,&to, serde_json::to_vec(&message_out).unwrap())).unwrap(),
                            ];
                            let c = ps.always_returned(*sa);
                            if c.len() > 0 {
                                message_out.push(serde_json::to_value(&c[0]).unwrap());
                            }
                            let message_out_bytes: Vec<u8> =
                                serde_json::to_vec(&message_out).unwrap();
                            message_out.pop();
                            trace!( "sending message {:?} to {sa} {their_pub_hex}", String::from_utf8_lossy(&message_out_bytes));
                            ps.socket.send_to(&message_out_bytes, sa).ok();
                            return;
                        }
                    }
                }
            }
            error!("user {} not found",their_pub_hex);
        }
    } else {
        error!("failed to decode hex {} ",their_pub_hex_);
    }
}

fn chat_to_pub(ps: &mut PeerState, their_pub_hex: &String, msg: &String) -> () {
    let mut message_out: Vec<Value> = Vec::new();
    for m in ChatMessage::new(&ps, msg.clone()) {
        message_out.push(serde_json::to_value(m).unwrap());
    }
    msgs_to_pub(ps, their_pub_hex, &message_out);
}
