//use base64::{engine::general_purpose, Engine as _};
//use bitvec::prelude::*;
//use chrono::{Timelike, Utc};
//use enum_dispatch::enum_dispatch;
use env_logger::fmt::TimestampPrecision;
use hex;
use libcjp::*;
//use log::{debug, error, info, log_enabled, trace, warn, Level};
use log::{debug, info, trace, warn};
//use memmap2::MmapMut;
use std::net::IpAddr;
//use nix::NixPath;
//use serde::{Deserialize, Serialize};
//use serde_json::json;
//use serde_with::{base64::Base64, serde_as, InspectError, VecSkipError};
//use sha2::{Digest, Sha256};
//use snow::Builder;
//use std::cmp;
use std::collections::{HashMap, HashSet};
//use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::io::{Read, Write};
//use std::convert::TryInto;
use std::env;
//use std::fmt;
//use std::f64;
//use std::fs;
use std::fs::File;
//use std::fs::OpenOptions;
//use std::io::copy;
use nix::sys::select::{select, FdSet};
//use rand::Rng;
use scanf::sscanf;
use std::net::SocketAddr;
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
use std::time::{Duration, Instant};
use std::vec;
//use std::{io, str};
use std::io;
fn main() -> Result<(), std::io::Error> {
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

    loop {
        let mut read_fds = FdSet::new();
        libcjp::maintenance(&mut inbound_states, &mut ps);
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

#[derive(Debug)]
pub struct HttpRequest {
    pub path: String,
    pub headers: HashMap<String, String>,
}

pub fn parse_header(stream: &mut TcpStream) -> Option<HttpRequest> {
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

pub fn handle_web_request(
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

            if let Ok(file) = File::open("./cjp2p/public/".to_owned() + &id) {
                let mut buf = vec![0; end-start ];
                let length = file.read_at(&mut buf, start as u64).unwrap();
                let mut response = format!(
                            "HTTP/1.1 206 Partial Content\r\n\
                             Content-Length: {}\r\n\
                             Content-Disposition: inline\r\n\
                             Accept-Range: bytes\r\n\
                            Content-Range: bytes {}-{}/{}\r\n"
                            ,length,start,start+length-1,
                            file.metadata().unwrap().len());
                match infer::get_from_path("./cjp2p/public/".to_owned() + &id) {
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
                        info!("http scheduling inbound file {:?}", id);
                        inbound_states.insert(id.to_string(), new_i);
                        inbound_states.get_mut(id).unwrap()
                    }
                };
                i.http_time = Instant::now();
                i.http_start = start;
                i.http_end = end;
                i.http_socket = Some(stream);
                if i.eof >= i.http_end && !i.serve_http_if_any_is_ready() {
                    i.next_block = start as usize / BLOCK_SIZE!();
                    if i.peers.len() > 0 {
                        for _ in 0..(1 + 50 / i.peers.len()) {
                            i.request_blocks(ps, i.peers.clone());
                        }
                    } else {
                        let to_try = ps.best_peers(500, 20);
                        debug!("http starting search  with {} hosts",to_try.len());
                        i.request_blocks(ps, ps.best_peers(500, 20));
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
pub fn handle_stdin(ps: &mut PeerState, inbound_states: &mut HashMap<String, InboundState>) {
    let mut line = String::new();
    io::stdin().read_line(&mut line).unwrap();
    if line.len() > 1 {
        let mut arg: String = "".to_string();
        let mut arg2: String = "".to_string();
        if sscanf!(line.as_str(), "/get {}",arg).is_ok() {
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
            println!("========== active IP4 peer/ports");
            for v in ps.peer_vec.iter().rev() {
                if let IpAddr::V4(ip) = v.ip() {
                    let d = ps.peer_map[v].delay;
                    if d < Duration::from_secs(1) {
                        println!("{:02x}{:02x}{:02x}{:02x}:{:04x} {:21?} {:21}",
ip.octets()[0], ip.octets()[1], ip.octets()[2], ip.octets()[3],
v.port(),
                        d,
                        v);
                    }
                }
            }
            println!("{} total active peers",ps.peer_map.len());
            let mut unique_ips = HashSet::new();
            println!("========== all IPs");
            for (k, _) in &ps.peer_map {
                if unique_ips.insert(k.ip()) {
                    println!("{:21} {}",k.ip(),if let Ok(hn)= dns_lookup::lookup_addr(&k.ip()) { hn } else { k.ip().to_string()});
                }
            }
            println!("{} total unique IP peers",unique_ips.len());
        } else if sscanf!(line.as_str(), "/recommend {}",arg).is_ok() {
            ps.p.you_should_see_this = Some(YouSouldSeeThis {
                id: arg.to_owned(),
                length: File::open("./cjp2p/public/".to_owned() + &arg)
                    .unwrap()
                    .metadata()
                    .unwrap()
                    .len(),
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
        } else if line == "/help\n" {
            println!("
                        - /ping
                        - /get hash
                        - /list
                        - /recommend hash
                        - /recommended
                        - /trending
                        - /peers
                        - /msg [ip:port or 0xPubKey] msg
                        - /version
                        - /help
                ");
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
