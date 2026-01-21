use base64::{engine::general_purpose, Engine as _};
use bit_vec::BitVec;
use serde_json::{json, Map, Value, Value::Null};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::convert::TryInto;
use std::env;
use std::fmt;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::copy;
use std::mem::transmute;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::str;
use std::time::{Duration, SystemTime};
use std::vec;

fn walk_object(name: &str, x: &Value, result: &mut Vec<String>) {
    let Value::Object(x) = x else { return };
    println!("name {:?}", name);
    println!("value {:?}", x);
    result.push(name.to_string());
    for (name, field) in x {
        println!("name {:?}", name);
        println!("field {:?}", field);
        walk_object(&name, field, result);
    }
}

fn main() -> Result<(), std::io::Error> {
    let mut peers: HashSet<SocketAddr> = HashSet::new();
    peers.insert("159.69.54.127:24254".parse().unwrap());
    peers.insert("148.71.89.128:24254".parse().unwrap());
    let socket = UdpSocket::bind("0.0.0.0:24254")?;
    std::env::set_current_dir("./pejovu");
    let mut peer_i = peers.iter();
    socket.send_to(b"[]", peer_i.next().unwrap()); // just so anyone knows i exist
    let mut args = env::args();
    args.next();
    use std::collections::HashMap;
    //    let mut inbound_states = HashMap::new();
    //    for v in args {
    //      request_content(&socket,peers,&inbound_states,v);
    //}
    loop {
        let mut buf = [0; 0x10000];
        let (_amt, src) = socket.recv_from(&mut buf).expect("socket err");
        let object: Vec<Value> = serde_json::from_slice(&buf[0.._amt]).unwrap();
        peers.insert(src);
        let mut message_out :  Vec<Value> = Vec::new();
        for message_in in &object {
            println!("type {}", message_in);
            println!("type {}", message_in["message_type"]);
                let reply= 
                json!( 
            match message_in["message_type"].as_str().unwrap() {
                "Please send peers." => send_peers(&peers),
                "These are peers." => receive_peers(&mut peers, message_in),
                //                "Please send content." => send_content(&peers, message_in),
                //                "Here is content." => receive_content(&socket, src, &peers, message_in),
                _ => json!(serde_json::Value::Null),
            }
            );
            if reply != Null { message_out.push(json!(reply)) }; 
            let mut result = vec![];
            walk_object("rot", message_in, &mut result);
            println!("{:?}", result);
        }
        let message_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
        println!("sending message {:?}", str::from_utf8(&message_bytes));
        socket.send_to(&message_bytes, src);
    }
    Ok(())
}

fn send_peers(peers: &HashSet<SocketAddr>) -> Value {
    println!("sending peers {:?}", peers);
    let p: Vec<SocketAddr> = peers.into_iter().cloned().collect();
    return json!(
        {"message_type": "These are peers.",
        "peers":  serde_json::to_value(p).unwrap()});
}

fn receive_peers(peers: &mut HashSet<SocketAddr>, message: &Value) -> Value {
    for p in message["peers"].as_array().unwrap() {
        println!(" a peer {:?}", p);
        let sa: SocketAddr = p.as_str().unwrap().parse().unwrap();
        peers.insert(sa);
    }
    return json!(serde_json::Value::Null);
}

//fn send_content(
//    socket: &UdpSocket,
//    src: SocketAddr,
//    peers: &HashSet<SocketAddr>,
//    message_in: &Value,
//) -> () {
//    if message_in["content_sha256"].as_str().unwrap().find("/") != None
//        || message_in["content_sha256"].as_str().unwrap().find("\\") != None
//    {
//        return;
//    };
//    let mut file = File::open(message_in["content_sha256"].as_str().unwrap()).unwrap();
//    let mut to_read = message_in["content_length"].as_u64().unwrap() as usize;
//    if to_read > 4096 {
//        to_read = 4096
//    }
//    let mut content = vec![0; to_read];
//    let content_length = file
//        .read_at(&mut content, message_in["content_offset"].as_u64().unwrap())
//        .unwrap();
//    let content_b64: String = general_purpose::STANDARD_NO_PAD.encode(content);
//    let mut message_out = json!([
//        {"message_type": "Here is content.",
//        "content_sha256":  message_in["content_sha256"],
//        "content_offset":  message_in["content_offset"],
//        "content_b64":  content_b64,
//        }
//    ]);
//    let message_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
//    println!("sending content {:?}", str::from_utf8(&message_bytes));
//    socket.send_to(&message_bytes, src);
//}
//
//fn receive_content(
//    socket: &UdpSocket,
//    src: SocketAddr,
//    peers: &HashSet<SocketAddr>,
//    message_in: &Value,
//) -> () {
//    if message_in["content_sha256"].as_str().unwrap().find("/") != None
//        || message_in["content_sha256"].as_str().unwrap().find("\\") != None
//    {
//        return;
//    };
//        inbound_state=inboundd_states[message_in["content_sha256"].as_str()]
//        if inbound_state == None { return;}
//    let content_bytes = general_purpose::STANDARD_NO_PAD
//        .decode(message_in["content_b64"].as_str().unwrap())
//        .unwrap();
//    inbound_state.file.write_at(
//        &content_bytes,
//        message_in["content_offset"].as_u64().unwrap(),
//    );
//        inbound_state.blocks_remaining -= 1;
//        inbound_state.bitmap.set(message_in["content_offset"] as usize, true);
//        request_content_block(&socket,&peers,&inbound_state,&sha256);
//        if !(inbound_state.blocks_remaining %100)
//        request_content_block(&socket,&peers,&inbound_state,&sha256);
//}
////
////fn request_content_block(
////    socket: &UdpSocket,
////    peers: &HashSet<SocketAddr>,
//    inbound_state: &InboundState,
//    sha256: String
//) -> () {
//        if inbound_state.blocks_remaining == 0 {
//            offset = inbound_state.next_block;
//            //                println!("{}",inbound_state.bitmap.iter().position(|x| x == false ).unwrap());
//            while {
//                inbound_state.next_block += 1;
//                inbound_state.next_block %= blocks(inbound_state.len);
//                inbound_state.bitmap.get(inbound_state.next_block as usize).unwrap()
//            } {}
//        }
//    let mut message_out = json!([
//        {"message_type": "Pleae send content.",
//        "content_sha256":  inbound_state.sha256,
//        "content_offset":  inbound_state.next_block*4096,
//        "content_length": 4096,
//        }
//    ]);
//    let message_bytes: Vec<u8> = serde_json::to_vec(&message_out).unwrap();
//    println!("sending content {:?}", str::from_utf8(&message_bytes));
//    socket.send_to(&message_bytes, src);
//}
//
//fn request_content(
//    socket: &UdpSocket,
//    peers: &HashSet<SocketAddr>,
//    inbound_states: HashMap;
//    sha256: String
//)  -> () {
//    fs::create_dir("./incoming");
//    let path = "./incoming/".to_owned() + message_in["content_sha256"].as_str().unwrap();
//        inbound_states.insert(v,
//            InboundState {
//                file:  // File::create(
//    OpenOptions::new()
//        .create(true)
//        .read(true)
//        .write(true)
//        .open(path)
//        .unwrap();
//                len: self.len,
//                blocks_remaining: blocks(self.len),
//                next_block: 1,
//                bitmap: BitVec::from_elem(blocks(self.len) as usize, false),
//            }
//        );
//        request_content_block(&socket,&peers,&inbound_state,&sha256);
//        request_content_block(&socket,&peers,&inbound_state,&sha256);
//}
//
//struct InboundState {
//    file: File,
//    len: u64,
//    blocks_remaining: u64,
//    next_block: u64,
//    bitmap: BitVec,
//}
//
//
