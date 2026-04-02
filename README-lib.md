This implements everything in spotted and listed in the https://github.com/kermit4/cjp2p protocol tracking repo, plus some other things.   

This will make available any files in the directory ./cj2p/public  It will ignore any requests for anything that has a / or \ in it.

# Usage
```rust
    use std::os::unix::fs::FileExt;

    let mut ps: PeerState = PeerState::new();
    let mut read_fds = FdSet::new();
    let mut inbound_states: HashMap<String, InboundState> = HashMap::new();
    id = "...."
    let download = InboundState::new(id, &ps);
    inbound_states.insert(id.to_string(), download);

    read_fds.insert(ps.socket.as_fd());
    loop {
        select( None, &mut read_fds, None, None, &mut (nix::sys::time::TimeVal::new(1, 0))).unwrap();
        libcjp::maintenance(&mut inbound_states, &mut ps); // this only does anything once per second
        if read_fds.contains(ps.socket.as_fd()) {
            handle_network(&mut ps, &mut inbound_states);
        }
    }


```
Except half the point of this is that it's easily expansible, and I have no idea how to do that with Rust libraries, or if you're even supposed to.  i.e. add fields to messages, add new messages, ignore messages, add handling to messages, i.e. expand on the code not just call it.  So maybe it's better to copy/fork the source than use the library.

This uses 10KB/s at idle.

# TODO
- try some HashMap of message handlers instead of enum+enum_dispatcher, so an appliction can replace, expand, add, or remove, messages?  or maybe somehow put the core loop steps more in the application side so it can replace the enum?. or maybe something with "dyn"?
- really need metadata for /list and /recommended and /trending
- make it so users of lib can add message types
## cryptography/scarcity related
- more encryption? by default? the asymmetric encryption i have is 10x as much CPU as none.  symmetric might be  fast
- trust 
- valuable numbers? (PoW)
- proof of latency? signature chain of somewhat verifiable latency?
- thanks/reputation. auto thanks on succesful get.
- direct referal trust or public reputation..and is that the scarcity or something else like ipv4 addresses or work.
- https://howtofixtheweb.com/
## near-real time things - may overlap 
- news feed
- group chats
## unnsorted
- 6/4x the CPU to send/receive content encrypted. why?
- need metadata for large files, then finish lib
- some equivalent of wikipedia
