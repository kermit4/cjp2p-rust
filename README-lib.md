This implements everything in spotted and listed in the https://github.com/kermit4/cjp2p protocol tracking repo, plus some other things.   

This will make available any files in the directory ./cj2p/public  It will ignore any requests for anything that has a / or \ in it.

# Usage
```rust
    use std::os::unix::fs::FileExt;

    let mut ps: PeerState = PeerState::new();
    let mut read_fds = FdSet::new();
    read_fds.insert(ps.socket.as_fd());
    loop {
        select( None, &mut read_fds, None, None, &mut (nix::sys::time::TimeVal::new(1, 0))).unwrap();
        if read_fds.contains(ps.socket.as_fd()) {
            handle_network(&mut ps, &mut inbound_states);
        }
    }


```


# TODO
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
