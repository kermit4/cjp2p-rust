This implements everything in spotted and listed in the https://github.com/kermit4/cjp2p protocol repo.

This will make available any files in the directory ./shared  It will ignore any requests for anything that has a / or \ in it.

To request a file, run with the content_id as an arguement.  It will be placed in ./shared/incoming/ until it is complete, then moved to ./shared

i.e. 

     ./target/debug/cjp2p  c3514bf0056180d09376462a7a1b4f213c1d6e8ea67fae5c25099c6fd3d8274b # ubuntu-24.04.3-live-server-amd64.iso


# building
 cargo build

# hints

try running with RUST_BACKTRACE=1 RUST_LOG=debug ./target/debug/cjp2p

for fun try:

```
make demo
# ^C when it seems done, and then
(cd shared
cat $(cat                                                                                                                   562b168a64967fd64687664b987dd1c50c36d1532449bb4c385d683538c0bf03 )) |
sha256sum    
# should be  6f5a06b0a8b83d66583a319bfa104393f5e52d2c017437a1b425e9275576500c
```

or info/warn log levels

the debug build won't care if you dont send AlwaysReturned, so easier for testing, but the debug build is slower.

# TODO
- need sub-hashes otherwise a bad bit may copy aroundd and the file may never complete correctly anywhere .. https://dasl.ing/ ?  blake3?
- streaming (files that grow after they're started.. with a goal that someone streaming video to millions only needs enough bandwidth to send out one copy, live, with little delay.  Multicast, as real multicast never caught on on the internet sadly.).. i think the code is there, it just needs to say to not stop, infinite EOF, or just make eof optional..as all fields should be
- remember to talk like people not a computer (naming)
- this should be like a daemon, runnin locally, things can communate through it, rather than speak it directly?  localhost URLs?
- streaming live cam of something is a good test case.. the sky .. ffmpeg -i /dev/video2 o.mkv .. 
- lossy real time streams? it would require knowing the media's container block boundaries
- CLI commands  / API, run as a daemon?  do we want each app speaking the protocol or using a daemon("node")?
- mplayer seekable streams.   cli search.    
- make this a rust crate? libcjp
- how would end users best interact? through a browser? how about sending or streaming
- probably less unwrap and more questoin marks
- encryption? snow crate / noise protocol 
- it could track hosts by public key not host port to get rid of the issuew with these weird rolling port nats
- send peers when asking for them? why not, be nice, save a RTT?
- try again to move some inbound state stuff to the implementation of inbound state
