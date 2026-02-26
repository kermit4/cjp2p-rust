This implements everything in spotted and listed in the https://github.com/kermit4/cjp2p protocol repo.

This will make available any files in the directory ./shared  It will ignore any requests for anything that has a / or \ in it.

To request a file, run with the content_id as an arguement.  It will be placed in ./shared/incoming/ until it is complete, then moved to ./shared

i.e. 

     ./target/debug/cjp2p  c3514bf0056180d09376462a7a1b4f213c1d6e8ea67fae5c25099c6fd3d8274b # ubuntu-24.04.3-live-server-amd64.iso


# building
 cargo build

# hints

try running with RUST_BACKTRACE=1 RUST_LOG=debug ./target/debug/cjp2p

try make demo to get 1GB in 1MB chunks

or info/warn log levels

the debug build won't care if you dont send AlwaysReturned, so easier for testing, but the debug build is slower.

# TODO
- need sub-hashes otherwise a bad bit may copy aroundd and the file may never complete correctly anywhere .. https://dasl.ing/ ?  blake3?
- streaming (files that grow after they're started.. with a goal that someone streaming video to millions only needs enough bandwidth to send out one copy, live, with little delay.  Multicast, as real multicast never caught on on the internet sadly.).. i think the code is there, it just needs to say to not stop, infinite EOF, or just make eof optional..as all fields should be

- remember to talk like people not a computer (naming)
- 
- this should be like a daemon, runnin locally, things can communate through it, rather than speak it directly?  localhost URLs?
- 
- streaming live cam of somethin is a good test case.. the sky .. ffmpeg -i /dev/video2 o.mkv .. 
- 
- lossy real time streams? it would require knowing the media's container block boundaries
- 
- CLI commands  / API, run as a daemon?  do we want each app speaking the protocol or using a daemon("node")?
- mplayer seekable streams.   cli search.    
- should be some delay if a hash doesnt match so it doest loop forever eating bandwidth
- make this a rust crate? libcjp
- how would end users best interact? through a browser? how about sending or streaming
- probably less unwrap and more questoin marks
- encryption? snow crate / noise protocol 
- it could track hosts by public key not host port to get rid of the issuew with these weird rolling port nats
- if content exists, but there is no AlwaysReply key, send one byte, so a big search can at least ind it even if it doesnt have the key
- worry less about DOS stuff right now, deal with that later, make it easy to use right now
