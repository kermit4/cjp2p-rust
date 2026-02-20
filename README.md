This implements everything in spotted and listed in the https://github.com/kermit4/cjp2p protocol repo.

This will make available any files in the directory ./shared  It will ignore any requests for anything that has a / or \ in it, so as long as Rust's JSON parser (Serde) doesn't have an exploit, it seems safe to leave running.

To request a file, run with the content_id as an arguement.  It will be placed in ./shared/incoming/ until it is complete, then moved to ./shared

i.e. 

     ./target/debug/cjp2p  c3514bf0056180d09376462a7a1b4f213c1d6e8ea67fae5c25099c6fd3d8274b # ubuntu-24.04.3-live-server-amd64.iso


# building
 cargo build

# hints

try running with RUST_BACKTRACE=1 RUST_LOG=debug ./target/debug/cjp2p

or info/warn log levels

# TODO
- use Option in PleaseReturnThisMessage so it can be in the usual spot in the loop, just still send back unknown parts when getting one.
- save inbound peers list to share with others even after its done
- save peers looking for content to share with others looking for it so they can collaborate
- need sub-hashes otherwise a bad bit may copy aroundd and the file may never complete correctly anywhere .. https://dasl.ing/ ?  blake3?
- some way to not be used as a DDOS as people can spoof their IPs in a request for peers or contont
- streaming (files that grow after they're started.. with a goal that someone streaming video to millions only needs enough bandwidth to send out one copy, live, with little delay.  Multicast, as real multicast never caught on on the internet sadly.).. i think the code is there, it just needs to say to not stop, infinite EOF, or just make eof optional..as all fields should be

- maybe replies just include the original request but note that it is a reply, so cookies and all data are there even if not used by replier, rather than separate message types? this would be less code?
-  
- remember to talk like people not a computer (naming)
- 
- this should be like a daemon, runnin locally, things can communate through it, rather than speak it directly?  localhost URLs?
- 
- streaming live cam of somethin is a good test case.. the sky .. ffmpeg -i /dev/video2 o.mkv .. 
- 
- lossy real time streams? it would require knowing the media's container block boundaries
- 
- try all interfaces' broadcast addresses
- 
- CLI commands  / API, run as a daemon?  do we want each app speaking the protocol or using a daemon("node")?
- mplayer seekable streams.   cli search.    
- strace of the release build shows the peers.json loads one byte at a time. thats odd, understand why in case there are larger JSON files ever
- actually store sources for MaybeTheyHaveSome outside of just current transfers
- always MaybeTheyHaveSome for block 0 requests if any known
- should be some delay if a hash doesnt match so it doest loop forever eating bandwidth
