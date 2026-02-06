This implements the https://github.com/kermit4/cjp2p protocol.

This will make available any files in the directory ./cjp2p  It will ignore any requests for anything that has a / or \ in it, so as long as Rust's JSON parser (Serde) doesn't have an exploit, it seems safe to leave running.

To request a file, run with the content_id as an arguement.  It will be placed in ./cjp2p/incomplete/ until it is complete, then moved to ./cjp2p

i.e. 

     ./target/debug/cjp2p 3d5486b9e4dcd259689ebfd0563679990a4cf45cf83b7b7b5e99de5a46b5d46f  # abe_lincoln_of_the_4th_ave.mp4


# building
 cargo build

# hints

try running with RUST_BACKTRACE=1 RUST_LOG=debug ./target/debug/cjp2p

or info/warn log levels

# TODO
- rel-let instead of mut?
- broahcast and multicast peer discovery..listen on known and unknown ports?
- literally the most recently spoke to peers is probbaly the ones sending us data, so just suggest those with inbound state bumps, and ask for some in those too, to whoveer i expect will have the data so thta same loop..also occationally during xfer just ask them for peers, no sep list needed for now, its self solving, also this will include people asking for this data too
- chose random port on first run, but then stick with it between restarts, save in a config file json
- inboundstate - save peers known to have some of a file for stalls to resume without a search and window growth
- need sub-hashes otherwise a bad bit may copy aroundd and the file may never complete correctly anywhere .. https://dasl.ing/ ?  blake3?
- some way to not be used as a DDOS as people can spoof their IPs in a request for peers or contont
- streaming (files that grow after they're started.. with a goal that someone streaming video to millions only needs enough bandwidth to send out one copy, live, with little delay.  Multicast, as real multicast never caught on on the internet sadly.)
- for speed i suppose i could ask for big blobs, once i have the hash map

maybe replies just include request and that it is a reply, so cookies and all data are there even if not used by replier
 
cookie as its own message.  be sure to call part timestamp too  so people dont cache it

trim peers last seen or rtt? or both? and track unverified
ping new.   

randomize peer suggestions
, share more often than just at inactivity.   

remember to talk like people.        


this should be like a daemon, runnin locally, things can communate through it, rather than speak it directly?  localhost URLs?

streaming live cam of somethin is a good test case.. the sky .. ffmpeg -i /dev/video2 o.mkv .. 


streams...allow lossy for real time, must know where to break blocks and a codec that allows it
c
