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
- save peer list between restarts to not depend on the hard coded list .. but not before a way to expiring them.
- send_peers and bump_inbounds should chose more intelligently, randomly is better than first 50, ideally a vector sorted by responsiveness and chosen somewhat ranomly with a lean to the closer hosts
- chose random port on first run, but then stick with it between restarts, save in a config file json
- need sub-hashes otherwise a bad bit may copy aroundd and the file may never complete correctly anywhere
- some way to not be used as a DDOS as people can spoof their IPs in a request for peers or contont
- streaming
-- prioritize earlier packets to improve streaming 

maybe replies just include request and that it is a reply, so cookies and all data are there even if not used by replier
 
cookie as its own message.  be sure to call part timestamp too  so people dont cache it

timer to say hey and ask whatsup

trim peers last seen or rtt? or both? and track unverified
ping new.   

randomize peer suggestions
, share more often than just at inactivity.   

remember to talk like people.        
