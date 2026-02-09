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
- save inbound peers list to share with others even after its done
- save peers looking for content to share with others looking for it so they can collaborate
- need sub-hashes otherwise a bad bit may copy aroundd and the file may never complete correctly anywhere .. https://dasl.ing/ ?  blake3?
- some way to not be used as a DDOS as people can spoof their IPs in a request for peers or contont
- streaming (files that grow after they're started.. with a goal that someone streaming video to millions only needs enough bandwidth to send out one copy, live, with little delay.  Multicast, as real multicast never caught on on the internet sadly.).. i think the code is there, it just needs to say to not stop, infinite EOF, or just make eof optional..as all fields should be

maybe replies just include the original request but note that it is a reply, so cookies and all data are there even if not used by replier, rather than separate message types? this would be less code?
 
remember to talk like people not a computer (naming)

this should be like a daemon, runnin locally, things can communate through it, rather than speak it directly?  localhost URLs?

streaming live cam of somethin is a good test case.. the sky .. ffmpeg -i /dev/video2 o.mkv .. 

lossy real time streams? it would require knowing the media's container block boundaries

try all interfaces' broadcast addresses

CLI commands  / API, run as a daemon?  do we want each app speaking the protocol or using a daemon("node")?
