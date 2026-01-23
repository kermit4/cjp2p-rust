This implements the https://github.com/kermit4/pejovu protocol.

This will make available any files in the directory ./pejovu  It will ignore any requests for anything that's not a sha256, so as long as Rust's JSON parser (Serde) doesn't have an exploit, it seems safe to leave running.

It currently assumes the filenames are their sha256 (maybe link them to their ordinary names for now)

This is very early in development, so people can send you files you didn't request, or sabotage transfers by sending invalid data.  Contributors are welcome. 

To request a file, run with the sha256 as an arguement.  It will be placed in ./pejovu/incomplete/<sha256> until it is complete.

File sharing is a primitive example common use case, not the only intended purpose.

# TODO
- save peer list 
- chose random port on first run, but then stick with it on restarts
- cookies so its not used for a DDOS, as people can spoof their source IPs
- need sub-hashes otherwise a bad bit may copy aroundd and the file may never complete correctly anywhere

maybe replies just include request and that it is a reply, so cookies and all data are there even if not used by replier
 
cookie as its own message.  be sure to call part timestamp too  so people dont cache it

timer to say hey and ask whatsup



try running with RUST_BACKTRACE=1 RUST_LOG=debug ./target/debug/pejovu
or info/warn log levels
