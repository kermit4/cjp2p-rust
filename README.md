This implements everything in spotted and listed in the https://github.com/kermit4/cjp2p protocol repo, plus some other things.   The primary purpose of this repo, is to demonstrate sample use cases of the CJP2P protocol.

It's functional for end users, but the current target audience is p2p devs, so the UI IS minimal and not clearly documented.

This will make available any files in the directory ./cj2p/public  It will ignore any requests for anything that has a / or \ in it.


# building
"cargo build" or "make"

# hints

try running with RUST_BACKTRACE=1 RUST_LOG=debug ./target/debug/libcjp
or info/warn log levels

Try /help
Try /get c3514bf0056180d09376462a7a1b4f213c1d6e8ea67fae5c25099c6fd3d8274b (its ubuntu-24.04.3-live-server-amd64.iso )

or watch Sintel http://127.0.0.1:24255/43a39a05ce426151da3c706ab570932b550065ab4f9e521bb87615f841517cf1 in a browser. Check out the amazing seek time!

or inlined images in HTML loaded live 
- http://127.0.0.1:24255/c0b5426d0ccce3b647aaff4adf4b2aaead97aa626c5db29f77b8886efaa730c6 random img src
- http://127.0.0.1:24255/8714bb72411457c9e0c6ea00118690eb495eaba68df9c0404a7b00d286a1d8d1  ./html_slurp.sh https://commons.wikimedia.org/wiki/Category:Fossils  -- lots of images in an html page - the few broken images are due to issues with wget and possibly html_slurp.sh's handling of special characters in URLs, not this software
- http://127.0.0.1:24255/96b375185bb9cb1ff8aecea12480b0663749d0afb1e8ffa8f32b8d6e48b90f10 1000 random img src
- http://127.0.0.1:24255/fb132816910cda37494d2c1ec70b6bc92f9bc4b129842e7f4e9d16aac789ac3f wikipedia JSON page, with dependancies, made with ./html_slurp.sh https://en.wikipedia.org/wiki/JSON
- http://127.0.0.1:24255/d70caf078afe39d38f63b86c0f03a70a4722773e3021c487d5e9852750d8c17a   made with ./html_slurp.sh  https://en.wikipedia.org/wiki/Earth --wait 1   

src/lib.rs is also at https://crates.io/crates/libcjp but this probably isn't useful as a crate, as it's examples to build from, not strict implementations, so it's probably better to copy or fork this repo than use it, as I don't see how you would arbitrarily override parts of a crate in Rust.  

# TODO
## general 
- remember to talk like people not a computer (naming, especially on the wire)
- make it easy for other people to build on, even if they dont know rust? /on to add functionality? scriptable?
## UI
- CLI commands  / API?  or just as curl//REST examples, not CLI
- how would end users best interact? through a browser? how about sending or streaming
- how can users easily and excitedly use decentralized software in place of centralized...easy plus a draw..whats hot and trending, what peers respect, an algorithm but that they control
- more / commands
- http quickstart and acceleration need work, maybe just request the whole thing as soon as it knows a peer  .. user waiting is much more important than maintaining some low packet loss
- easy web UI - just interface on the / commands
- really need metadata for /list and /recommended and /trending
-   can browsers be p2p nodes in tab?  though if not, a browser plugin isnt inconceiveable.  https://github.com/webtorrent/webtorrent  webrtc but webtransport is probably better now
## cryptography related
- more encryption? by default? the asymmetric encryption i have is 10x as much CPU as none.  symmetric might be  fast
- trust 
- valuable numbers? (PoW)
- proof of latency? signature chain of somewhat verifiable latency?
- reputation
- thanks based reputation. auto-thanks on succesful get.
- direct referal trust or public reputation..and is that the scarcity or something else like ipv4 addresses or work.
- read this again https://howtofixtheweb.com/
- 6/4x the CPU to send/receive content encrypted. why.
## near-real time things - may overlap 
- news feed
- once there is economics, sell services
- group chats
## public collaboration
- reviews of content
-  some equivalent of wikipedia
## unnsorted
- make it do what i actually do each day, check for news basically. /trending is all i really do. but, i may want to weight some sources higher. well, do that later. get /trending into a nice /UI ..  make it do it well, easy, streamlined, in browser, and to select 2nd and third most trending, an most popular, etc.
- alerts if a large set of IPs stop responding suddenly - this is basically why i check the news constantly
- need metadata for large files
- images and html over 4M dont render well in brave.  It only handles partial content for videos.  rewrite http handler to use non-blocking tcp writes and serve complete content. also curl doesn't like it.
