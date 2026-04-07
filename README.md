This implements everything in spotted and listed in the https://github.com/kermit4/cjp2p protocol repo, plus some other things.   The primary purpose of this repo, is to demonstrate sample use cases of the CJP2P protocol.

It's functional for end users, but the current target audience is p2p devs, so the UI IS minimal and not clearly documented.

This will make available any files in the directory ./cj2p/public  It will ignore any requests for anything that has a / or \ in it.


# building

"cargo build" or "make"

# running

./target/debug/cjp2p

or 

RUST_LOG=info ./target/debug/cjp2p


This uses 10KB/s at idle (almost 1GB/day).  It seems to not use a lot of battery but I haven't done long tests and there's still a small risk it'll spin net/cpu due to some bug, as the only version is currently very experimental.

You can copy cjp2p/state/key.json to another system/phone if you want and it should do what you'd expect.

# hints


Try /help
Try /get c3514bf0056180d09376462a7a1b4f213c1d6e8ea67fae5c25099c6fd3d8274b (its ubuntu-24.04.3-live-server-amd64.iso )

or watch Sintel http://127.0.0.1:24255/43a39a05ce426151da3c706ab570932b550065ab4f9e521bb87615f841517cf1 in a browser. Check out the amazing seek time!

or the status page (soon to be a WEB INTERFACE that looks like a console.) http://127.0.0.1:24255/

or HTML pages with many page components, individually downloaded from the network live (unless you already did.)
- http://127.0.0.1:24255/c0b5426d0ccce3b647aaff4adf4b2aaead97aa626c5db29f77b8886efaa730c6 random img src
- http://127.0.0.1:24255/96b375185bb9cb1ff8aecea12480b0663749d0afb1e8ffa8f32b8d6e48b90f10 1000 random img src
- http://127.0.0.1:24255/fb132816910cda37494d2c1ec70b6bc92f9bc4b129842e7f4e9d16aac789ac3f wikipedia JSON page, with dependancies, made with ./html_slurp.sh https://en.wikipedia.org/wiki/JSON
- http://127.0.0.1:24255/d70caf078afe39d38f63b86c0f03a70a4722773e3021c487d5e9852750d8c17a   made with ./html_slurp.sh  https://en.wikipedia.org/wiki/Earth 
- http://127.0.0.1:24255/380e9e5a09e5b0564e442a17f3bf054a07046323237bd60f2cd6834bbb45d14e  https://en.wikipedia.org/wiki/Geological_history_of_Earth


# TODO
## general 
- remember to talk like people not a computer (naming, especially on the wire)
- make it easy for other people to build on, even if they dont know rust? /on to add functionality? scriptable?
## UI
-   can browsers be p2p nodes in tab?  though if not, a browser plugin isnt inconceiveable.  https://github.com/webtorrent/webtorrent  webrtc but webtransport is probably better now
## cryptography or scarcity related
- trust 
- valuable numbers? (PoW?  or valuable just because the issuer, based on their public key, limits the issuance.  every person their own "coin" as value derived from their reputation?  reputation granting fungible negotiable scarcity? be your own CENTRAL bank!)
- proof of latency? signature chain of somewhat verifiable latency?
- reputation
- thanks based reputation. auto-thanks on succesful get.
- direct referal trust or public reputation..and is that the scarcity or something else like ipv4 addresses or work.
- read this again https://howtofixtheweb.com/
- more encryption? by default?   for debugging (tcpdump) its much easier to leave this off for now, but could be a command line option.  and its a bit slow with Noise unless they save state, 4x the CPU on to send/receive encrypted.  why? 4x block size makes  it only 70% slower though, but it still seems somewhat high.  its because Noise is doing DH even for one-way communication which is silly.  using N type and "into_transport_mode" on both sides after the 1st message is fast, but i think it needs state on both sides, to hold ephemeral keys i assume.  maybe use https://docs.rs/aes-gcm/latest/aes_gcm/ instead of Noise
## near-real time things - may overlap 
- news feed
- once there is economics, sell services
- group chats
## public collaboration
- reviews of content
-  some equivalent of wikipedia
## unnsorted
- make it do what i actually do each day, check for news basically, from friends or weigthed by importance/distance. like /trending but scoped/weighted.  user defined algorithm. get /trending into a nice /UI ..  make it do it well, easy, streamlined, in browser, and to select 2nd and third most trending, an most popular, etc.
- alerts if a large set of IPs stop responding suddenly - this is basically why i check the news constantly
- need metadata for large files, a list of 256k block hashes (256k of 64 byte hashes is  2^12, so files over 2^30 may want another layer of hashing, over 4TB yet another.), so in-transit corruption recovers faster, and also files can be relayed before compelete (which would enable streaming)
- images and html over 4M dont render well in brave.  It only handles partial content for videos.  rewrite http handler to use non-blocking tcp writes and serve complete content. also curl doesn't like it.
- really need working demo html pages
- reputation, ip-time?
- 4M is a slow seek, let it serve some before its all there? will it render early though? or just chop 256k for video only for fast seeks..etry it and see how it improves
