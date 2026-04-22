This uses https://github.com/kermit4/LCDP .   The primary purpose of this repo, is to demonstrate sample use cases of connectionless JSON (externally tagged) P2P aka the Lowest Common Denominator Protocol messaging, however there are some users of it now, usually using web interfaces over the websocket that speaks the same protocol though is handled somewhat differently as it's intended only for the node operator's browser.

The current target audience is devs, so the UI IS minimal and not clearly documented.   

This will make available any files in the directory ./cj2p/public  It will ignore any requests for anything that has a / or \ in it.


# building

make release

# running

./target/release/cjp2p

or 

RUST_BACKTRACE=1 RUST_LOG=info ./target/release/cjp2p

for some noise


This uses 10KB/s at idle (almost 1GB/day).  It seems to not use a lot of battery but I haven't done long tests, and there's still a small risk of bugs that will spin net/cpu.

You can copy cjp2p/state/key.json to other sysetems if you want and it should receive messages directed to it on all systems.

This also works on Android.

# hints


Try /help
Try /get c3514bf0056180d09376462a7a1b4f213c1d6e8ea67fae5c25099c6fd3d8274b (its ubuntu-24.04.3-live-server-amd64.iso )

or watch Sintel http://localhost:24255/43a39a05ce426151da3c706ab570932b550065ab4f9e521bb87615f841517cf1 in a browser. Check out the amazing seek time!

hand made status page http://localhost:24255/
Claude made status page http://localhost:24255/dashboard.html

or HTML pages with many page components, individually downloaded from the network live (unless you already did.)
- http://localhost:24255/c0b5426d0ccce3b647aaff4adf4b2aaead97aa626c5db29f77b8886efaa730c6 random img src
- http://localhost:24255/96b375185bb9cb1ff8aecea12480b0663749d0afb1e8ffa8f32b8d6e48b90f10 1000 random img src
- http://localhost:24255/b98d4a019a3b4cb29c1a0207f9f60dd5302d611374667fb3ea4b1a671ad9bf99  https://commons.wikimedia.org/wiki/Category:Fossils made with SingleFile browser plugin (for firexfox or chrome) (works much better than wget and my html_slurp.sh but becausue its inlining the images so doesnt really demonstrate the get-lots-of-little-files-quickly capabilities of this )
- http://localhost:24255/245dfbdcd947e8cb4bf650846da7e7c7042d7a39c2fa31df541312dc9722234b the world's most censored news site.. to click any links on this, if you're in the EU, you may have to change your DNS provider. Most browsers have an option.  
- http://localhost:24255/fb132816910cda37494d2c1ec70b6bc92f9bc4b129842e7f4e9d16aac789ac3f wikipedia JSON page, with dependancies, made with ./html_slurp.sh https://en.wikipedia.org/wiki/JSON
- http://localhost:24255/d70caf078afe39d38f63b86c0f03a70a4722773e3021c487d5e9852750d8c17a   made with ./html_slurp.sh  https://en.wikipedia.org/wiki/Earth 
- http://localhost:24255/380e9e5a09e5b0564e442a17f3bf054a07046323237bd60f2cd6834bbb45d14e  https://en.wikipedia.org/wiki/Geological_history_of_Earth



# TODO
## general 
- remember to talk like people not a computer (naming, especially on the wire)
- make it easy for other people to build on, make easy for UI devs on websockets
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
## updateable content
- for distirbuting latest versions of things, maybe a homepageish thing for key, generally avaliable with a seq number, signed home page, with which newer content can be linked?  or just any pages signed by pubs, its how to find the newest thats the trick.. oh just give people latest urls that always pull from me not by hash..and dont error in the app about it
- content NAMES..updateable only be the pub who initially issued it, (i.e. chat5, by me)
## unnsorted
- make it do what i actually do each day, check for news basically, from friends or weigthed by importance/distance. like /trending but scoped/weighted.  user defined algorithm. get /trending into a nice /UI ..  make it do it well, easy, streamlined, in browser, and to select 2nd and third most trending, an most popular, etc.
- need metadata for large files, a list of 256k block hashes (256k of 64 byte hashes is  2^12, so files over 2^30 may want another layer of hashing, over 4TB yet another.), so in-transit corruption recovers faster, and also files can be relayed before compelete (which would enable streaming)
- reputation, ip-time? web of trust (people approve other people)? 
- polls, approval voting style..which need some kind of scarcity
- drop in socket() replacement that takes public keys intead of ips(), in Rust crate?
- group chat 
- public websocket support? / gateway /  consider more the model where anyone can connect to any node but keep the identity and security browser side
- put nostr or bitcoin addr in chat too ..however that is signed
- put this as a git bundle in cjp2p/public
- putting git files in cjp2p/public is breaking a git pull if the directory is beyond is a symlink
- my putting plain names in public/ will go badly for anyone who doest have thetm and tries to get them ..just think of what i need to do for me and the fastest way to do it, htats how it will be done.. it doesnt have to be authenticated , as long as it CAN be later, just automate what i do, thats my specialtiy, and if a file is deleted and someone uses the URL it will have unpredictable results
- lcdp crate now? send to ed25519 as the base theme with the big hash getter should be core?
- more orderly chat with history on dashboard page, like make this a social focused space 
- find by eth faster for 1st time users of OnePlus, assuming the other side already has /  aggressive search for pubs and eth addrs for chriss app OnePlusOne
- put this on radicle? at least look at it more
- when people publish UIs to this, on this, there sholud be an easy directory of those, and with latest versions, and shown right on the status page
- web of trust, reputation is not absolute, its from your point of view, that solves sybil attacks
- any aggressive scans should monitor latency and loss consequences and throttle both max bw and max hosts/sec because they are often separate limits on consumer routers even without NAT (DMZ/ipv6)
- browser light node, its easy, just treat non-localhost as network..easy, right? hows routing work
- have Claude make a .apk of the node and one of those built in webbrowsers that dont look like it is a web browser exactly so it can just reuse the same html thats already used for node+browser setups.  lets see what this bot can do!
- maybe with clauds new multi ID support, manage your signatures page separately fro the chat that's not working
- audio on video.html is 85% overhead..i thought i fixed that
- if streaming video is a signed list of hashes, just sign the video itself, then i can multisource per packet, the encryption does hashing already i think?
