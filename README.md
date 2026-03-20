This implements everything in spotted and listed in the https://github.com/kermit4/cjp2p protocol repo, plus some other things.   The primary purpose of this repo, is to demonstrate sample use cases of the CJP2P protocol.

This will make available any files in the directory ./cj2p/public  It will ignore any requests for anything that has a / or \ in it.

To request a file, run with the content_id as an arguement.  It will be placed in ./cjp2p/incoming/ until it is complete, then moved to ./cjp2p/public

i.e. 

     ./target/release/libcjp  c3514bf0056180d09376462a7a1b4f213c1d6e8ea67fae5c25099c6fd3d8274b # ubuntu-24.04.3-live-server-amd64.iso


# building
 cargo build

# hints

try running with RUST_BACKTRACE=1 RUST_LOG=debug ./target/debug/libcjp
or info/warn log levels

for fun try: make demo, ^C when it seems done, and then
```
(cd shared/public
cat $(cat                                                                                                                   562b168a64967fd64687664b987dd1c50c36d1532449bb4c385d683538c0bf03 )) |
sha256sum    
# should be  6f5a06b0a8b83d66583a319bfa104393f5e52d2c017437a1b425e9275576500c
```

or Sintel http://127.0.0.1:24254/43a39a05ce426151da3c706ab570932b550065ab4f9e521bb87615f841517cf1 in a browser. Check out the amazing seek time!

or inlined images in HTML loaded live 
- http://127.0.0.1:24254/c0b5426d0ccce3b647aaff4adf4b2aaead97aa626c5db29f77b8886efaa730c6 random img src
- http://127.0.0.1:24254/3c7fae70df52af6cc784d9ce9fce234fb930da3fbd04f72c3365b438f2c5e6bb wikipedia JSON page, with dependancies, made with ./html_slurp.sh https://en.wikipedia.org/wiki/JSON --wait 1 
- http://127.0.0.1:24254/d70caf078afe39d38f63b86c0f03a70a4722773e3021c487d5e9852750d8c17a   made with ./html_slurp.sh  https://en.wikipedia.org/wiki/Earth --wait 1   

typing stdin sends a chat message to a mostly random set of peers, but there are some / commands:
- /ping

typing stdin sends a chat message to a mostly random set of peers, but there are some / commands:
- /ping
- /get hash
- /list
- /recommend <hash>
- /recommended
- /trending
- /peers
- /msg [ip:port or 0xPubKey] msg

This is also at https://crates.io/crates/libcjp but probably isn't useful as a crate yet.  

# TODO
## general 
- remember to talk like people not a computer (naming, especially on the wire)
## lib
- daemon or library?  library with daemon as one implementation
- make this crate more useful and proper   https://rust-lang.github.io/api-guidelines/checklist.html  poll with timeout parameter, or provide the fd to let the app use in its own select loop?  callbacks?
- make it easy for other people to build on, even if they dont know rust? /on to add functionality? scriptable?
## UI
- CLI commands  / API?  or just as curl//REST examples, not CLI
- how would end users best interact? through a browser? how about sending or streaming
- cjp2p crate too? or instead? or just cjp? is lib redundant?
- split lib and use cases, but need one or two more use cases?  but functionality builds on other functionality, where''s he cut?   the UI i guess or move/expose core functions i havent changed in a while to the lib
- how can users easily and excitedly use decentralized software in place of centralized...easy plus a draw..whats hot and trending, what peers respect, an algorithm but that they control
- more / commands
- http quickstart and acceleration need work, maybe just request the whole thing as soon as it knows a peer  .. user waiting is much more important than maintaining some low packet loss
## cryptography related
- more encryption? by default? the asymmetric encryption i have is 10x as much CPU as none.  symmetric might be  fast
- trust 
- valuable numbers
- proof of latency? signature chain of somewhat verifiable latency?
- reputation
- thanks/reputation. auto thanks on succesful get.
## near-real time things - may overlap 
- news feed
- once there is economics, sell services
- group chats
## public collaboration
- reviews of content
## unnsorted
- make it do what i actually do each day, check for news basically. /trending is all i really do. but, i may want to weight some sources higher. well, do that later. get /trending into a nice /UI ..  make it do it well, easy, streamlined, in browser, and to select 2nd and third most trending, an most popular, etc.
-   can browsers be p2p nodes in tab?  though if not, a browser plugin isnt inconceiveable.  https://github.com/webtorrent/webtorrent  webrtc but webtransport is probably better now
- really need metadata for /list and /recommended and /trending
- easy web UI
- web page converter? to put a whole page in the system..
dont rev dns the entire peer list
