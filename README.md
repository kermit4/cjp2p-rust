This implements everything in spotted and listed in the https://github.com/kermit4/cjp2p protocol repo, plus some other things.   The primary purpose of this and the protocol are to demonstrate how you can A) use JSON as your base protocol to maintain future compatibility and be easily approachable to new implementations, and B) how you can send messages directly without relays or connections, rather than messages relayed around a web of connections that are abstracted on top of messages, as is oddly commonplace in p2p networking, probably out of habbit from 1:1 server/clientt application design.  However this code is functional, at various things, just not the best at any 1 of them, but interoperability instead of lots of siloed p2p apps is the benefit.

This will make available any files in the directory ./shared  It will ignore any requests for anything that has a / or \ in it.

To request a file, run with the content_id as an arguement.  It will be placed in ./shared/incoming/ until it is complete, then moved to ./shared

i.e. 

     ./target/release/libcjp  c3514bf0056180d09376462a7a1b4f213c1d6e8ea67fae5c25099c6fd3d8274b # ubuntu-24.04.3-live-server-amd64.iso


# building
 cargo build

# hints

try running with RUST_BACKTRACE=1 RUST_LOG=debug ./target/debug/libcjp
or info/warn log levels

for fun try: make demo, ^C when it seems done, and then
```
(cd shared
cat $(cat                                                                                                                   562b168a64967fd64687664b987dd1c50c36d1532449bb4c385d683538c0bf03 )) |
sha256sum    
# should be  6f5a06b0a8b83d66583a319bfa104393f5e52d2c017437a1b425e9275576500c
```

or http://127.0.0.1:24254/43a39a05ce426151da3c706ab570932b550065ab4f9e521bb87615f841517cf1 in a browser. Check out the amazing seek time!

typing stdin sends a chat message to a mostly random set of peers, but say "/ping" for fun, or "/search"

This is also at https://crates.io/crates/libcjp but probably isn't useful as a crate yet.  

# TODO
## general 
- remember to talk like people not a computer (naming, especially on the wire)
## lib
- daemon or library?  library with daemon as one implementation
- make this crate more proper   https://rust-lang.github.io/api-guidelines/checklist.html  poll with timeout parameter, or provide the fd to let the app use in its own select loop?  callbacks?
## UI
- CLI commands  / API?  or just as curl//REST examples, not CLI
- how would end users best interact? through a browser? how about sending or streaming
- cjp2p crate too? or instead? or just cjp? is lib redundant?
- split lib and use cases, but need one or two more use cases?  but functionality builds on other functionality, where''s he cut?   the UI i guess
- how can users easily and excitedly use decentralized software in place of centralized...easy plus a draw..whats hot and trending, what peers respect, an algorithm but that they control
- more / commands
- http quickstart and acceleration need work, maybe just request the whole thing as soon as it knows a peer  .. user waiting is much more important than maintaining some low packet loss
## cryptography related
- more encryption? by default? the asymmetric encryption i have is 10x as much CPU as none.  symmetric might be  fast
- trust 
- valuable numbers
## near-real time things - may overlap 
- news feed
- once there is economics, sell services
- DM
- group chats
## public collaboration
- ipv4 scacity, like search for static content but also for timely content..pushed even possibly
- /promote for things you really want others to see and /popular to see whats most promoted since you last ran it  (which you can then /get) .. you only get one at a time, and only for the main port, and only not ip spoofed
- reviews of content
- count promoted and sort low to high, filter for only primary port..obviuos0y get should scan those too.
- count promoted and sort low to high, filter for only primary port..obviuos0y get should scan those too.
call maybetheyhavesome on last viewed and promotoed
check local maybetheyhavesome on get
or just search peer list and dont store separately..yeah
add /trending to read last_viewed
