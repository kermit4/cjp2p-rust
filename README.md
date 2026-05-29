This builds on the following standards:

- https://github.com/kermit4/LCDP Lowest Common Denominator Protocol
- https://en.wikipedia.org/wiki/WebSocket
- https://en.wikipedia.org/wiki/User_Datagram_Protocol (UDP)
- https://en.wikipedia.org/wiki/HTTP
- https://rust-lang.org/

The current target audience is developers, so the UI is minimal and not well documented.   If you don't intend to develop p2p software, this repo is probably not for you, though the sample implementations are quite powerful.  

This will make available any files in the directory ./cj2p/public  It will ignore any requests for anything that has a / or \ in it, except for /latest/ which are ordinary names that get checked for changes and published by hash in /public/, and the requester is sent the latest hash. (So you have distributed updateable content by your public key.  Make yourself a home page, call it index.html .)

If you create .allow_remote_http in the directory you run this, the next time it starts it will allow any IP to connect to the HTTP port, but it will only serve files you already have, it can't cause it to download anything new, and doesn't have any of special access that localhost does. As of this writing that means it will refuse websockets too. I run it with .allow_remote_http so I think its safe, but I have no crypto keys laying around to worry about.


# building (optional)

- https://github.com/kermit4/cjp2p-rust/ 
- https://app.radicle.xyz/nodes/iris.radicle.xyz/rad:z4NaokAHdQyjkF562Cj9PpHpGH5f1 (but ive seen it a week behind on the same Radical node I was pushing to daily so I'm not sure if this is working right.  It seems to be now, though)

make release

# running

- https://github.com/kermit4/cjp2p-rust/releases if you didn't build it above

./target/release/cjp2p

or 

RUST_LOG=info ./target/release/cjp2p

or 

RUST_LOG=warn ./target/release/cjp2p

Then type /help or go to http://localhost:24255/ where all the on-network links are

This uses about 400MB/day out and 100MB/day in

This also works great on Android.  It does use "StartForeground" but the base maintenance timer is ~2 seconds on Android ( ~1 elsewhere ).  I don't notice any more battery drain with it running than without on mobile or wifi.

# updating

`/update` for locally built installs, `/update bin` for binary installs yet, or just do whatever you initially did again.  No method wipes your cjp2p/ (state, your hosted files, downloads, or key)

If it's not running, `git pull` then `make`

# hints

[build your own p2p game in minutes quick start](quickstart_build_a_p2p_game_with_one_prompt.md)
[build your own p2p twitter in minutes quick start](quickstart_build_a_p2p_twitter_with_one_prompt.md)


Try /get c3514bf0056180d09376462a7a1b4f213c1d6e8ea67fae5c25099c6fd3d8274b (its ubuntu-24.04.3-live-server-amd64.iso ) and watch it come from two places with iftop


# TODO
## general 
- remember to talk like people not a computer (naming, especially on the wire)
- make it easy for other people to build on, make easy for UI devs on websockets
## UI
-   can browsers be p2p nodes in tab?  though if not, a browser plugin isnt inconceiveable.  https://github.com/webtorrent/webtorrent  webrtc but webtransport is probably better now
- public websocket support/ browser light node, its easy, just treat non-localhost as network..easy, right? update Source enum..  the code is intended to possibly allow this but there are gaps to fully implementing it, if i even want to
- more orderly useful chat interface, with history on dashboard page, like make this a social focused space , with clicking on a id to open the 1:1 chat
## scarcity related
- proof of latency? signature chain of somewhat verifiable latency?
- valuable numbers? (PoW?  or valuable just because the issuer, based on their public key, limits the issuance.  every person their own "coin" as value derived from their reputation?  reputation granting fungible negotiable scarcity? be your own CENTRAL bank!)
- ipv4 scarcity, that worked fine until 2000, just do that, for ipv6 its all in 2... 3.... (2000::/3) . the next 32 are about as in ipv4.
- read this again https://howtofixtheweb.com/
- once there is economics, sell services
### reputation
- thanks based reputation. auto-thanks on succesful get.
- web of trust - direct referal trust or public reputation..and is that the scarcity   reputation is not absolute, its from your point of view, that solves sybil attacks
## public collaboration 
- needs some scarcity, eventually, right?  to not be spam?  as long as the spam cant be automated without limit
- news feed
- group chats - or just another field in chat message, an array of tags? for public chats
- reviews of content
- reviews of anything
- polls, approval voting style
- some equivalent of wikipedia.. no concensus needed, DAG, fork if they want, or agree if they want. forks forever or people sane enough to sync up.  each name space can have a popularity 
## unnsorted
- make it do what i actually do each day, check for news basically, from friends or weigthed by importance/distance. like /trending but scoped/weighted.  user defined algorithm. get /trending into a nice /UI ..  make it do it well, easy, streamlined, in browser, and to select 2nd and third most trending, and most popular, etc.
- need metadata for large files, a list of 256k block hashes (256k of 64 byte hashes is  2^12, so files over 2^30 may want another layer of hashing, over 4TB yet another.), so in-transit corruption recovers faster, and also files can be relayed before compelete (which would enable streaming).. maybe this starts right from messages a message type that says "too big, get this hash or list of hashes" (or is that a different scenario, level 0 of get by hash)
- any aggressive scans should monitor latency and loss consequences and throttle both max bw and max hosts/sec because they are often separate limits on consumer routers even without NAT (DMZ/ipv6)
- dot file, env var, commmand line options..too many ways to pass options
- lcdp crate now? send to ed25519 and big hash getter are basic legos .. the killer app for this i think is a lib that is a drop in socket replacement that takes a pub (oh https://www.iroh.computer/ does that), or maybe libp2p semantics..look into how you actually send a message with libp2p, or transport for it as long as the app can still direct message on the socket.
- focus on enabling devs, i've done enough demoing
- just default stream url for people not dated
- it is time to make various mini stand-alone apps instead of this one big thing, separate repos, real users of the protocol .. except that peer discover is evolving, maybe thats the lib part?..make a standalone pong apk? 
- general UX .. for devs though ..DX..more walkthroughs, speedruns, how to build something, native, html, some overlap, no overlap, different languages
- less latency on the broadcast.html .. rewriting blocks should work fine, i think the problem was that they werent aligned before ..they need to modify in place node side
- why does /msg with 2 spaces crash it
- test dual cgnat again
