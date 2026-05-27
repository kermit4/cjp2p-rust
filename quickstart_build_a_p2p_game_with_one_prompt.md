# Build a P2P Web Game in One Prompt

This shows how to ship a real-time multiplayer game -- no server, no account, no cloud -- using **cjp2p-rust** as the networking layer and Claude to write the game code. On a LAN it works with no internet at all, even from an offline hotspot, once Rust is compiled.

---

## 1. Get the source

```bash
git clone https://github.com/kermit4/cjp2p-rust.git 
cd cjp2p-rust
```

---

## 2. Install Rust and build

```bash
# Install Rust (skip if you already have it)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Build (takes a few minutes the first time)
make release
```

---

## 3. Run the node

```bash
./target/release/cjp2p
```

In another window

```
wget http://localhost:24255/latest/e13a614dff88de239a986bea20ca129c3dc77bb727fac18f2f092eed27cfb3fb/pong.html
```

---

## 4. Ask Claude to write the game

Paste the prompt below into Claude as-is. It will produce a single, self-contained HTML file you drop into `cjp2p/origin/`.

---

### The Prompt

```
Write a real-time 2-player P2P game called "Blob Tag" using the cjp2p WebSocket.  See pong.html for an example. 

--- GAME RULES ---
- 800x500 canvas, each player is a filled circle (radius 18), you=blue, opponent=red.
- Both players control their circle with mouse or touch (relative to the canvas).
- One player is "it" -- shown with a bright pulsing ring around their circle.
- If the "it" player's circle overlaps the other, the other becomes "it" and a
  point is scored for the tagger. Display both scores at the top.
- Who starts as "it": once both my_ed25519 and their_ed25519 are known, set
  myIt = (my_ed25519 < their_ed25519) using plain string comparison. Both sides
  compute this independently and always agree (one key is always smaller).
  DO NOT derive "it" from URL params or from a "server/client" role -- that
  breaks whenever both players open the page fresh with no ?ed25519= param,
  making both think they are "it" or neither is "it".
- When "it" is first determined, place myX at W*0.25 (if "it") or W*0.75 (if not),
  and reset the tag cooldown timer to now -- so blobs start on opposite sides and
  don't immediately score from the default center overlap.

--- NETWORKING (cjp2p WebSocket API) ---
Connect to: ws://localhost:24255/wt  (let the user edit this URL on the page)

On connect the server sends your identity:
  [{"YourEd25519":{"ed25519":"<key>"}}]
  or [{"PleaseSignYourPub":{"ed25519":"<key>"}}]
Use whichever arrives; both give you your public key.

To send a message to your opponent:
  socket.send(JSON.stringify([{"Forward":{
      "to_ed25519": "<their_key>",
      "messages":   [{"BlobPos":{"x":123,"y":456,"it":true,"score_me":5,"score_them":3}}]
  }}]))

Messages from your opponent arrive as:
  [{"Forwarded":{"from_ed25519":"<their_key>","messages":"<JSON_string>"}}]
Parse the inner "messages" field as JSON (it is a JSON-encoded string).

Send your position (BlobPos) every ~16ms (throttle to 60fps max).
The "it" field in BlobPos is for rendering only (opponent's ring); it does NOT
determine authoritative "it" state. Do NOT modify myIt based on their BlobPos.
Send BlobTag when you detect a tag (you are "it" and circles overlap).
The receiver of BlobTag becomes "it"; the sender is no longer "it".
Add a 500ms cooldown after any tag event before the next tag can fire, to
prevent rapid re-tagging while circles are still overlapping.
Both sides track scores locally: the SENDER of BlobTag increments myScore;
the RECEIVER of BlobTag increments theirScore. No authoritative server needed.

--- UI ---
- Input at the top: "Their ed25519:" (pre-filled from ?ed25519= URL param).
- Below that: "Share this link:" -- auto-populated using location.pathname
  (like pong.html does: "http://localhost:24255" + location.pathname + "?ed25519=" + my_ed25519)
  once you know your key. Do NOT hardcode any hash into the URL.
- Status line: "Waiting for opponent..." -> game instructions once connected.
- A small "Fullscreen" button.
- Reconnect automatically if the WebSocket closes.

--- OUTPUT ---
One HTML file, no external scripts, no build step. The file goes in
cjp2p/origin/blobtag.html and is served by the node.
```

---

## How it works end-to-end

```
Player A's browser                       Player B's browser
  |                                          |
  | ws://localhost:24255/wt                  | ws://localhost:24255/wt
  v                                          v
[Node A]  <------- UDP/TCP/LAN ----------> [Node B]
```

Each browser talks only to its own local node. The nodes find each other via UDP
broadcast/multicast on the LAN (or through peers on the internet). Messages are encrypted
with Noise IK -- the ed25519 public key *is* the address. No accounts, no DNS,
no central broker.

---

## Tips

- **Works offline on a hotspot**: once compiled, the binary is self-contained.
  Spin up a phone hotspot, connect both laptops, run `./target/release/cjp2p`
  on each. Nodes discover each other automatically over UDP broadcast.
- **Android**: the same binary cross-compiles for Android in Termux or as an apk (`make apk`).
- **Multiple games**: each HTML file in `cjp2p/origin/` is independent. Share
  different `?ed25519=` links to launch different games with different people.
- **Latency**: on a LAN you'll typically see 1-5ms RTT. The chart makes this
  viscerally visible -- that's the point.
- **No port forwarding needed** for most LAN setups; UDP hole-punching handles
  the internet case when both nodes can reach a common peer.
