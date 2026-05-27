# cjp2p WebSocket API

Connect to `ws://localhost:24255/wt` to send and receive messages with any peer on the network.
No account, no login -- your identity is an ed25519 public key the node generates for you.

---

## Message format

Every message is an object in a **JSON array** whose single key is the message type:

```json
[{"TypeName": { ...fields... }}]
```

Multiple messages can ride in one array:

```json
[{"TypeA": {...}}, {"TypeB": {...}}]
```

Ignore any type or field you don't recognize. The namespace is open -- apps define their own types freely.

---

## Handshake

The server speaks first. Immediately after the WebSocket opens, it sends:

```json
[{"YourEd25519": {"ed25519": "e13a614dff88de239a986bea20ca129c3dc77bb727fac18f2f092eed27cfb3fb"}}]
```

`ed25519` is your node's public key -- 64 hex characters. This is your address on the network.
Share it with peers out-of-band (QR code, URL param, copy-paste) so they can reach you.

---

## Sending to a peer -- `Forward`

```json
[{"Forward": {
  "to_ed25519": "<recipient-64-hex>",
  "messages": [
    {"ChatMessage": {"message": "hello"}},
    {"MyCustomType": {"foo": 42}}
  ]
}}]
```

| Field | Type | Description |
|---|---|---|
| `to_ed25519` | string | Recipient's ed25519 public key |
| `messages` | array | One or more message objects to deliver |
| `sign` | bool (optional) | If true, the node signs the message array before sending |

### Sending a signed (authenticated) message

Add `"sign": true` and the node wraps `messages` in a `SignedMessage` using its private key before
encrypting and dispatching. The recipient can verify the signature against your `ed25519` public key.

```json
[{"Forward": {
  "to_ed25519": "<recipient-64-hex>",
  "sign": true,
  "messages": [
    {"ChatMessage": {"message": "hello, signed"}}
  ]
}}]
```

Signing is intentionally only available inside `Forward` -- a signed message that isn't forwarded
to anyone would never be verified by another node, so there is no standalone "sign and keep locally"
operation in the WebSocket API.

Since its encrypting, the recipient already knows it came from you anyway, so this is only useful if you want the recipient to be able to tell others what you said, verifiably.

---

## Receiving from a peer -- `Forwarded`

```json
[{"Forwarded": {
  "from_ed25519": "a3b9...",
  "src": "192.168.1.12:24254",
  "messages": "[{\"ChatMessage\":{\"message\":\"hello\"}}]"
}}]
```

| Field | Type | Description |
|---|---|---|
| `from_ed25519` | string | Sender's public key (may be `null` if unverified) |
| `src` | string | Sender's IP:port |
| `messages` | **string** | JSON-encoded inner message array -- parse it again |

The inner `messages` field is a JSON string, not an object:

```javascript
const inner = JSON.parse(forwarded.messages);   // parse twice
for (const m of inner) {
  if ("ChatMessage" in m) console.log(m.ChatMessage.message);
}
```

When the sender used `"sign": true`, `from_ed25519` is cryptographically verified -- the node
checked the signature before delivering it to your WebSocket. If signature verification failed the
message is silently dropped and you never see it.

---

## Node status -- `GET /status.json`

Before opening the WebSocket, or any time you need your own identity or a peer list, fetch:

```
GET http://localhost:24255/status.json
```

Response:

```json
{
  "version": "1.2.3",
  "public_key": "0xe13a614dff88de239a986bea20ca129c3dc77bb727fac18f2f092eed27cfb3fb",
  "total_peers": 42,
  "unique_ips": 18,
  "active_peer_count": 7,
  "fast_peer_count": 4,
  "active_peers": [
    {"addr": "192.168.1.12:24254", "pub": "0xa3b9...", "delay_ms": 45},
    {"addr": "192.168.1.20:24254", "pub": "0xc7f2...", "delay_ms": 112}
  ],
  "free_disk_bytes": 21474836480
}
```

`active_peers` are peers with a round-trip time under 250 ms -- a good starting list for `Forward.to_ed25519`.
The endpoint has `Access-Control-Allow-Origin: *`, so it's safe to fetch from any HTML page.

---

## Minimal working example

```javascript
const ws = new WebSocket("ws://localhost:24255/wt");
let myId = null;

ws.onmessage = (e) => {
  const [msg] = JSON.parse(e.data);

  if ("YourEd25519" in msg) {
    myId = msg.YourEd25519.ed25519;
    console.log("my id:", myId);
  }

  if ("Forwarded" in msg) {
    const inner = JSON.parse(msg.Forwarded.messages);
    for (const m of inner) {
      if ("ChatMessage" in m)
        console.log("from", msg.Forwarded.from_ed25519, "->", m.ChatMessage.message);
    }
  }
};

function send(peerId, text) {
  ws.send(JSON.stringify([{
    Forward: {
      to_ed25519: peerId,
      messages: [{ ChatMessage: { message: text } }]
    }
  }]));
}

function sendSigned(peerId, text) {
  ws.send(JSON.stringify([{
    Forward: {
      to_ed25519: peerId,
      sign: true,
      messages: [{ ChatMessage: { message: text } }]
    }
  }]));
}
```

---

## Defining your own message types

There is no registry. Pick a name, pick fields, and use it. The node routes anything inside `Forward.messages` without inspecting it. Other nodes and apps silently ignore types they don't know.

Conventions from the examples at http://127.0.0.1:24255/latest/e13a614dff88de239a986bea20ca129c3dc77bb727fac18f2f092eed27cfb3fb/

| Type | Direction | Use |
|---|---|---|
| `ChatMessage` | peer<->peer | `{message: string}` |
| `GroupChatMessage` | peer<->peer | `{group_name, text, timestamp}` |
| `PongMove` | peer<->peer | Ball state in pong game |
| `PongPaddle` | peer<->peer | Paddle position |
| `PleaseSendContent` | peer<->peer | Request file chunk by SHA-256 hash |
| `Content` | peer<->peer | File chunk response `{id, offset, eof, data}` (base64) |

Post new message types on https://github.com/kermit4/LCDP/wiki to avoid collisions, or just pick names not likely to collide. The namespace is huge.

---

## Notes

- **Reconnect freely.** If the socket closes, reconnect -- no session state is lost on the server side.
- **Works offline.** On a LAN with no internet, peers discover each other and communicate directly.
- **No origin restriction.** Any HTML page served from localhost can open the socket.
- **Encryption.** Traffic between nodes over the internet uses Noise IK. The local WebSocket is plaintext (loopback only).
