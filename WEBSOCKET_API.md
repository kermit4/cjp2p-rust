Claude suggested and then wrote this. I didn't prooof read it yet.


# cjp2p WebSocket API

Connect to `ws://localhost:24255/wt` to send and receive messages with any peer on the network.
No account, no login -- your identity is an ed25519 public key the node generates for you.

---

## Message format

Every message is a **JSON array containing one object** whose single key is the message type:

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
| `from_ed25519` | string | Sender's public key (may be `null` if not yet verified) |
| `src` | string | Sender's IP:port |
| `messages` | **string** | JSON-encoded inner message array -- parse it again |

The inner `messages` field is a JSON string, not an object:

```javascript
const inner = JSON.parse(forwarded.messages);   // parse twice
for (const m of inner) {
  if ("ChatMessage" in m) console.log(m.ChatMessage.message);
}
```

---

## Measuring latency -- `PongPing` / `PongPingPong`

Send a ping:

```json
[{"Forward": {
  "to_ed25519": "<peer>",
  "messages": [{"PongPing": {"seq": 1, "t": 1748908800000}}]
}}]
```

The peer's node echoes it back automatically:

```json
[{"Forwarded": {
  "from_ed25519": "<peer>",
  "messages": "[{\"PongPingPong\": {\"seq\": 1, \"t\": 1748908800000}}]"
}}]
```

RTT in milliseconds: `Date.now() - msg.PongPingPong.t`. Discard pongs older than ~5 seconds.

---

## Peer discovery -- `PleaseSendPeers` / `Peers`

Ask your node for a list of known peers:

```json
[{"PleaseSendPeers": {}}]
```

Response:

```json
[{"Peers": {"peers": ["192.168.1.100:24254", "192.168.1.101:24254"]}}]
```

These are socket addresses, not public keys. To get a peer's key, communicate with them directly and read `from_ed25519` off an incoming `Forwarded` message.

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
```

---

## Defining your own message types

There is no registry. Pick a name, pick fields, and use it. The node routes anything inside `Forward.messages` without inspecting it. Other nodes and apps silently ignore types they don't know.

Convention from the built-in examples:

| Type | Direction | Use |
|---|---|---|
| `ChatMessage` | peer<->peer | `{message: string}` |
| `GroupChatMessage` | peer<->peer | `{group_name, text, timestamp}` |
| `PongMove` | peer<->peer | Ball state in pong game |
| `PongPaddle` | peer<->peer | Paddle position |
| `PleaseSendContent` | peer<->peer | Request file chunk by SHA-256 hash |
| `Content` | peer<->peer | File chunk response `{id, offset, eof, data}` (base64) |

---

## Notes

- **Reconnect freely.** If the socket closes, reconnect -- no session state is lost on the server side.
- **Works offline.** On a LAN with no internet, peers discover each other and communicate directly.
- **No origin restriction.** Any HTML page served from localhost can open the socket.
- **Encryption.** Traffic between nodes over the internet uses Noise IK. The local WebSocket is plaintext (loopback only).
