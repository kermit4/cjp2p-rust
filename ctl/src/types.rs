//! Wire-shape mirrors of the node's JSON/WS contracts.
//!
//! These are NOT the node's internal types (those are private to the `cjp2p`
//! crate); they are small serde mirrors of the loopback JSON the node emits.
//! Every field is `#[serde(default)]`-tolerant so a renamed/added field on the
//! node side degrades gracefully instead of failing the whole parse.

use serde::{Deserialize, Serialize};

/// `GET /status.json`
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Status {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub total_peers: u64,
    #[serde(default)]
    pub unique_ips: u64,
    #[serde(default)]
    pub active_peer_count: u64,
    #[serde(default)]
    pub fast_peer_count: u64,
    #[serde(default)]
    pub active_peers: Vec<PeerInfo>,
    #[serde(default)]
    pub free_disk_bytes: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    #[serde(default)]
    pub addr: String,
    /// the node emits this under the JSON key `pub`
    #[serde(default, rename = "pub")]
    pub pubkey: String,
    #[serde(default)]
    pub delay_ms: u128,
}

/// `GET /content.json` (the endpoint added to the node by this project)
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ContentJson {
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub origin: Vec<OriginItem>,
    #[serde(default)]
    pub directories: Vec<DirItem>,
    #[serde(default)]
    pub public: Vec<PublicItem>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct OriginItem {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub mtime: String,
    #[serde(default)]
    pub mtime_unix: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DirItem {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub url: String,
}

/// One content-addressed blob; sha256 and blake3 are paired by inode on the node.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PublicItem {
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub blake3: Option<String>,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub mtime: String,
    #[serde(default)]
    pub mtime_unix: u64,
    #[serde(default)]
    pub tree: bool,
}

/// A parsed WebSocket frame. WS frames are JSON arrays of externally-tagged
/// single-key objects; serde's `#[serde(other)]` is unsupported for externally
/// tagged enums, so we parse via `serde_json::Value` and tolerate unknown types.
#[derive(Debug, Clone)]
pub enum WsFrame {
    /// `YourEd25519` / `PleaseSignYourPub` — our identity from the node
    Identity {
        ed25519: String,
    },
    /// `Forwarded` — a message relayed from a peer
    Forwarded {
        src: String,
        from: Option<String>,
        messages: String,
    },
    /// any other message type (carries the type name)
    Other(String),
}

/// Parse one WS text frame (a JSON array) into zero or more `WsFrame`s,
/// ignoring anything we do not recognize (LCDP tolerance rule).
pub fn parse_ws_frames(text: &str) -> Vec<WsFrame> {
    let mut out = Vec::new();
    let Ok(val) = serde_json::from_str::<serde_json::Value>(text) else {
        return out;
    };
    let Some(arr) = val.as_array() else {
        return out;
    };
    for item in arr {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let Some((k, v)) = obj.iter().next() else {
            continue;
        };
        match k.as_str() {
            "YourEd25519" | "PleaseSignYourPub" => {
                out.push(WsFrame::Identity {
                    ed25519: v
                        .get("ed25519")
                        .and_then(|x| x.as_str())
                        .unwrap_or_default()
                        .to_string(),
                });
            }
            "Forwarded" => {
                let from =
                    v.get("from_ed25519").and_then(|x| x.as_str()).map(str::to_string).or_else(
                        || v.get("maybe_ed25519").and_then(|x| x.as_str()).map(str::to_string),
                    );
                out.push(WsFrame::Forwarded {
                    src: v.get("src").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                    from,
                    messages: v
                        .get("messages")
                        .and_then(|x| x.as_str())
                        .unwrap_or_default()
                        .to_string(),
                });
            }
            other => out.push(WsFrame::Other(other.to_string())),
        }
    }
    out
}

/// Mirror of the node's `is_safe_relative_path` (src/main.rs:5823) — used to
/// reject publish names the node would accept but then be unable to serve.
pub fn is_safe_relative_path(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('\\')
        && !name.contains('\0')
        && !name.contains("/.")
        && !name.starts_with('.')
        && !name.starts_with('/')
        && !name.ends_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_json_contract() {
        let sample = r#"{"version":"v1","public_key":"0xabc","total_peers":3,
            "unique_ips":2,"active_peer_count":1,"fast_peer_count":1,
            "active_peers":[{"addr":"1.2.3.4:24254","pub":"0xdead","delay_ms":42}],
            "free_disk_bytes":1024}"#;
        let s: Status = serde_json::from_str(sample).expect("status parses");
        assert_eq!(s.public_key, "0xabc");
        assert_eq!(s.active_peers[0].pubkey, "0xdead");
        assert_eq!(s.active_peers[0].delay_ms, 42);
    }

    #[test]
    fn content_json_contract() {
        let sample = r#"{"public_key":"0xabc",
            "origin":[{"name":"a.html","url":"/latest/0xabc/a.html","size":5,"mtime":"t","mtime_unix":1}],
            "directories":[{"name":"d","url":"/latest/0xabc/d/"}],
            "public":[{"sha256":"aa","blake3":"bb","size":9,"mtime":"t","mtime_unix":2,"tree":true}]}"#;
        let c: ContentJson = serde_json::from_str(sample).expect("content parses");
        assert_eq!(c.origin[0].name, "a.html");
        assert_eq!(c.public[0].sha256.as_deref(), Some("aa"));
        assert!(c.public[0].tree);
    }

    #[test]
    fn ws_frame_identity_and_forwarded() {
        let id = parse_ws_frames(r#"[{"YourEd25519":{"ed25519":"abcd"}}]"#);
        assert!(matches!(&id[0], WsFrame::Identity { ed25519 } if ed25519 == "abcd"));

        // from_ed25519 absent -> falls back to maybe_ed25519
        let f = parse_ws_frames(
            r#"[{"Forwarded":{"src":"1.2.3.4:1","maybe_ed25519":"peerpub","messages":"hi"}}]"#,
        );
        match &f[0] {
            WsFrame::Forwarded {
                from,
                src,
                ..
            } => {
                assert_eq!(from.as_deref(), Some("peerpub"));
                assert_eq!(src, "1.2.3.4:1");
            }
            _ => panic!("expected Forwarded"),
        }

        // unknown type tolerated
        let o = parse_ws_frames(r#"[{"SomethingNew":{"x":1}}]"#);
        assert!(matches!(&o[0], WsFrame::Other(t) if t == "SomethingNew"));
    }

    #[test]
    fn safe_path_rules() {
        assert!(is_safe_relative_path("repos/my-repo.bundle"));
        assert!(is_safe_relative_path("site.html"));
        assert!(!is_safe_relative_path(".hidden"));
        assert!(!is_safe_relative_path("/abs"));
        assert!(!is_safe_relative_path("a/../b"));
        assert!(!is_safe_relative_path("trailing/"));
        assert!(!is_safe_relative_path("back\\slash"));
    }
}
