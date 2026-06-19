//! Loopback HTTP client for the node.
//!
//! Hand-rolled over `TcpStream` rather than a crate because the node speaks
//! HTTP/1.0 and frames request bodies by `Content-Length` only (no chunked
//! decode — see handle_upload/handle_publish_origin in the node). A generic
//! client that emits `Transfer-Encoding: chunked` would corrupt uploads, so we
//! control the framing exactly. This also gives us per-read timeouts (needed:
//! a cold cross-node `/latest` fetch parks the socket with no node-side timeout)
//! and lets us NOT follow the `/?get=` 301 (which points at the homepage).

use crate::types::{is_safe_relative_path, ContentJson, Status};
use anyhow::{anyhow, bail, Context, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

pub struct NodeClient {
    addr: String, // host:port for TcpStream::connect
}

#[derive(Debug, Clone)]
pub struct UploadResult {
    pub sha256: String,
    pub blake3: String,
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl NodeClient {
    /// `--node` flag > `$CJP2P_NODE` > `127.0.0.1:24255` (the node default port).
    pub fn resolve(flag: Option<&str>) -> NodeClient {
        let raw = flag
            .map(str::to_string)
            .or_else(|| std::env::var("CJP2P_NODE").ok())
            .unwrap_or_else(|| "127.0.0.1:24255".to_string());
        let addr = raw
            .trim()
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .to_string();
        NodeClient {
            addr,
        }
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn ws_url(&self) -> String {
        format!("ws://{}/wt", self.addr)
    }

    fn connect(&self, read_timeout: Option<Duration>) -> Result<TcpStream> {
        let stream = TcpStream::connect(&self.addr)
            .with_context(|| format!("connecting to node at {} (is it running?)", self.addr))?;
        stream.set_read_timeout(read_timeout).context("setting read timeout on node socket")?;
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .context("setting write timeout on node socket")?;
        Ok(stream)
    }

    fn get(&self, path: &str, read_timeout: Option<Duration>) -> Result<HttpResponse> {
        let mut stream = self.connect(read_timeout)?;
        let head =
            format!("GET {path} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n", self.addr);
        stream.write_all(head.as_bytes())?;
        stream.flush().ok();
        read_response(stream)
    }

    fn post_stream(
        &self,
        path: &str,
        extra: &[(&str, String)],
        mut body: impl Read,
        len: u64,
        read_timeout: Option<Duration>,
    ) -> Result<HttpResponse> {
        let mut stream = self.connect(read_timeout)?;
        let mut head =
            format!("POST {path} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n", self.addr);
        for (k, v) in extra {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str(&format!("Content-Length: {len}\r\n\r\n"));
        stream.write_all(head.as_bytes())?;
        std::io::copy(&mut body, &mut stream).context("streaming request body")?;
        stream.flush().ok();
        read_response(stream)
    }

    pub fn status(&self) -> Result<Status> {
        let r = self.get("/status.json", Some(Duration::from_secs(10)))?;
        if r.status != 200 {
            bail!("/status.json returned HTTP {}", r.status);
        }
        serde_json::from_slice(&r.body).context("parsing /status.json")
    }

    pub fn content(&self) -> Result<ContentJson> {
        let r = self.get("/content.json", Some(Duration::from_secs(10)))?;
        match r.status {
            200 => serde_json::from_slice(&r.body).context("parsing /content.json"),
            404 => bail!("/content.json not found — the node needs the updated build with the content endpoint"),
            403 => bail!("/content.json is loopback-only (HTTP 403) — run on the node host or tunnel 127.0.0.1:24255"),
            s => bail!("/content.json returned HTTP {s}"),
        }
    }

    pub fn upload(&self, path: &Path) -> Result<UploadResult> {
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let len = file.metadata()?.len();
        let r = self.post_stream("/upload", &[], file, len, Some(Duration::from_secs(300)))?;
        if r.status != 200 {
            bail!("/upload returned HTTP {}: {}", r.status, String::from_utf8_lossy(&r.body));
        }
        let v: serde_json::Value =
            serde_json::from_slice(&r.body).context("parsing /upload response")?;
        Ok(UploadResult {
            sha256: v["sha256"]
                .as_str()
                .ok_or_else(|| anyhow!("/upload response missing sha256"))?
                .to_string(),
            blake3: v["blake3"]
                .as_str()
                .ok_or_else(|| anyhow!("/upload response missing blake3"))?
                .to_string(),
        })
    }

    pub fn publish(&self, name: &str, path: &Path) -> Result<String> {
        if !is_safe_relative_path(name) {
            bail!("unsafe publish name {name:?}: no leading dot/slash, trailing slash, '/.' or backslash");
        }
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let len = file.metadata()?.len();
        let enc = urlencoding::encode(name).to_string();
        let r = self.post_stream(
            "/publish_origin",
            &[("X-Filename", enc)],
            file,
            len,
            Some(Duration::from_secs(300)),
        )?;
        if r.status != 200 {
            bail!(
                "/publish_origin returned HTTP {}: {}",
                r.status,
                String::from_utf8_lossy(&r.body)
            );
        }
        let v: serde_json::Value =
            serde_json::from_slice(&r.body).context("parsing /publish_origin response")?;
        Ok(v["filename"].as_str().unwrap_or(name).to_string())
    }

    /// Kick a network fetch by sha256. The node 301s to `/`; we do not follow.
    pub fn start_get_sha256(&self, hash: &str) -> Result<()> {
        self.get(&format!("/?get={hash}"), Some(Duration::from_secs(10)))?;
        Ok(())
    }

    /// Kick a network fetch by blake3. The node 301s to `/blake3/<h>`.
    pub fn start_get_blake3(&self, hash: &str) -> Result<()> {
        self.get(&format!("/?getb3={hash}"), Some(Duration::from_secs(10)))?;
        Ok(())
    }

    /// Fetch bytes for a content path (`/<sha256>`, `/blake3/<h>`, `/latest/...`).
    /// A timeout means "not available yet / publisher unreachable", never a hang.
    pub fn fetch_bytes(&self, path: &str, read_timeout: Duration) -> Result<Vec<u8>> {
        let r = self.get(path, Some(read_timeout))?;
        if r.status != 200 {
            bail!(
                "fetch {path} returned HTTP {} (content not available yet / publisher unreachable)",
                r.status
            );
        }
        Ok(r.body)
    }
}

fn read_response(mut stream: TcpStream) -> Result<HttpResponse> {
    // HTTP/1.0 + `Connection: close` -> the response is delimited by EOF.
    let mut raw = Vec::new();
    match stream.read_to_end(&mut raw) {
        Ok(_) => {}
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            if raw.is_empty() {
                return Err(anyhow!("timed out waiting for node response"));
            }
            // partial data before the stall — try to parse what we have
        }
        Err(e) => return Err(anyhow!("reading response: {e}")),
    }
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Result<HttpResponse> {
    let pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed HTTP response (no header terminator)"))?;
    let line_end = raw.iter().position(|&b| b == b'\r' || b == b'\n').unwrap_or(raw.len());
    let line = String::from_utf8_lossy(&raw[..line_end]);
    let status: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("bad status line: {line}"))?;
    Ok(HttpResponse {
        status,
        body: raw[pos + 4..].to_vec(),
    })
}
