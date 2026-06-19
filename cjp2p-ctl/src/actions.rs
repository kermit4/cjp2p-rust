//! Shared action layer. The CLI, the TUI, and the git helpers all call these —
//! there is exactly one place that knows how to talk to the node.

use crate::client::{NodeClient, UploadResult};
use crate::types::{ContentJson, Status};
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn status(c: &NodeClient) -> Result<Status> {
    c.status()
}

pub fn content(c: &NodeClient) -> Result<ContentJson> {
    c.content()
}

/// share = immutable, hash-addressed (`POST /upload`).
pub fn share(c: &NodeClient, path: &Path) -> Result<UploadResult> {
    c.upload(path)
}

/// publish = updatable, key-addressed (`POST /publish_origin`).
pub fn publish(c: &NodeClient, path: &Path, name: &str) -> Result<String> {
    c.publish(name, path)
}

#[derive(Clone, Copy, Debug)]
pub enum Algo {
    Sha256,
    Blake3,
}

/// Fetch content by hash: kick the network fetch, then read the bytes and save.
pub fn get(c: &NodeClient, algo: Algo, hash: &str, out: Option<&Path>) -> Result<PathBuf> {
    let server_path = match algo {
        Algo::Sha256 => {
            c.start_get_sha256(hash)?;
            format!("/{hash}")
        }
        Algo::Blake3 => {
            c.start_get_blake3(hash)?;
            format!("/blake3/{hash}")
        }
    };
    let bytes = c.fetch_bytes(&server_path, Duration::from_secs(60))?;
    let out_path = out.map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(hash));
    std::fs::write(&out_path, &bytes)?;
    Ok(out_path)
}
