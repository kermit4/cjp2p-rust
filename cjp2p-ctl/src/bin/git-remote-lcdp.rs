//! git-remote-lcdp -- git remote helper for lcdp:// URLs.
//!
//! Implements the git remote-helper protocol (gitremote-helpers(7)) for the
//! `fetch` capability. git invokes this binary as:
//!
//!   git-remote-lcdp <remote-name> lcdp://0x<pub>/<name>
//!
//! and speaks a line-oriented protocol on stdin/stdout. We download a git
//! bundle from the local node using the same NodeClient path that
//! `cjp2pctl clone` / `cjp2pctl pull` use, then serve git's fetch/list
//! commands by delegating to `git bundle list-heads` and
//! `git bundle unbundle`.
//!
//! Protocol summary (we implement the `fetch` capability only):
//!   capabilities  -> "fetch\n\n"
//!   option ...    -> "ok\n"
//!   list          -> one "<sha> <ref>" per head + optional "@<branch> HEAD" + "\n"
//!   fetch <s> <r> -> batch terminated by blank line; unbundle into object
//!                    store; reply "\n"
//!   <blank>/EOF   -> exit 0

use anyhow::{bail, Context, Result};
use cjp2p_ctl::client::NodeClient;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

// ---------------------------------------------------------------------------
// URL / path helpers (mirrors git.rs but self-contained to avoid pulling in
// the share/clone/pull API surface which needs the full NodeClient).
// ---------------------------------------------------------------------------

/// Parse lcdp://<pub>/<name> -> (pub_hex, name).  pub_hex keeps any "0x" prefix.
fn parse_url(url: &str) -> Result<(String, String)> {
    let s = url
        .trim()
        .strip_prefix("lcdp://")
        .ok_or_else(|| anyhow::anyhow!("url must start with lcdp:// (got {url})"))?;
    let mut parts = s.splitn(2, '/');
    let pub_hex = parts.next().unwrap_or_default().to_string();
    let name = parts
        .next()
        .unwrap_or_default()
        .trim_end_matches('/')
        .trim_end_matches(".bundle")
        .to_string();
    if pub_hex.is_empty() || name.is_empty() {
        bail!("url must be lcdp://<pubkey>/<name> (got {url})");
    }
    Ok((pub_hex, name))
}

/// Server path for a repo bundle: /latest/0x<pub>/repos/<name>.bundle
fn bundle_server_path(pub_hex: &str, name: &str) -> String {
    format!("/latest/0x{}/repos/{}.bundle", pub_hex.trim_start_matches("0x"), name)
}

/// Temp file path for the fetched bundle, unique per-process.
fn tmp_bundle(name: &str) -> PathBuf {
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    std::env::temp_dir().join(format!("lcdp-remote-{safe}-{}.bundle", std::process::id()))
}

// ---------------------------------------------------------------------------
// git helpers
// ---------------------------------------------------------------------------

/// Run a git subcommand, capture stdout, propagate stderr.
fn git(args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .args(args)
        .output()
        .with_context(|| format!("running: git {}", args.join(" ")))?;
    if !out.status.success() {
        bail!("git {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// List-heads from a bundle: returns lines of "<sha> <refname>".
fn bundle_list_heads(bundle: &str) -> Result<Vec<String>> {
    let out = git(&["bundle", "list-heads", bundle])?;
    Ok(out.lines().map(str::to_string).collect())
}

/// Unbundle into the current repo's object store.
fn bundle_unbundle(bundle: &str) -> Result<()> {
    // "git bundle unbundle" writes pack-refs to stdout; we don't need them.
    git(&["bundle", "unbundle", bundle]).map(|_| ())
}

/// The refname from a "<sha> <refname>" list-heads line.
fn refname_of(head_line: &str) -> Option<&str> {
    head_line.split_once(' ').map(|(_, r)| r)
}

// ---------------------------------------------------------------------------
// Protocol loop
// ---------------------------------------------------------------------------

/// Read one line from `r`, stripping trailing CR/LF.
/// Returns None on EOF.
fn read_line(r: &mut impl BufRead) -> Result<Option<String>> {
    let mut buf = String::new();
    let n = r.read_line(&mut buf).context("reading from git")?;
    if n == 0 {
        return Ok(None); // EOF
    }
    let s = buf.trim_end_matches('\n').trim_end_matches('\r').to_string();
    Ok(Some(s))
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        bail!("usage: git-remote-lcdp <remote-name> <url>");
    }
    let url = &args[2];

    let (pub_hex, name) = parse_url(url)?;
    let client = NodeClient::resolve(None);

    // Use a single BufReader over stdin so we can call read_line repeatedly
    // without the double-lock deadlock that stdin.lock().lines() would cause.
    let mut inp = BufReader::new(io::stdin());
    let stdout = io::stdout();
    let mut out = stdout.lock();

    // Bundle is fetched once (on first `list`) and reused for `fetch`.
    let mut bundle_path: Option<PathBuf> = None;

    loop {
        let line = match read_line(&mut inp)? {
            Some(l) => l,
            None => break, // EOF
        };

        if line.is_empty() {
            // Blank line signals end of session.
            break;
        }

        if line == "capabilities" {
            out.write_all(b"fetch\n\n")?;
            out.flush()?;
        } else if line.starts_with("option ") {
            // Accept/ignore all options.
            out.write_all(b"ok\n")?;
            out.flush()?;
        } else if line == "list" || line == "list for-push" {
            // Fetch the bundle (or reuse if already fetched).
            let bp = match bundle_path.take() {
                Some(p) => p,
                None => {
                    let server_path = bundle_server_path(&pub_hex, &name);
                    let bytes = client
                        .fetch_bytes(&server_path, Duration::from_secs(120))
                        .context("fetching bundle from node")?;
                    let p = tmp_bundle(&name);
                    std::fs::write(&p, &bytes).context("writing bundle to temp file")?;
                    p
                }
            };
            let bp_str = bp.to_str().ok_or_else(|| anyhow::anyhow!("non-UTF8 temp path"))?;
            let heads = bundle_list_heads(bp_str).context("listing bundle heads")?;

            for h in &heads {
                out.write_all(h.as_bytes())?;
                out.write_all(b"\n")?;
            }

            // Advertise a symbolic HEAD for the default branch: prefer
            // master/main, else the first refs/heads/* in the bundle.
            let default_branch = heads
                .iter()
                .filter_map(|h| refname_of(h))
                .find(|r| *r == "refs/heads/master" || *r == "refs/heads/main")
                .or_else(|| {
                    heads
                        .iter()
                        .filter_map(|h| refname_of(h))
                        .find(|r| r.starts_with("refs/heads/"))
                });
            if let Some(branch) = default_branch {
                writeln!(out, "@{branch} HEAD")?;
            }

            out.write_all(b"\n")?;
            out.flush()?;
            bundle_path = Some(bp);
        } else if line.starts_with("fetch ") {
            // Consume the rest of the fetch batch (lines until a blank line).
            // The first fetch line is already in `line`; drain until blank/EOF.
            loop {
                match read_line(&mut inp)? {
                    Some(l) if l.is_empty() => break,
                    Some(_) => {} // another fetch <sha> <ref> line -- ignore, we unbundle all
                    None => break, // EOF
                }
            }

            // Unbundle once for the whole batch.
            let bp = bundle_path
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("fetch received before list"))?;
            let bp_str = bp.to_str().ok_or_else(|| anyhow::anyhow!("non-UTF8 temp path"))?;
            bundle_unbundle(bp_str).context("unbundling into object store")?;

            out.write_all(b"\n")?;
            out.flush()?;
        } else {
            // Unknown command -- log to stderr (not stdout), keep going.
            eprintln!("git-remote-lcdp: unknown command: {line}");
        }
    }

    // Clean up the temp bundle file.
    if let Some(bp) = bundle_path {
        std::fs::remove_file(&bp).ok();
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("git-remote-lcdp: {e:#}");
        std::process::exit(1);
    }
}
