//! git-remote-lcdp -- git remote helper for lcdp:// URLs.
//!
//! Implements the git remote-helper protocol (gitremote-helpers(7)) for the
//! `fetch` and `push` capabilities. git invokes this binary as:
//!
//!   git-remote-lcdp <remote-name> lcdp://0x<pub>/<name>
//!
//! and speaks a line-oriented protocol on stdin/stdout.
//!
//! FETCH path: download a git bundle from the local node (same NodeClient path
//! that `cjpctl clone` / `cjpctl pull` use), then serve git's fetch/list
//! commands by delegating to `git bundle list-heads` and `git bundle unbundle`.
//!
//! PUSH path: validate the URL pubkey matches the node's own pubkey (you can
//! only publish under your own key), create a git bundle of the requested refs,
//! and publish it via `NodeClient::publish` (same path as `cjpctl share-repo`).
//!
//! Protocol summary:
//!   capabilities     -> "fetch\npush\n\n"
//!   option ...       -> "ok\n"
//!   list             -> one "<sha> <ref>" per head + optional "@<branch> HEAD" + "\n"
//!   list for-push    -> same, but 404 on the bundle is OK (returns just "\n")
//!   fetch <s> <r>    -> batch terminated by blank line; unbundle into object
//!                       store; reply "\n"
//!   push <src>:<dst> -> batch terminated by blank line; bundle local refs;
//!                       publish as repos/<name>.bundle; reply "ok <dst>" per ref
//!   <blank>/EOF      -> exit 0

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
// Push helpers
// ---------------------------------------------------------------------------

/// Normalize a pubkey string for comparison: strip "0x" prefix, lowercase.
fn normalize_pubkey(k: &str) -> String {
    k.trim_start_matches("0x").to_ascii_lowercase()
}

/// Parse a push refspec line ("push <src>:<dst>" or "push +<src>:<dst>").
/// Returns (src_ref, dst_ref).  A leading '+' (force) is stripped from src.
fn parse_push_refspec(line: &str) -> Option<(String, String)> {
    // line format: "push [+]<src>:<dst>"
    let rest = line.strip_prefix("push ")?;
    let rest = rest.strip_prefix('+').unwrap_or(rest); // strip force marker
    let (src, dst) = rest.split_once(':')?;
    if src.is_empty() || dst.is_empty() {
        return None;
    }
    Some((src.to_string(), dst.to_string()))
}

/// Create a git bundle from the given src refs.
/// Returns the path to the temp bundle file (caller must remove it).
fn bundle_create(refs: &[String], bundle_path: &str) -> Result<()> {
    let mut args: Vec<&str> = vec!["bundle", "create", bundle_path];
    for r in refs {
        args.push(r.as_str());
    }
    git(&args).context("creating git bundle for push")?;
    Ok(())
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
            out.write_all(b"fetch\npush\n\n")?;
            out.flush()?;
        } else if line.starts_with("option ") {
            // Accept/ignore all options.
            out.write_all(b"ok\n")?;
            out.flush()?;
        } else if line == "list" {
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
        } else if line == "list for-push" {
            // Advertise currently-published refs for fast-forward checks.
            // If the bundle does not exist yet (first push), return an empty
            // ref list -- do NOT error.
            let server_path = bundle_server_path(&pub_hex, &name);
            match client.fetch_bytes(&server_path, Duration::from_secs(30)) {
                Ok(bytes) => {
                    let p = tmp_bundle(&name);
                    if std::fs::write(&p, &bytes).is_ok() {
                        let p_str = p.to_str().unwrap_or_default();
                        if let Ok(heads) = bundle_list_heads(p_str) {
                            for h in &heads {
                                out.write_all(h.as_bytes())?;
                                out.write_all(b"\n")?;
                            }
                            bundle_path = Some(p);
                        }
                    }
                }
                Err(_) => {
                    // 404 or unreachable: first push, no existing bundle -- fine.
                }
            }
            out.write_all(b"\n")?;
            out.flush()?;
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
        } else if line.starts_with("push ") {
            // Collect the full push batch (lines until blank/EOF).
            let mut push_lines: Vec<String> = vec![line.clone()];
            loop {
                match read_line(&mut inp)? {
                    Some(l) if l.is_empty() => break,
                    Some(l) if l.starts_with("push ") => push_lines.push(l),
                    Some(_) => {}  // unexpected non-push line, ignore
                    None => break, // EOF
                }
            }

            // Parse all refspecs.
            let refspecs: Vec<(String, String)> =
                push_lines.iter().filter_map(|l| parse_push_refspec(l)).collect();

            if refspecs.is_empty() {
                // Nothing to push -- send blank line terminator.
                out.write_all(b"\n")?;
                out.flush()?;
                continue;
            }

            // Own-key check: only allow pushing under the node's own pubkey.
            let node_pub = match client.status() {
                Ok(s) => s.public_key,
                Err(e) => {
                    for (_, dst) in &refspecs {
                        writeln!(out, "error {dst} could not fetch node status: {e}")?;
                    }
                    out.write_all(b"\n")?;
                    out.flush()?;
                    continue;
                }
            };

            let url_pub_norm = normalize_pubkey(&pub_hex);
            let node_pub_norm = normalize_pubkey(&node_pub);

            if url_pub_norm != node_pub_norm {
                let node_pub_display = node_pub.trim_start_matches("0x");
                for (_, dst) in &refspecs {
                    writeln!(
                        out,
                        "error {dst} can only push under your own pubkey 0x{node_pub_display}"
                    )?;
                }
                out.write_all(b"\n")?;
                out.flush()?;
                continue;
            }

            // Bundle the source refs and publish.
            let tmp = tmp_bundle(&format!("{name}-push"));
            let tmp_str = match tmp.to_str() {
                Some(s) => s.to_string(),
                None => {
                    for (_, dst) in &refspecs {
                        writeln!(out, "error {dst} non-UTF8 temp path")?;
                    }
                    out.write_all(b"\n")?;
                    out.flush()?;
                    continue;
                }
            };

            let src_refs: Vec<String> = refspecs.iter().map(|(src, _)| src.clone()).collect();
            let bundle_result = bundle_create(&src_refs, &tmp_str);

            let publish_result = bundle_result.and_then(|_| {
                let server_name = format!("repos/{name}.bundle");
                client.publish(&server_name, &tmp).context("publishing bundle to node")
            });

            // Clean up temp bundle regardless of outcome.
            std::fs::remove_file(&tmp).ok();

            match publish_result {
                Ok(_) => {
                    for (_, dst) in &refspecs {
                        writeln!(out, "ok {dst}")?;
                    }
                }
                Err(e) => {
                    for (_, dst) in &refspecs {
                        writeln!(out, "error {dst} {e:#}")?;
                    }
                }
            }
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
