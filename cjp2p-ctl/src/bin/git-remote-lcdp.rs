//! git-remote-lcdp -- git remote helper for lcdp:// URLs.
//!
//! Implements the git remote-helper protocol (gitremote-helpers(7)) for the
//! `fetch` and `push` capabilities. git invokes this binary as:
//!
//!   git-remote-lcdp <remote-name> lcdp://0x<pub>/<path>
//!
//! and speaks a line-oriented protocol on stdin/stdout.
//!
//! FETCH path: download a git bundle from the local node (same NodeClient path
//! that `cjpctl clone` / `cjpctl pull` use), then serve git's fetch/list
//! commands by delegating to `git bundle list-heads` and `git bundle unbundle`.
//! Downloads go through a PERSISTENT, CONTENT-ADDRESSED cache: the node emits
//! `ETag: "<sha256>"` on `/latest`, so the helper keeps the last bundle plus its
//! etag and re-fetches with `If-None-Match`.  A `304 Not Modified` reuses the
//! cached bundle with no re-download.  A cached pair is trusted ONLY when
//! sha256(bundle) == etag, so a torn/truncated pair can never be served.
//!
//! PUSH path: validate the URL pubkey matches the node's own pubkey (you can
//! only publish under your own key), then publish a git bundle via
//! `NodeClient::publish` (same path as `cjpctl share-repo`).
//!
//! The push is ADDITIVE: the remote is a single bundle, but git only sends the
//! CHANGED refs on each invocation, so naively re-bundling just those refs would
//! silently DROP every unchanged branch already on the remote.  A real remote
//! preserves untouched refs, so we reconstruct the UNION:
//!   1. Fetch the existing remote bundle (a miss == first push; bounded probe).
//!   2. In a TEMP git repo, unbundle the existing remote (existing refs + objects).
//!   3. Apply each pushed refspec into the temp repo: fetch `<src>:<dst>` from the
//!      LOCAL repo for an update, or `update-ref -d <dst>` for a delete (`:<dst>`).
//!   4. `git bundle create --all` from the temp repo (existing preserved + pushed
//!      updated + deletes removed) and publish that at the mirrored path.
//!
//! URL -> real-URL mapping: the lcdp:// URL MIRRORS the node's real content URL,
//! the only transform being `http://<node>/` -> `lcdp://`.  Concretely:
//!
//!   lcdp://0x<pub>/<path>  ==  GET http://<node>/latest/0x<pub>/<path>
//!
//! `<path>` after the pubkey is used VERBATIM under `/latest/0x<pub>/...`: no
//! `repos/` insertion, no `.bundle` synthesis, no bare-vs-repos translation, no
//! fallback.  You type the full published path, including any `repos/` prefix
//! and the `.bundle` suffix, exactly as it appears in the real URL.  Examples:
//!   lcdp://0x<pub>/repos/cjp2p-rust.bundle -> GET /latest/0x<pub>/repos/cjp2p-rust.bundle
//!   lcdp://0x<pub>/cjp2p.bundle            -> GET /latest/0x<pub>/cjp2p.bundle
//! PUSH publishes at the SAME mirrored path, so push/fetch are symmetric.
//!
//! HARDENING (untrusted-remote defense): a downloaded bundle is `git bundle
//! verify`-ed BEFORE any of its refs are advertised or unbundled (fail closed),
//! and `list` drops (with a stderr warning, never an echo) any refname that does
//! not match a strict `refs/(heads|tags)/...` allowlist -- so a hostile bundle
//! cannot inject a bogus or path-traversing refname into git's ref namespace.
//!
//! Protocol summary:
//!   capabilities     -> "fetch\npush\n\n"
//!   option ...       -> "ok\n"
//!   list             -> one "<sha> <ref>" per head + optional "@<branch> HEAD" + "\n"
//!   list for-push    -> same, but 404 on the bundle is OK (returns just "\n")
//!   fetch <s> <r>    -> batch terminated by blank line; unbundle into object
//!                       store; reply "\n"
//!   push <src>:<dst> -> batch terminated by blank line; bundle local refs;
//!                       publish at the mirrored path; reply "ok <dst>" per ref
//!   <blank>/EOF      -> exit 0

use anyhow::{bail, Context, Result};
use cjp2p_ctl::client::{Fetched, NodeClient};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

// ---------------------------------------------------------------------------
// URL / path helpers (mirrors git.rs but self-contained to avoid pulling in
// the share/clone/pull API surface which needs the full NodeClient).
// ---------------------------------------------------------------------------

/// Parse lcdp://0x<pub>/<path> -> (pub_hex, path).
///
/// `pub_hex` keeps any "0x" prefix.  `path` is the VERBATIM content path that
/// follows the pubkey -- it maps directly onto `/latest/0x<pub>/<path>`, with no
/// translation (no `repos/` insertion, no `.bundle` synthesis, no fallback).
fn parse_url(url: &str) -> Result<(String, String)> {
    let s = url
        .trim()
        .strip_prefix("lcdp://")
        .ok_or_else(|| anyhow::anyhow!("url must start with lcdp:// (got {url})"))?;
    let mut parts = s.splitn(2, '/');
    let pub_hex = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().trim_end_matches('/').to_string();
    if pub_hex.is_empty() || path.is_empty() {
        bail!("url must be lcdp://0x<pubkey>/<path> (got {url})");
    }
    Ok((pub_hex, path))
}

/// Real content URL for a published path, mirroring the node's HTTP surface:
/// `lcdp://0x<pub>/<path>` -> `GET /latest/0x<pub>/<path>` (path used verbatim).
fn bundle_server_path(pub_hex: &str, path: &str) -> String {
    format!("/latest/0x{}/{}", pub_hex.trim_start_matches("0x"), path)
}

/// Read the per-fetch read timeout from `CJP2P_LCDP_FETCH_TIMEOUT_SECS`.
///
/// Default (unset/empty/unparseable/0) is `None` == no timeout: a fetch pends
/// until the body arrives or the user interrupts (ctrl-C, or a `timeout N`
/// prefix), per kermit -- "I'd set it to infinity, not reduce it."  A positive
/// value caps a stalled fetch at that many seconds when explicitly requested.
///
/// NOTE: the genuinely better signal than any timeout is an event-driven,
/// node-side "content not available" reply instead of the node parking the
/// socket on a missing/unreachable item -- that is a FUTURE node-side track,
/// out of scope for this helper.
fn fetch_timeout() -> Option<Duration> {
    env_timeout_secs().flatten().map(Duration::from_secs)
}

/// Default probe timeout, in seconds, for the `list for-push` existence check.
const PROBE_TIMEOUT_SECS: u64 = 5;

/// Read timeout for the `list for-push` EXISTENCE PROBE (does a base bundle
/// already exist, for fast-forward checks?).
///
/// Unlike a user-facing fetch, a miss here is the NORMAL first-push case, and
/// the node parks the socket on missing content (it has no "not available"
/// reply -- see the NOTE on `fetch_timeout`).  So this MUST be bounded, or the
/// very first push to a brand-new path would hang forever.  Default is a short
/// `PROBE_TIMEOUT_SECS` so a miss auto-resolves to "no base bundle -> first
/// push" with no env var and no hang; an explicit
/// `CJP2P_LCDP_FETCH_TIMEOUT_SECS` (including 0 == none) overrides it.
fn probe_timeout() -> Option<Duration> {
    match env_timeout_secs() {
        Some(over) => over.map(Duration::from_secs),
        None => Some(Duration::from_secs(PROBE_TIMEOUT_SECS)),
    }
}

/// Parse `CJP2P_LCDP_FETCH_TIMEOUT_SECS`: `None` == unset (use the caller's
/// default), `Some(None)` == explicit "no timeout" (0/empty/unparseable),
/// `Some(Some(secs))` == explicit positive cap.
fn env_timeout_secs() -> Option<Option<u64>> {
    let v = std::env::var("CJP2P_LCDP_FETCH_TIMEOUT_SECS").ok()?;
    match v.trim().parse::<u64>() {
        Ok(0) | Err(_) => Some(None),
        Ok(secs) => Some(Some(secs)),
    }
}

/// Temp file path for the fetched bundle, unique per-process.  Used as the
/// cache fallback when no cache dir is writable, and for push temp bundles.
fn tmp_bundle(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "lcdp-remote-{}-{}.bundle",
        sanitize(name),
        std::process::id()
    ))
}

// ---------------------------------------------------------------------------
// Persistent, content-addressed bundle cache (ETag / conditional GET).
//
// The node content-addresses with sha256 and emits that same hex as the
// `/latest` ETag, so the cache keeps the last bundle plus its etag and re-fetches
// with `If-None-Match`; a 304 reuses the cached bundle with no re-download.  A
// cached pair is trusted ONLY when sha256(bundle) == etag, so a torn/truncated
// pair can never be served as current.
// ---------------------------------------------------------------------------

/// Lowercase-hex sha256 of `bytes`. The node content-addresses with sha256 and
/// emits that same hex as the `/latest` ETag, so this is what a cached bundle's
/// `.etag` file must equal to be trustworthy.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Persistent bundle-cache directory: $XDG_CACHE_HOME/cjp2p-lcdp/bundles/, else
/// $HOME/.cache/cjp2p-lcdp/bundles/. `None` if neither var is set (no usable
/// cache home -> caller falls back to a per-process temp bundle). Hand-rolled to
/// avoid pulling in a `dirs` dependency.
fn cache_dir() -> Option<PathBuf> {
    let xdg = std::env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty());
    let home = std::env::var_os("HOME").filter(|v| !v.is_empty());
    cache_dir_from(xdg, home)
}

/// Pure resolver for `cache_dir` (env values passed in, so it is unit-testable
/// without mutating process-global env vars).
fn cache_dir_from(
    xdg: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    let base = match xdg {
        Some(v) => PathBuf::from(v),
        None => PathBuf::from(home?).join(".cache"),
    };
    Some(base.join("cjp2p-lcdp").join("bundles"))
}

/// Cache key for a server path: the sanitized path (human-legible) plus a short
/// hex of the sha256 of the FULL unsanitized path. The hash suffix prevents the
/// sanitize() collision where distinct paths fold to the same key (e.g.
/// `.../my/repo` and `.../my_repo` both sanitize to `..._my_repo`).
fn cache_key(server_path: &str) -> String {
    let digest = sha256_hex(server_path.as_bytes());
    format!("{}.{}", sanitize(server_path), &digest[..16])
}

/// Cache file pair for a server path: (`<dir>/<key>.bundle`, `<dir>/<key>.etag`).
/// Returns `None` if no cache dir is available or it cannot be created.
fn cache_paths(server_path: &str) -> Option<(PathBuf, PathBuf)> {
    let dir = cache_dir()?;
    std::fs::create_dir_all(&dir).ok()?;
    let key = cache_key(server_path);
    Some((dir.join(format!("{key}.bundle")), dir.join(format!("{key}.etag"))))
}

/// Write `bytes` to `path` atomically (write to a sibling temp then rename).
///
/// The temp name PRESERVES the full file name and adds a per-process suffix
/// (`<file_name>.<pid>.tmp`). `path.with_extension("tmp")` would collapse
/// `<key>.bundle` and `<key>.etag` onto the SAME `<key>.tmp`, so two writers
/// (or the bundle+etag writes of one fetch) could clobber each other's temp.
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "cache path has no file name")
    })?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(format!(".{}.tmp", std::process::id()));
    let tmp = path.with_file_name(tmp_name);
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// Validate a cached `<bundle>`/`<etag>` pair before trusting it for a
/// conditional fetch. Returns the etag string ONLY when the bundle's sha256
/// matches the cached etag (the node's ETag IS the sha256 of the content), so a
/// torn/truncated/corrupt pair -- old bundle + new etag, a half-written bundle,
/// or a foreign etag -- is rejected. `None` means "do not trust; re-fetch
/// unconditionally" and the caller drops the pair.
///
/// This is what makes a 304 safe: we never send `If-None-Match` for a pair whose
/// bytes do not hash to the etag we would send, so a 304 can only ever reuse the
/// exact content the node still considers current. It also self-heals a
/// truncated bundle (whose hash will not match) that `git bundle list-heads`
/// alone would wave through.
fn validate_cached_pair(bundle: &std::path::Path, etag_file: &std::path::Path) -> Option<String> {
    let etag = std::fs::read_to_string(etag_file).ok()?.trim().to_string();
    if etag.is_empty() {
        return None;
    }
    let bytes = std::fs::read(bundle).ok()?;
    if sha256_hex(&bytes) == etag {
        Some(etag)
    } else {
        None
    }
}

/// Fetch the bundle for `server_path`, using the persistent cache and a
/// conditional GET when a trustworthy ETag is on file. Returns the path to a
/// usable bundle (a cached file on 304/reuse, a freshly-written cache file on
/// 200, or a per-process temp file when no cache dir is writable). `timeout`
/// follows the same `Option<Duration>` discipline as `NodeClient::fetch_bytes`:
/// `None` == no read timeout (unbounded, for user-facing `list`), `Some(d)` ==
/// bounded (for the `list for-push` / push existence probe).
///
/// Corrupt/missing cached bundle is treated as a miss: the pair is removed and
/// the content re-fetched UNCONDITIONALLY (never trust a 304 against a bundle we
/// cannot read).
fn fetch_bundle_cached(
    client: &NodeClient,
    server_path: &str,
    name: &str,
    timeout: Option<Duration>,
) -> Result<PathBuf> {
    let cache = cache_paths(server_path);

    // Only send `If-None-Match` when the cached bundle's sha256 matches the
    // cached etag. The node's ETag IS the sha256 of the content, so a matching
    // pair is exactly the content the node would 304 against; a non-matching
    // pair (torn old-bundle/new-etag, truncated/half-written bundle, or a
    // foreign etag) is dropped and re-fetched UNCONDITIONALLY. This is the
    // single guard that closes the torn-pair stale-fetch hole and self-heals a
    // truncated bundle that `git bundle list-heads` alone would pass.
    let mut cached_etag: Option<String> = None;
    if let Some((ref bundle, ref etag_file)) = cache {
        match validate_cached_pair(bundle, etag_file) {
            Some(etag) => cached_etag = Some(etag),
            None => {
                // Torn/corrupt/partial pair -> drop both so we re-fetch fresh.
                std::fs::remove_file(bundle).ok();
                std::fs::remove_file(etag_file).ok();
            }
        }
    }

    let fetched = client
        .fetch_bytes_cond(server_path, cached_etag.as_deref(), timeout)
        .context("fetching bundle from node")?;

    match fetched {
        Fetched::NotModified => {
            // Node confirms the cached bundle is current. We only sent
            // If-None-Match when the cached bundle was usable, so this is safe.
            if let Some((bundle, _)) = cache {
                return Ok(bundle);
            }
            // Should not happen (no etag sent without a cache), but be safe:
            // re-fetch unconditionally rather than trust a phantom cache.
            let bytes = client
                .fetch_bytes(server_path, timeout)
                .context("re-fetching bundle from node (304 without cache)")?;
            let p = tmp_bundle(name);
            std::fs::write(&p, &bytes).context("writing bundle to temp file")?;
            Ok(p)
        }
        Fetched::Fresh {
            body,
            etag,
        } => {
            // Try the persistent cache first; fall back to a temp file if the
            // cache dir is unwritable (read-only HOME etc.).
            if let Some((bundle, etag_file)) = cache {
                if write_atomic(&bundle, &body).is_ok() {
                    if let Some(tag) = etag {
                        write_atomic(&etag_file, tag.as_bytes()).ok();
                    } else {
                        std::fs::remove_file(&etag_file).ok();
                    }
                    return Ok(bundle);
                }
            }
            let p = tmp_bundle(name);
            std::fs::write(&p, &body).context("writing bundle to temp file")?;
            Ok(p)
        }
    }
}

/// True if `p` lives under the persistent cache dir (so it must be kept, not
/// deleted on cleanup, and is the kind of bundle that can self-heal a corrupt
/// re-fetch).
fn is_cached_path(p: &std::path::Path) -> bool {
    cache_dir().map(|d| p.starts_with(&d)).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// git helpers
// ---------------------------------------------------------------------------

/// Run a git subcommand, capture stdout, propagate stderr.
fn git(args: &[&str]) -> Result<String> {
    run_git(args, false)
}

/// Like `git`, but with the inherited git repo environment CLEARED so the
/// command operates purely on the `-C <dir>` target.
///
/// git sets `GIT_DIR` (and friends) in the remote-helper's environment, and an
/// explicit `GIT_DIR` env var OVERRIDES `-C <dir>` -- so a naive
/// `git -C <temp> bundle create --all` would bundle the USER's repo, not the
/// temp repo (the additive-push union is built in a temp repo).  Strip those
/// vars so temp-repo commands really run against the temp repo.
fn git_clean(args: &[&str]) -> Result<String> {
    run_git(args, true)
}

fn run_git(args: &[&str], clean_env: bool) -> Result<String> {
    let mut cmd = Command::new("git");
    cmd.args(args);
    if clean_env {
        // Vars git injects when invoking the helper that would hijack `-C`.
        for var in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_COMMON_DIR",
            "GIT_NAMESPACE",
        ] {
            cmd.env_remove(var);
        }
    }
    let out = cmd.output().with_context(|| format!("running: git {}", args.join(" ")))?;
    if !out.status.success() {
        bail!("git {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `git bundle verify <bundle>`: confirm the bundle is well-formed and its
/// prerequisites are satisfiable as a self-contained bundle.  Run BEFORE any of
/// the bundle's refs are advertised or unbundled, so a malformed/corrupt/hostile
/// bundle fails closed instead of feeding bogus objects into the object store.
fn bundle_verify(bundle: &str) -> Result<()> {
    git(&["bundle", "verify", bundle])
        .map(|_| ())
        .with_context(|| format!("bundle failed verification: {bundle}"))
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

/// Strict refname allowlist for refs advertised out of a DOWNLOADED bundle.
///
/// A bundle is untrusted input: a hostile or buggy publisher could advertise a
/// refname that escapes the `refs/(heads|tags)/` namespace, traverses the path
/// (`..`), looks like an option (leading `-`), or is otherwise a name git itself
/// would reject (`.lock` suffix, control bytes, `//`, etc.).  `list` MUST drop
/// such names (with a stderr warning, never echoing them to git's stdout), so
/// the helper never injects a bogus ref into git's namespace.  Accepts only:
///
///   ^refs/(heads|tags)/[A-Za-z0-9._/-]+$
///
/// with the extra git-refname rules layered on: no `..`, no leading `-`, no
/// leading/trailing `/`, no `//`, no `.lock` suffix, no control bytes, bounded
/// length.  (Conservative: a few exotic-but-legal names are rejected; that only
/// costs a warning, never safety.)
fn validate_refname(refname: &str) -> bool {
    // Bounded length: git itself caps ref paths well under this; an absurdly
    // long name is a red flag, not a real branch.
    if refname.is_empty() || refname.len() > 255 {
        return false;
    }
    // Must live under an allowed namespace: heads/tags for branches and tags,
    // plus git-bug's CRDT data refs (bugs/identities) so the review board can
    // travel over this transport. Still excludes dangerous namespaces such as
    // refs/replace/* and refs/notes/*.
    let rest = match refname
        .strip_prefix("refs/heads/")
        .or_else(|| refname.strip_prefix("refs/tags/"))
        .or_else(|| refname.strip_prefix("refs/bugs/"))
        .or_else(|| refname.strip_prefix("refs/identities/"))
    {
        Some(r) => r,
        None => return false,
    };
    if rest.is_empty() {
        return false;
    }
    // No control bytes / non-ASCII; only the allowlisted character class.
    if !rest.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-')) {
        return false;
    }
    // Path-traversal / option-injection / git ref-format rules.
    if rest.contains("..") {
        return false;
    }
    if rest.starts_with('-') {
        return false;
    }
    if rest.starts_with('/') || rest.ends_with('/') {
        return false;
    }
    if rest.contains("//") {
        return false;
    }
    if rest.ends_with(".lock") {
        return false;
    }
    true
}

/// The untrusted-bundle -> advertise boundary, fail-closed in one place: verify
/// the bundle, then return only its "<sha> <refname>" heads whose refname passes
/// the `validate_refname` allowlist (dropping the rest with a stderr warning,
/// never echoing them).  Used by BOTH advertise paths (`list`, `list for-push`)
/// so the verify+allowlist gate stays byte-identical between them.
fn verified_safe_heads(bundle: &str) -> Result<Vec<String>> {
    bundle_verify(bundle)?;
    let heads = bundle_list_heads(bundle).context("listing bundle heads")?;
    Ok(heads
        .into_iter()
        .filter(|h| match refname_of(h) {
            Some(r) if validate_refname(r) => true,
            _ => {
                eprintln!("git-remote-lcdp: dropping bundle ref failing the refname allowlist");
                false
            }
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Push helpers
// ---------------------------------------------------------------------------

/// Normalize a pubkey string for comparison: strip "0x" prefix, lowercase.
fn normalize_pubkey(k: &str) -> String {
    k.trim_start_matches("0x").to_ascii_lowercase()
}

/// A parsed push refspec.  `src` is `None` for a delete (`push :<dst>`).
struct PushSpec {
    /// Source ref in the LOCAL repo, or `None` for a delete.
    src: Option<String>,
    /// Destination ref on the remote.
    dst: String,
}

/// Parse a push refspec line ("push <src>:<dst>", "push +<src>:<dst>", or the
/// delete form "push :<dst>").  A leading '+' (force) is stripped from src; an
/// empty src means a delete.
fn parse_push_refspec(line: &str) -> Option<PushSpec> {
    // line format: "push [+]<src>:<dst>" (delete: "push :<dst>")
    let rest = line.strip_prefix("push ")?;
    let rest = rest.strip_prefix('+').unwrap_or(rest); // strip force marker
    let (src, dst) = rest.split_once(':')?;
    if dst.is_empty() {
        return None;
    }
    let src = if src.is_empty() {
        None
    } else {
        Some(src.to_string())
    };
    Some(PushSpec {
        src,
        dst: dst.to_string(),
    })
}

/// Absolute path to the LOCAL repo's git dir, so the temp repo can fetch source
/// objects from it.  git runs the helper with cwd/GIT_DIR inside the user's repo,
/// so `git rev-parse --absolute-git-dir` resolves it robustly.
fn local_git_dir() -> Result<String> {
    let out = git(&["rev-parse", "--absolute-git-dir"])?;
    let p = out.trim();
    if p.is_empty() {
        bail!("could not resolve local git dir");
    }
    Ok(p.to_string())
}

/// A throwaway git repo under temp_dir, removed on drop.
struct TempRepo {
    dir: PathBuf,
}

impl TempRepo {
    /// Create and `git init` a fresh temp repo unique to this process + nonce.
    fn init(nonce: &str) -> Result<TempRepo> {
        let dir = std::env::temp_dir().join(format!("lcdp-push-{}-{}", std::process::id(), nonce));
        // Start clean in case a stale dir lingers from a crashed prior run.
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating temp repo dir {}", dir.display()))?;
        let dir_str = dir.to_str().ok_or_else(|| anyhow::anyhow!("non-UTF8 temp repo path"))?;
        // -q to keep stdout clean; the helper's stdout is the git protocol.
        // git_clean: the inherited GIT_DIR would otherwise hijack this init.
        git_clean(&["init", "-q", dir_str]).context("git init temp push repo")?;
        Ok(TempRepo {
            dir,
        })
    }

    fn path_str(&self) -> Result<&str> {
        self.dir.to_str().ok_or_else(|| anyhow::anyhow!("non-UTF8 temp repo path"))
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

/// Unbundle an existing remote bundle into the temp repo, importing every
/// existing remote ref (and its objects) under its original name.
fn temp_unbundle_existing(temp: &str, bundle: &str) -> Result<()> {
    // HARDENING: this is the push-path unbundle, and the existing bundle is
    // untrusted input (re-fetched fresh when `list for-push`'s verify failed, so
    // it can be the very corrupt/hostile bundle that failed there).  Fail closed
    // like the advertise paths: verify the bundle BEFORE touching it, and run
    // every refname through `validate_refname` before `update-ref` so an
    // option-like / traversing name can neither wedge the union build nor escape
    // git's namespace.
    bundle_verify(bundle)?;
    // `bundle unbundle` only writes the objects; it does not create refs.  We
    // unbundle, then create each ref the bundle advertised so it survives into
    // the union `bundle create --all`.  git_clean throughout: `-C <temp>` must
    // beat the inherited GIT_DIR.
    git_clean(&["-C", temp, "bundle", "unbundle", bundle]).context("unbundling existing remote")?;
    for line in bundle_list_heads(bundle)? {
        if let Some((sha, refname)) = line.split_once(' ') {
            if !validate_refname(refname) {
                eprintln!(
                    "git-remote-lcdp: dropping existing-remote ref failing the refname allowlist"
                );
                continue;
            }
            git_clean(&["-C", temp, "update-ref", refname, sha])
                .with_context(|| format!("recreating existing remote ref {refname}"))?;
        }
    }
    Ok(())
}

/// Apply one pushed refspec into the temp repo: fetch `<src>:<dst>` from the
/// LOCAL repo for an update, or delete `<dst>` for a delete refspec.
fn temp_apply_refspec(temp: &str, local_git_dir: &str, spec: &PushSpec) -> Result<()> {
    match &spec.src {
        Some(src) => {
            // Force-update the dst ref to the local src object (push semantics:
            // the pushed ref wins; git already enforced fast-forward unless +).
            let refspec = format!("+{src}:{dst}", dst = spec.dst);
            git_clean(&["-C", temp, "fetch", "--no-tags", local_git_dir, &refspec])
                .with_context(|| format!("fetching {src} from local repo for push"))?;
        }
        None => {
            // Delete: drop the dst ref from the union.  Missing == already gone.
            git_clean(&["-C", temp, "update-ref", "-d", &spec.dst]).ok();
        }
    }
    Ok(())
}

/// A temp bundle file removed on drop.
struct TempBundle {
    path: PathBuf,
}

impl TempBundle {
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempBundle {
    fn drop(&mut self) {
        std::fs::remove_file(&self.path).ok();
    }
}

/// Build the UNION bundle for an additive push: import the existing remote refs
/// (if any), apply the pushed updates/deletes, then `bundle create --all`.
///
/// Returns a temp bundle holding the union (existing preserved, pushed refs
/// updated, deleted refs removed), with every reachable object included.  Errors
/// if the resulting union has no refs (e.g. a delete that empties the remote),
/// since git cannot create an empty bundle.
fn build_additive_bundle(
    path: &str,
    local_git_dir: &str,
    existing: Option<&std::path::Path>,
    specs: &[PushSpec],
) -> Result<TempBundle> {
    // Unique nonce so concurrent/repeat calls in one process never collide.
    let nonce = next_nonce();
    let temp = TempRepo::init(&format!("{}-{nonce}", sanitize(path)))?;
    let temp_str = temp.path_str()?;

    // 1. Import existing remote refs + objects (skip on first push).
    if let Some(existing) = existing {
        let existing_str =
            existing.to_str().ok_or_else(|| anyhow::anyhow!("non-UTF8 existing bundle path"))?;
        temp_unbundle_existing(temp_str, existing_str)?;
    }

    // 2. Apply each pushed refspec (update from local repo, or delete).
    for spec in specs {
        temp_apply_refspec(temp_str, local_git_dir, spec)?;
    }

    // 3. Bundle the union of all refs now in the temp repo.
    let out = TempBundle {
        path: tmp_bundle(&format!("{path}-union-{nonce}")),
    };
    let out_str =
        out.path().to_str().ok_or_else(|| anyhow::anyhow!("non-UTF8 union bundle path"))?;
    // git_clean: without it the inherited GIT_DIR makes `--all` bundle the
    // USER's entire repo instead of the temp repo's union.  This was the bug.
    let res = git_clean(&["-C", temp_str, "bundle", "create", out_str, "--all"]);
    // `--all` with no refs fails; surface a clear message rather than git's.
    res.context(
        "creating union bundle (a delete that removes the last ref leaves an empty remote, \
         which git cannot represent as a bundle)",
    )?;
    Ok(out)
}

/// Sanitize a string into a filesystem-safe nonce for temp dir/file names.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Monotonic per-process counter, so concurrent additive-push builds get
/// distinct temp dir/bundle names.
fn next_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

/// An advisory exclusive file lock (`flock(2)`) held for the duration of an
/// additive push to one path, released when dropped (on close).
///
/// The additive union (fetch base -> apply -> bundle --all -> publish) is a
/// read-modify-write, and the node has NO atomic/conditional publish (publish is
/// a blind overwrite).  Two overlapping pushes to the same path would each read
/// the same base, add only their own ref, and the later publish would silently
/// drop the earlier ref.  This lock SERIALIZES same-host pushes to one path so
/// they apply in turn.  NOTE: it is host-local only -- cross-host concurrent
/// pushes to one path remain the user's responsibility (no node-side CAS).
struct PushLock {
    _file: File,
}

impl PushLock {
    /// Acquire (blocking) the per-path push lock.  Lock file lives in the cache
    /// dir when available (stable across runs), else the temp dir.
    fn acquire(path: &str) -> Result<PushLock> {
        let name = format!("lcdp-push-{}.lock", sanitize(path));
        let lock_path = cache_dir()
            .and_then(|d| std::fs::create_dir_all(&d).ok().map(|_| d))
            .unwrap_or_else(std::env::temp_dir)
            .join(name);
        let file = File::create(&lock_path)
            .with_context(|| format!("opening push lock {}", lock_path.display()))?;
        // LOCK_EX, blocking: wait until any concurrent same-path push releases.
        let rc = unsafe { flock(file.as_raw_fd(), LOCK_EX) };
        if rc != 0 {
            return Err(anyhow::Error::new(io::Error::last_os_error())
                .context(format!("locking {}", lock_path.display())));
        }
        Ok(PushLock {
            _file: file,
        })
    }
}

// flock(2): advisory whole-file lock, auto-released on close (Drop of `_file`).
const LOCK_EX: i32 = 2;
extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

// ---------------------------------------------------------------------------
// Protocol loop
// ---------------------------------------------------------------------------

/// Terminate a remote-helper command's response: the git remote-helper line
/// protocol ends each command's reply with a blank line.  Write it and flush so
/// git sees the batch boundary.
fn end_batch(out: &mut impl Write) -> Result<()> {
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

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

    let (pub_hex, path) = parse_url(url)?;
    let client = NodeClient::resolve(None);
    // User-facing fetch: unbounded by default (pends until done or interrupt).
    let fetch_to = fetch_timeout();
    // Existence probe for `list for-push`: short bounded default so a miss
    // (the normal first-push case) auto-resolves instead of hanging.
    let probe_to = probe_timeout();

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
            // Fetch the bundle (or reuse if already fetched), through the
            // content-addressed cache (conditional GET / 304-reuse).
            let server_path = bundle_server_path(&pub_hex, &path);
            let bp = match bundle_path.take() {
                Some(p) => p,
                None => fetch_bundle_cached(&client, &server_path, &path, fetch_to)
                    .context("fetching bundle from node")?,
            };
            let bp_str = bp.to_str().ok_or_else(|| anyhow::anyhow!("non-UTF8 temp path"))?;
            // HARDENING: verify the downloaded bundle BEFORE advertising any of
            // its refs (fail closed on a malformed/corrupt/hostile bundle), and
            // drop (warn, never echo) any refname failing the strict
            // refs/(heads|tags)/... allowlist so a hostile bundle cannot inject a
            // bogus / path-traversing ref into git's namespace.
            let safe_heads = verified_safe_heads(bp_str)?;

            for h in &safe_heads {
                out.write_all(h.as_bytes())?;
                out.write_all(b"\n")?;
            }

            // Advertise a symbolic HEAD for the default branch: prefer
            // master/main, else the first refs/heads/* in the bundle.  Only
            // consider refs that passed the allowlist.
            let default_branch = safe_heads
                .iter()
                .filter_map(|h| refname_of(h))
                .find(|r| *r == "refs/heads/master" || *r == "refs/heads/main")
                .or_else(|| {
                    safe_heads
                        .iter()
                        .filter_map(|h| refname_of(h))
                        .find(|r| r.starts_with("refs/heads/"))
                });
            if let Some(branch) = default_branch {
                writeln!(out, "@{branch} HEAD")?;
            }

            end_batch(&mut out)?;
            bundle_path = Some(bp);
        } else if line == "list for-push" {
            // Advertise currently-published refs for fast-forward checks.
            // EXISTENCE PROBE: if the bundle does not exist yet (first push),
            // return an empty ref list -- do NOT error.  Bounded by `probe_to`
            // so a miss auto-resolves to "first push" instead of hanging on the
            // node parking the socket for missing content.
            let server_path = bundle_server_path(&pub_hex, &path);
            match fetch_bundle_cached(&client, &server_path, &path, probe_to) {
                Ok(p) => {
                    let p_str = p.to_str().unwrap_or_default();
                    // Same hardening on the for-push advertisement: verify, then
                    // only advertise allowlisted refnames (shared helper).
                    if let Ok(heads) = verified_safe_heads(p_str) {
                        for h in &heads {
                            out.write_all(h.as_bytes())?;
                            out.write_all(b"\n")?;
                        }
                        bundle_path = Some(p);
                    }
                }
                Err(_) => {
                    // 404 or unreachable: first push, no existing bundle -- fine.
                }
            }
            end_batch(&mut out)?;
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
            if let Err(e) = bundle_unbundle(bp_str).context("unbundling into object store") {
                // Self-heal: if the bundle that failed to unbundle is a CACHED
                // one, it is unusable despite passing the hash/header/verify
                // checks (e.g. genuine pack corruption). Drop the pair and
                // re-fetch UNCONDITIONALLY once, re-verify, then retry. A
                // per-process temp bundle (no cache dir) cannot self-heal this
                // way -- surface the error.
                let server_path = bundle_server_path(&pub_hex, &path);
                if is_cached_path(bp) {
                    if let Some((b, t)) = cache_paths(&server_path) {
                        std::fs::remove_file(&b).ok();
                        std::fs::remove_file(&t).ok();
                    }
                    let fresh = fetch_bundle_cached(&client, &server_path, &path, fetch_to)
                        .context("re-fetching bundle after unbundle failure")?;
                    let fresh_str =
                        fresh.to_str().ok_or_else(|| anyhow::anyhow!("non-UTF8 temp path"))?;
                    bundle_verify(fresh_str)?;
                    bundle_unbundle(fresh_str)
                        .context("unbundling into object store (after self-heal re-fetch)")?;
                    bundle_path = Some(fresh);
                } else {
                    return Err(e);
                }
            }

            end_batch(&mut out)?;
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

            // Parse all refspecs (updates + deletes).
            let specs: Vec<PushSpec> =
                push_lines.iter().filter_map(|l| parse_push_refspec(l)).collect();

            if specs.is_empty() {
                // Nothing to push -- send blank line terminator.
                end_batch(&mut out)?;
                continue;
            }

            // Own-key check: only allow pushing under the node's own pubkey.
            let node_pub = match client.status() {
                Ok(s) => s.public_key,
                Err(e) => {
                    for s in &specs {
                        writeln!(out, "error {} could not fetch node status: {e}", s.dst)?;
                    }
                    end_batch(&mut out)?;
                    continue;
                }
            };

            let url_pub_norm = normalize_pubkey(&pub_hex);
            let node_pub_norm = normalize_pubkey(&node_pub);

            if url_pub_norm != node_pub_norm {
                let node_pub_display = node_pub.trim_start_matches("0x");
                for s in &specs {
                    writeln!(
                        out,
                        "error {} can only push under your own pubkey 0x{node_pub_display}",
                        s.dst
                    )?;
                }
                end_batch(&mut out)?;
                continue;
            }

            // ADDITIVE push: rebuild the UNION of (existing remote refs) +
            // (pushed updates) - (deletes), so unchanged branches survive.
            //
            // Serialize same-host pushes to this path: hold an advisory lock
            // across fetch-existing -> union -> publish so two concurrent pushes
            // can't each read the same base and drop each other's ref (the node
            // has no atomic/conditional publish).  The lock is held until the end
            // of this push batch (dropped at the end of the `push` arm).  A lock
            // failure is non-fatal -- proceed unserialized rather than wedge.
            let _push_lock = PushLock::acquire(&path)
                .map_err(|e| eprintln!("git-remote-lcdp: push lock unavailable: {e:#}"))
                .ok();

            // 1. Get the EXISTING remote bundle.  Fetch FRESH under the lock (a
            //    concurrent push may have just changed the published base), so
            //    drop any pre-lock fetch from `list for-push`.  Bounded by
            //    `probe_to`: a miss (404 / unreachable) == first push.
            if let Some(p) = bundle_path.take() {
                if !is_cached_path(&p) {
                    std::fs::remove_file(&p).ok();
                }
            }
            let existing_bundle: Option<PathBuf> = {
                let server_path = bundle_server_path(&pub_hex, &path);
                fetch_bundle_cached(&client, &server_path, &path, probe_to).ok()
            };

            // Resolve the local repo (source of pushed objects) once.
            let outcome = local_git_dir().and_then(|local| {
                build_additive_bundle(&path, &local, existing_bundle.as_deref(), &specs).and_then(
                    |tmp| {
                        // Publish at the verbatim mirrored path so push == fetch.
                        let r =
                            client.publish(&path, tmp.path()).context("publishing bundle to node");
                        drop(tmp); // remove the union bundle now we're done with it
                        r
                    },
                )
            });

            // Drop a per-process temp existing bundle; keep a cached one (the
            // cache is the whole point -- a later fetch/push reuses it).
            if let Some(p) = existing_bundle {
                if !is_cached_path(&p) {
                    std::fs::remove_file(&p).ok();
                }
            }

            match outcome {
                Ok(_) => {
                    for s in &specs {
                        writeln!(out, "ok {}", s.dst)?;
                    }
                }
                Err(e) => {
                    for s in &specs {
                        writeln!(out, "error {} {e:#}", s.dst)?;
                    }
                }
            }
            end_batch(&mut out)?;
        } else {
            // Unknown command -- log to stderr (not stdout), keep going.
            eprintln!("git-remote-lcdp: unknown command: {line}");
        }
    }

    // Clean up only a per-process temp bundle.  A bundle under the persistent
    // cache dir is kept on purpose (that is the whole point of the cache).
    if let Some(bp) = bundle_path {
        if !is_cached_path(&bp) {
            std::fs::remove_file(&bp).ok();
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("git-remote-lcdp: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn parse_url_keeps_path_verbatim() {
        // The path after the pubkey is taken as-is: no `.bundle` stripping, no
        // `repos/` translation.  A `repos/` prefix and `.bundle` suffix survive.
        let (p, path) =
            parse_url("lcdp://0xb448/repos/cjp2p-rust.bundle").expect("parse repos path");
        assert_eq!(p, "0xb448");
        assert_eq!(path, "repos/cjp2p-rust.bundle");

        // A bare (no `repos/`) published path is equally verbatim.
        let (_, path) = parse_url("lcdp://0xb448/cjp2p.bundle").expect("parse bare path");
        assert_eq!(path, "cjp2p.bundle");
    }

    #[test]
    fn parse_url_rejects_missing_parts() {
        assert!(parse_url("https://0xb448/x").is_err()); // wrong scheme
        assert!(parse_url("lcdp://0xb448").is_err()); // no path
        assert!(parse_url("lcdp://0xb448/").is_err()); // empty path
        assert!(parse_url("lcdp:///cjp2p.bundle").is_err()); // no pubkey
    }

    #[test]
    fn server_path_mirrors_real_url() {
        // lcdp://0x<pub>/<path>  ->  GET /latest/0x<pub>/<path>  (verbatim path,
        // single 0x prefix even if the caller supplied one).
        assert_eq!(
            bundle_server_path("0xb448", "repos/cjp2p-rust.bundle"),
            "/latest/0xb448/repos/cjp2p-rust.bundle"
        );
        assert_eq!(bundle_server_path("b448", "cjp2p.bundle"), "/latest/0xb448/cjp2p.bundle");
    }

    // NB: `fetch_timeout`/`probe_timeout` read a process-global env var, so
    // these two cases share one test to avoid cross-test interference.
    #[test]
    fn fetch_unbounded_but_probe_bounded_by_default() {
        // Default: user-facing fetch is unbounded; the existence probe is
        // bounded so a first-push miss auto-resolves instead of hanging.
        std::env::remove_var("CJP2P_LCDP_FETCH_TIMEOUT_SECS");
        assert_eq!(fetch_timeout(), None, "fetch default is infinite");
        assert_eq!(
            probe_timeout(),
            Some(Duration::from_secs(PROBE_TIMEOUT_SECS)),
            "probe default is short-bounded"
        );

        // Invalid/empty also means "use defaults" for both.
        std::env::set_var("CJP2P_LCDP_FETCH_TIMEOUT_SECS", "not-a-number");
        assert_eq!(fetch_timeout(), None);
        assert_eq!(probe_timeout(), None, "explicit unparseable == no timeout, overrides probe");

        // Explicit 0 == "no timeout" overrides BOTH (the user opted out).
        std::env::set_var("CJP2P_LCDP_FETCH_TIMEOUT_SECS", "0");
        assert_eq!(fetch_timeout(), None);
        assert_eq!(probe_timeout(), None);

        // An explicit positive value caps BOTH the fetch and the probe.
        std::env::set_var("CJP2P_LCDP_FETCH_TIMEOUT_SECS", "45");
        assert_eq!(fetch_timeout(), Some(Duration::from_secs(45)));
        assert_eq!(probe_timeout(), Some(Duration::from_secs(45)));

        std::env::remove_var("CJP2P_LCDP_FETCH_TIMEOUT_SECS");
    }

    #[test]
    fn parse_push_refspec_handles_update_force_and_delete() {
        // Plain update.
        let s = parse_push_refspec("push refs/heads/master:refs/heads/master").unwrap();
        assert_eq!(s.src.as_deref(), Some("refs/heads/master"));
        assert_eq!(s.dst, "refs/heads/master");

        // Force update: the '+' is stripped from src.
        let s = parse_push_refspec("push +refs/heads/a:refs/heads/a").unwrap();
        assert_eq!(s.src.as_deref(), Some("refs/heads/a"));
        assert_eq!(s.dst, "refs/heads/a");

        // Delete: empty src.
        let s = parse_push_refspec("push :refs/heads/gone").unwrap();
        assert_eq!(s.src, None);
        assert_eq!(s.dst, "refs/heads/gone");

        // Malformed: empty dst, no colon, not a push line.
        assert!(parse_push_refspec("push refs/heads/a:").is_none());
        assert!(parse_push_refspec("push refs/heads/a").is_none());
        assert!(parse_push_refspec("list").is_none());
    }

    #[test]
    fn sanitize_keeps_safe_chars_and_replaces_separators() {
        assert_eq!(sanitize("repos/cjp2p-rust.bundle"), "repos_cjp2p-rust.bundle");
        assert_eq!(sanitize("a b/c"), "a_b_c");
        assert_eq!(sanitize("ok-1.2_3"), "ok-1.2_3");
    }

    // --- ETag / bundle-cache helper tests -----------------------------------

    #[test]
    fn cache_dir_prefers_xdg_then_home_then_none() {
        let bundles = PathBuf::from("cjp2p-lcdp").join("bundles");

        // XDG_CACHE_HOME set -> used verbatim as the base.
        assert_eq!(
            cache_dir_from(Some(OsString::from("/xdg/cache")), Some(OsString::from("/home/u"))),
            Some(PathBuf::from("/xdg/cache").join(&bundles))
        );

        // No XDG -> $HOME/.cache base.
        assert_eq!(
            cache_dir_from(None, Some(OsString::from("/home/u"))),
            Some(PathBuf::from("/home/u").join(".cache").join(&bundles))
        );

        // Neither set -> no cache home (caller falls back to temp).
        assert_eq!(cache_dir_from(None, None), None);
    }

    #[test]
    fn sha256_hex_known_answer() {
        // sha256("") and sha256("abc"), lowercase hex (matches the node's ETag).
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn cache_key_distinguishes_sanitize_collisions() {
        // `my/repo` and `my_repo` both sanitize to the same string, so the
        // sanitized part collides -- but the hash suffix (sha256 of the FULL
        // unsanitized path) must differ, so the keys do not collide.
        let a = "/latest/0xPUB/repos/my/repo.bundle";
        let b = "/latest/0xPUB/repos/my_repo.bundle";
        assert_eq!(sanitize(a), sanitize(b), "precondition: sanitize collides");
        assert_ne!(cache_key(a), cache_key(b), "cache keys must not collide");
        // A path is stable across calls.
        assert_eq!(cache_key(a), cache_key(a));
    }

    #[test]
    fn write_atomic_uses_name_preserving_temp() {
        // `<key>.bundle` and `<key>.etag` must not share a temp file.
        // with_file_name(<name>.<pid>.tmp) keeps the full name, so their temps
        // differ; a with_extension("tmp") would collapse both to `<key>.tmp`.
        let dir = std::env::temp_dir().join(format!("lcdp-wa-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bundle = dir.join("k.bundle");
        let etag = dir.join("k.etag");
        write_atomic(&bundle, b"bundle-bytes").unwrap();
        write_atomic(&etag, b"etag-bytes").unwrap();
        assert_eq!(std::fs::read(&bundle).unwrap(), b"bundle-bytes");
        assert_eq!(std::fs::read(&etag).unwrap(), b"etag-bytes");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn torn_pair_is_rejected_and_matching_pair_trusted() {
        // A cached bundle is trusted for a conditional (If-None-Match) fetch
        // ONLY when its sha256 equals the cached etag. A torn pair -- OLD bundle
        // bytes + a NEW/foreign etag -- must be rejected so the helper re-fetches
        // UNCONDITIONALLY instead of letting a 304 serve the stale bundle. A
        // truncated bundle is the same: its hash will not match its etag.
        let dir = std::env::temp_dir().join(format!("lcdp-torn-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bundle = dir.join("k.bundle");
        let etag_file = dir.join("k.etag");

        let old_bundle = b"OLD BUNDLE CONTENT".to_vec();

        // --- Torn pair: old bundle on disk, but the etag is for NEW content. ---
        std::fs::write(&bundle, &old_bundle).unwrap();
        std::fs::write(&etag_file, sha256_hex(b"NEW BUNDLE CONTENT")).unwrap();
        assert_eq!(
            validate_cached_pair(&bundle, &etag_file),
            None,
            "torn pair (old bundle + new etag) must be rejected -> re-fetch unconditionally"
        );

        // --- Truncated bundle: etag is for the full content, bytes are short. ---
        std::fs::write(&etag_file, sha256_hex(b"OLD BUNDLE CONTENT, FULL LENGTH")).unwrap();
        std::fs::write(&bundle, b"OLD BUNDLE").unwrap();
        assert_eq!(
            validate_cached_pair(&bundle, &etag_file),
            None,
            "truncated bundle (hash != etag) must be rejected"
        );

        // --- Matching pair: etag == sha256(bundle bytes) -> trust + send INM. ---
        std::fs::write(&bundle, &old_bundle).unwrap();
        std::fs::write(&etag_file, sha256_hex(&old_bundle)).unwrap();
        assert_eq!(
            validate_cached_pair(&bundle, &etag_file),
            Some(sha256_hex(&old_bundle)),
            "matching pair must be trusted and return the etag"
        );

        // --- Empty etag file -> not trustworthy. ---
        std::fs::write(&etag_file, "").unwrap();
        assert_eq!(validate_cached_pair(&bundle, &etag_file), None);

        std::fs::remove_dir_all(&dir).ok();
    }

    // --- 5.6 hardening: validate_refname allowlist --------------------------

    #[test]
    fn validate_refname_accepts_well_formed_heads_and_tags() {
        assert!(validate_refname("refs/heads/master"));
        assert!(validate_refname("refs/heads/main"));
        assert!(validate_refname("refs/heads/feature/x-1.2_3"));
        assert!(validate_refname("refs/tags/v1.0.0"));
        assert!(validate_refname("refs/heads/a"));
        // git-bug CRDT data refs (review-board support over this transport).
        assert!(validate_refname(
            "refs/bugs/0ba8d588caddc777fe9d03c2de18d33d8a78bbd093a678d48335e34e0fec5ef0"
        ));
        assert!(validate_refname(
            "refs/identities/fcb4a229aaa668befe1328de5d501b556e59f32d1915e56d0426f94da15dae90"
        ));
    }

    #[test]
    fn validate_refname_rejects_hostile_or_malformed() {
        // Outside the heads/tags namespace.
        assert!(!validate_refname("refs/remotes/origin/master"));
        assert!(!validate_refname("refs/replace/deadbeef")); // dangerous namespaces stay blocked
        assert!(!validate_refname("refs/notes/commits"));
        assert!(!validate_refname("HEAD"));
        assert!(!validate_refname("refs/heads"));
        assert!(!validate_refname("refs/heads/"));
        // Path traversal.
        assert!(!validate_refname("refs/heads/../../etc/passwd"));
        assert!(!validate_refname("refs/heads/a..b"));
        // Option injection (leading dash).
        assert!(!validate_refname("refs/heads/-rf"));
        // Leading/trailing/double slash.
        assert!(!validate_refname("refs/heads//x"));
        assert!(!validate_refname("refs/heads/x/"));
        assert!(!validate_refname("refs/heads//"));
        // .lock suffix (git reserves it).
        assert!(!validate_refname("refs/heads/x.lock"));
        // Control bytes / non-ASCII / disallowed punctuation.
        assert!(!validate_refname("refs/heads/x\ty"));
        assert!(!validate_refname("refs/heads/x y"));
        assert!(!validate_refname("refs/heads/x~1"));
        assert!(!validate_refname("refs/heads/x:y"));
        // Over-length.
        let long = format!("refs/heads/{}", "a".repeat(300));
        assert!(!validate_refname(&long));
    }

    // --- Additive-push integration tests (real git, no node) -----------------
    //
    // These build actual git repos in temp dirs and exercise the union logic of
    // `build_additive_bundle` directly, proving a second single-branch push does
    // NOT drop the branches that were already on the remote (the bug).

    /// Run git in `dir`, asserting success.
    fn git_in(dir: &std::path::Path, args: &[&str]) -> String {
        let mut a = vec!["-C", dir.to_str().unwrap()];
        a.extend_from_slice(args);
        // git_clean so an ambient GIT_DIR (the regression test sets one) cannot
        // hijack `-C <dir>` and make these run against the wrong repo.
        git_clean(&a).unwrap_or_else(|e| panic!("git {args:?} in {}: {e}", dir.display()))
    }

    /// Commit an empty change onto `branch`, creating it if needed; returns sha.
    fn commit_on(dir: &std::path::Path, branch: &str, msg: &str) -> String {
        git_in(dir, &["checkout", "-q", "-B", branch]);
        git_in(dir, &["commit", "-q", "--allow-empty", "-m", msg]);
        git_in(dir, &["rev-parse", "HEAD"]).trim().to_string()
    }

    /// Ref -> sha map advertised by a bundle.
    fn bundle_refs(bundle: &std::path::Path) -> std::collections::BTreeMap<String, String> {
        bundle_list_heads(bundle.to_str().unwrap())
            .unwrap()
            .into_iter()
            .filter_map(|l| l.split_once(' ').map(|(s, r)| (r.to_string(), s.to_string())))
            .collect()
    }

    /// A scratch dir under temp_dir, removed on drop.
    struct Scratch {
        dir: PathBuf,
    }
    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!(
                "lcdp-test-{}-{}-{tag}",
                std::process::id(),
                next_nonce()
            ));
            std::fs::remove_dir_all(&dir).ok();
            std::fs::create_dir_all(&dir).unwrap();
            Scratch {
                dir,
            }
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    fn spec(src: Option<&str>, dst: &str) -> PushSpec {
        PushSpec {
            src: src.map(str::to_string),
            dst: dst.to_string(),
        }
    }

    #[test]
    fn additive_push_preserves_unchanged_branches() {
        // Set up a LOCAL repo with three branches. `build_additive_bundle` takes
        // the local git dir explicitly (no CWD dependency -> parallel-safe), so
        // resolve it from the scratch repo and pass it in.
        let local = Scratch::new("local");
        git_in(&local.dir, &["init", "-q"]);
        git_in(&local.dir, &["config", "user.email", "t@e.st"]);
        git_in(&local.dir, &["config", "user.name", "t"]);
        commit_on(&local.dir, "master", "m1");
        commit_on(&local.dir, "A", "a1");
        commit_on(&local.dir, "B", "b1");
        let local_dir = git_in(&local.dir, &["rev-parse", "--absolute-git-dir"]).trim().to_string();

        let path = "repos/additive-test.bundle";

        // FIRST push: master + A (no existing remote bundle).
        let b1 = build_additive_bundle(
            path,
            &local_dir,
            None,
            &[
                spec(Some("refs/heads/master"), "refs/heads/master"),
                spec(Some("refs/heads/A"), "refs/heads/A"),
            ],
        )
        .expect("first push bundle");
        let refs1 = bundle_refs(b1.path());
        assert!(refs1.contains_key("refs/heads/master"), "master after first push");
        assert!(refs1.contains_key("refs/heads/A"), "A after first push");
        assert!(!refs1.contains_key("refs/heads/B"), "B not yet pushed");

        // SECOND push: only B, against the existing remote (b1). The BUG would
        // drop master + A here; the fix must PRESERVE them.
        let b2 = build_additive_bundle(
            path,
            &local_dir,
            Some(b1.path()),
            &[spec(Some("refs/heads/B"), "refs/heads/B")],
        )
        .expect("second push bundle");
        let refs2 = bundle_refs(b2.path());
        assert!(refs2.contains_key("refs/heads/master"), "master PRESERVED after pushing B");
        assert!(refs2.contains_key("refs/heads/A"), "A PRESERVED after pushing B");
        assert!(refs2.contains_key("refs/heads/B"), "B added");
        assert_eq!(refs2.len(), 3, "union has all three branches");

        // DELETE push: remove A, against the 3-branch remote (b2).
        let b3 =
            build_additive_bundle(path, &local_dir, Some(b2.path()), &[spec(None, "refs/heads/A")])
                .expect("delete push bundle");
        let refs3 = bundle_refs(b3.path());
        assert!(!refs3.contains_key("refs/heads/A"), "A deleted");
        assert!(refs3.contains_key("refs/heads/master"), "master survives delete");
        assert!(refs3.contains_key("refs/heads/B"), "B survives delete");
        assert_eq!(refs3.len(), 2, "two branches remain after delete");
    }

    #[test]
    fn additive_push_fails_closed_on_corrupt_existing_bundle() {
        // S5: the push-path unbundle of the EXISTING remote bundle must be
        // fail-closed.  A corrupt/garbage existing bundle must make the union
        // build ERROR (via bundle_verify), not silently produce a partial union
        // or wedge -- so a hostile/torn published base can't poison a push.
        let local = Scratch::new("local-corrupt");
        git_in(&local.dir, &["init", "-q"]);
        git_in(&local.dir, &["config", "user.email", "t@e.st"]);
        git_in(&local.dir, &["config", "user.name", "t"]);
        commit_on(&local.dir, "master", "m1");
        let local_dir = git_in(&local.dir, &["rev-parse", "--absolute-git-dir"]).trim().to_string();

        // A file that is NOT a valid git bundle.
        let bogus = Scratch::new("bogus");
        let bogus_bundle = bogus.dir.join("corrupt.bundle");
        std::fs::write(&bogus_bundle, b"# v2 git bundle\nnot a real bundle at all\n").unwrap();

        // bundle_verify itself must reject it (the gate temp_unbundle_existing now
        // calls before touching the bundle).
        assert!(
            bundle_verify(bogus_bundle.to_str().unwrap()).is_err(),
            "a corrupt bundle must fail bundle_verify"
        );

        // And the whole additive build must fail closed when handed it as the
        // existing remote, rather than building a partial/empty union.
        let result = build_additive_bundle(
            "repos/corrupt-test.bundle",
            &local_dir,
            Some(&bogus_bundle),
            &[spec(Some("refs/heads/master"), "refs/heads/master")],
        );
        assert!(
            result.is_err(),
            "additive push against a corrupt existing bundle must fail closed"
        );
    }

    #[test]
    fn additive_push_ignores_ambient_git_dir() {
        // REGRESSION: git invokes the remote helper with GIT_DIR set to the
        // USER's repo.  An explicit GIT_DIR OVERRIDES `git -C <temp>`, so without
        // `git_clean` the `bundle create --all` would bundle the USER's entire
        // ref set (every branch/tag/remote) instead of the temp-repo union.  Set
        // a DECOY GIT_DIR full of extra refs and assert NONE leak into the union.
        let decoy = Scratch::new("decoy");
        git_in(&decoy.dir, &["init", "-q"]);
        git_in(&decoy.dir, &["config", "user.email", "t@e.st"]);
        git_in(&decoy.dir, &["config", "user.name", "t"]);
        commit_on(&decoy.dir, "decoy-leak-1", "d1");
        commit_on(&decoy.dir, "decoy-leak-2", "d2");
        let decoy_git_dir =
            git_in(&decoy.dir, &["rev-parse", "--absolute-git-dir"]).trim().to_string();

        let local = Scratch::new("local2");
        git_in(&local.dir, &["init", "-q"]);
        git_in(&local.dir, &["config", "user.email", "t@e.st"]);
        git_in(&local.dir, &["config", "user.name", "t"]);
        commit_on(&local.dir, "master", "m1");
        let local_dir = git_in(&local.dir, &["rev-parse", "--absolute-git-dir"]).trim().to_string();

        // Mimic git's invocation environment: GIT_DIR points at the decoy repo.
        std::env::set_var("GIT_DIR", &decoy_git_dir);
        let result = build_additive_bundle(
            "repos/git-dir-test.bundle",
            &local_dir,
            None,
            &[spec(Some("refs/heads/master"), "refs/heads/master")],
        );
        std::env::remove_var("GIT_DIR");

        let bundle = result.expect("build union under ambient GIT_DIR");
        let refs = bundle_refs(bundle.path());
        assert_eq!(refs.len(), 1, "union has exactly the pushed ref, not the decoy's refs");
        assert!(refs.contains_key("refs/heads/master"), "pushed master present");
        assert!(
            !refs.keys().any(|r| r.contains("decoy-leak")),
            "decoy GIT_DIR refs MUST NOT leak into the union: {refs:?}"
        );
    }

    #[test]
    fn push_lock_serializes_same_path() {
        // S6: the per-path advisory lock must SERIALIZE same-host pushes -- a
        // second acquire of the same path blocks until the first is dropped.  A
        // unique path means this test owns its own lock file (in the real cache
        // or temp dir), so it never mutates process-global env (which would race
        // git's HOME-driven config in the parallel additive-push tests).
        let path = format!("repos/lock-test-{}-{}.bundle", std::process::id(), next_nonce());

        use std::sync::mpsc;
        let (holding_tx, holding_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let path_for_thread = path.clone();
        let holder = std::thread::spawn(move || {
            let lock = PushLock::acquire(&path_for_thread).expect("first acquire");
            holding_tx.send(()).unwrap(); // signal: lock held
            release_rx.recv().unwrap(); // hold until told to drop
            drop(lock);
        });

        holding_rx.recv().unwrap(); // wait until the holder has the lock

        // A second acquire must BLOCK while the holder keeps the lock. Prove it by
        // showing it does not complete on its own thread until we release.
        let path_for_second = path.clone();
        let (acquired_tx, acquired_rx) = mpsc::channel::<()>();
        let second = std::thread::spawn(move || {
            let _lock = PushLock::acquire(&path_for_second).expect("second acquire");
            acquired_tx.send(()).unwrap();
        });

        // While the holder still owns it, the second acquire must NOT have fired.
        assert!(
            acquired_rx.recv_timeout(std::time::Duration::from_millis(300)).is_err(),
            "second acquire must block while the first holds the lock"
        );

        // Release the holder; now the second acquire must succeed promptly.
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        assert!(
            acquired_rx.recv_timeout(std::time::Duration::from_secs(5)).is_ok(),
            "second acquire must proceed once the first lock is released"
        );
        second.join().unwrap();
    }
}
