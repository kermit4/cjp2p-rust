//! Phase 2: a git remote helper so `git clone lcdp://<pub>/<name>` and
//! `git pull` work transparently. Not yet implemented — until then the
//! `cjp2pctl clone` / `cjp2pctl pull` subcommands provide the same capability
//! over the proven bundle data path.
//!
//! When implemented, this advertises the read path first (capabilities: `fetch`;
//! `list` -> fetch+verify bundle, `git bundle list-heads` -> `<sha> <ref>` lines;
//! `fetch` -> unbundle into the object store). `import`/`export` come later.

fn main() {
    eprintln!(
        "git-remote-lcdp: not yet implemented (Phase 2).\n\
         For now use:  cjp2pctl clone lcdp://<pub>/<name> [dest]\n\
                       cjp2pctl pull [dir]"
    );
    std::process::exit(1);
}
