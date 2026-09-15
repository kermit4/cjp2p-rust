.PHONY: build release tui tui-release check fmt clippy install clean

# ctl is a standalone cargo project (its own Cargo.lock / target/), NOT a
# member of the top-level cjp2p workspace. That is why `cargo build -p cjp2p-ctl
# --features tui` from the repo root fails with "cannot specify features for
# packages outside of workspace" -- feature-bearing builds MUST run from here.
# Both bins (cjp2pctl, git-remote-lcdp) come out of this one package.

BINS    = cjp2pctl git-remote-lcdp
# Install to BOTH dirs: ~/.cargo/bin shadows ~/.local/bin on PATH, so a stale
# copy in either wins. Override with `make install BINDIRS="/usr/local/bin"`.
BINDIRS ?= $(HOME)/.local/bin $(HOME)/.cargo/bin

build:
	cargo build

release:
	cargo build --release

# The TUI needs the `tui` feature (ratatui + crossterm).
tui:
	cargo build --features tui

tui-release:
	cargo build --release --features tui

check:
	cargo check --features tui

fmt:
	cargo fmt

clippy:
	cargo clippy --features tui

# Build the release TUI binaries and install cjp2pctl + git-remote-lcdp into
# every dir on BINDIRS. Run `hash -r` in your shell afterward to drop cached
# paths (a recipe subshell cannot do it for the parent).
install: tui-release
	@for d in $(BINDIRS); do \
		install -d "$$d"; \
		for b in $(BINS); do \
			install -m 755 target/release/$$b "$$d/$$b"; \
			echo "installed $$b -> $$d/$$b"; \
		done; \
	done

clean:
	cargo clean
