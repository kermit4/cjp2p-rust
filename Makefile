SHELL = /bin/bash -ue

debug: target/debug/cjp2p
target/debug/cjp2p: Makefile src/main.rs Cargo.toml
	cargo build

release: target/release/cjp2p
target/release/cjp2p:	Makefile src/main.rs Cargo.toml
	cargo build --release

check: Makefile src/main.rs Cargo.toml
	cargo check 

demo: release
	timeout 4  ./target/release/cjp2p                                         562b168a64967fd64687664b987dd1c50c36d1532449bb4c385d683538c0bf03 || true
	./target/release/cjp2p $$(cat                                                shared/562b168a64967fd64687664b987dd1c50c36d1532449bb4c385d683538c0bf03 )

pretty: debug
	cargo fmt --  --config skip_macro_invocations='["*"]' --config match_arm_blocks=false

all: check release debug

.PHONY: crate

crate: 
	cargo publish
