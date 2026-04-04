SHELL = /bin/bash -ue

debug: target/debug/cjp2p
target/debug/cjp2p: Makefile src/main.rs Cargo.toml
	BUILD_VERSION=`git log --pretty=format:"Rust %ad %h %s" -1` cargo build
	rm -f target/*/libcjp

release: target/release/cjp2p
target/release/cjp2p:	Makefile src/main.rs Cargo.toml
	BUILD_VERSION=`git log --pretty=format:"Rust %ad %h %s" -1` cargo build --release
	rm -f target/*/libcjp

check: Makefile src/main.rs Cargo.toml
	BUILD_VERSION=`git log --pretty=format:"Rust %ad %h %s" -1` cargo check 

demo: release
	timeout 4  ./target/release/cjp2p                                         562b168a64967fd64687664b987dd1c50c36d1532449bb4c385d683538c0bf03 || true
	./target/release/cjp2p $$(cat                                                shared/562b168a64967fd64687664b987dd1c50c36d1532449bb4c385d683538c0bf03 )

pretty: debug
	cargo fmt --  --config skip_macro_invocations='["*"]' --config match_arm_blocks=false

all: check release debug
