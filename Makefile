SHELL = /bin/bash -ue

debug: target/debug/cjp2p
target/debug/cjp2p: Makefile Cargo.toml src/*.rs src/*.html
	touch $@
	BUILD_VERSION=`git log --pretty=format:"Rust %ad %h %s" -1` cargo build
	rm -f target/*/libcjp

release: target/release/cjp2p
target/release/cjp2p:	Makefile Cargo.toml src/*.rs src/*.html
	touch $@
	BUILD_VERSION=`git log --pretty=format:"Rust %ad %h %s" -1` cargo build --release
	rm -f target/*/libcjp

check: Makefile Cargo.toml src/*.rs src/*.html
	touch src/main.html
	BUILD_VERSION=`git log --pretty=format:"Rust %ad %h %s" -1` cargo check 

pretty: debug
	cargo fmt --  --config skip_macro_invocations='["*"]' --config match_arm_blocks=false

all: check release debug
