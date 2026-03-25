SHELL = /bin/bash -ue

debug: Makefile
	BUILD_VERSION=`git log --pretty=format:"Rust %ad %h %s" -1` cargo build

release: Makefile
	BUILD_VERSION=`git log --pretty=format:"Rust %ad %h %s" -1` cargo build --release

check: Makefile
	cargo check 

demo: release
	timeout 4  ./target/release/libcjp                                         562b168a64967fd64687664b987dd1c50c36d1532449bb4c385d683538c0bf03 || true
	./target/release/libcjp $$(cat                                                shared/562b168a64967fd64687664b987dd1c50c36d1532449bb4c385d683538c0bf03 )

pretty: check
	cargo fmt --  --config skip_macro_invocations='["*"]' --config match_arm_blocks=false

all: check release debug

.PHONY: crate

crate: 
	cargo publish
