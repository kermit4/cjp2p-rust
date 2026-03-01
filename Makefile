SHELL = /bin/bash -ue

debug:
	cargo build

release:
	cargo build --release

check:
	cargo check 

demo: release
	timeout 4  ./target/release/libcjp                                         562b168a64967fd64687664b987dd1c50c36d1532449bb4c385d683538c0bf03 || true
	./target/release/libcjp $$(cat                                                shared/562b168a64967fd64687664b987dd1c50c36d1532449bb4c385d683538c0bf03 )

pretty: check
	rustfmt src/main.rs

all: check release debug

.PHONY: crate

crate: 
	cargo publish --dry-run
