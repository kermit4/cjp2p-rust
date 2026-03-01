
debug:
	cargo build

release:
	cargo build --release

check:
	cargo check 

demo: release
	timeout 4  ./target/release/cjp2p-rust                                         562b168a64967fd64687664b987dd1c50c36d1532449bb4c385d683538c0bf03 || true
	./target/release/cjp2p-rust $$(cat                                                shared/562b168a64967fd64687664b987dd1c50c36d1532449bb4c385d683538c0bf03 )

pretty: check
	rustfmt src/main.rs

all: check release debug
