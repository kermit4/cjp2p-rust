
debug:
	cargo build

release:
	cargo build --release

check:
	cargo check

all: check release debug
