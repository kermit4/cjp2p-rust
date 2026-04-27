SHELL = /bin/bash -ue

default: debug release

pins: 
	for a in $$(ls cjp2p/origin/);do  curl    -Ss http://azai.net:24255/latest/0xe13a614dff88de239a986bea20ca129c3dc77bb727fac18f2f092eed27cfb3fb/$$a;done > /dev/null

debug: target/debug/cjp2p pins
target/debug/cjp2p: Makefile Cargo.toml src/*.rs  src/bin/*.rs
	BUILD_VERSION="debug: `git log --pretty=format:"Rust %ad %h %s" -1`" cargo build
	rm -f target/*/libcjp

release: target/release/cjp2p pins
target/release/cjp2p:	Makefile Cargo.toml src/*.rs  src/bin/*.rs
	BUILD_VERSION="release `git log --pretty=format:"Rust %ad %h %s" -1`" cargo build --release
	rm -f target/*/libcjp

check: Makefile Cargo.toml src/*.rs src/bin/*.rs
	BUILD_VERSION="check `git log --pretty=format:"Rust %ad %h %s" -1`" cargo check 

pretty: debug
	cargo fmt --  --config skip_macro_invocations='["*"]' --config match_arm_blocks=false

APK = android/app/build/outputs/apk/debug/app-debug.apk
APK_SRCS = $(wildcard src/*.rs) Cargo.toml build_android.sh \
           android/app/src/main/AndroidManifest.xml \
           $(wildcard android/app/src/main/java/com/cjp2p/*.java) \
           android/app/build.gradle \
           $(wildcard cjp2p/public/*.html) \
		   src/bin/cjp2p.rs

apk: $(APK)
$(APK): $(APK_SRCS)
	./build_android.sh

all: check release debug apk
