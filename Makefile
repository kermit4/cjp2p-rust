SHELL = /bin/bash -ue

default: debug release

chat5: src/chat5.html Makefile
	mkdir -p cjp2p/public
	sha256sum src/chat5.html |awk '{print $$2,"cjp2p/public/"$$1;print "http://localhost:24255/"$$1"?0xeff7da60005c3f1ea5bdc5cbc4cf7511fe36199a" >"/dev/stderr" }'|xargs cp 

debug: target/debug/cjp2p
target/debug/cjp2p: Makefile Cargo.toml src/*.rs 
	BUILD_VERSION="debug: `git log --pretty=format:"Rust %ad %h %s" -1`" cargo build
	rm -f target/*/libcjp

release: target/release/cjp2p
target/release/cjp2p:	Makefile Cargo.toml src/*.rs 
	BUILD_VERSION="release `git log --pretty=format:"Rust %ad %h %s" -1`" cargo build --release
	rm -f target/*/libcjp

check: Makefile Cargo.toml src/*.rs 
	BUILD_VERSION="check `git log --pretty=format:"Rust %ad %h %s" -1`" cargo check 

pretty: debug
	cargo fmt --  --config skip_macro_invocations='["*"]' --config match_arm_blocks=false

APK = android/app/build/outputs/apk/debug/app-debug.apk
APK_SRCS = $(wildcard src/*.rs) Cargo.toml build_android.sh \
           android/app/src/main/AndroidManifest.xml \
           $(wildcard android/app/src/main/java/com/cjp2p/*.java) \
           android/app/build.gradle \
           $(wildcard cjp2p/public/*.html)

apk: $(APK)
$(APK): $(APK_SRCS)
	./build_android.sh

all: check release debug apk
