SHELL = /bin/bash -ue

default: debug release

cjp2p/origin/cjp2p.bundle: .git/logs/refs/heads/master
	git bundle create --quiet cjp2p/origin/cjp2p.bundle_ master
	mv cjp2p/origin/cjp2p.bundle_ cjp2p/origin/cjp2p.bundle

# "your IP address can't do this to my server"
pins: cjp2p/origin/cjp2p.bundle
	find cjp2p/origin/ -not -name '.*' -type f -not -path '*/.*' -exec cat {} \;|wc -c
	for _x in . .;do find cjp2p/origin/ -not -name '.*' -type f -not -path '*/.*' -printf "%P\n"|xargs -P 0 -i curl    -Ss http://azai.net:24255/latest/0xe13a614dff88de239a986bea20ca129c3dc77bb727fac18f2f092eed27cfb3fb/{}  |wc -c;sleep .3;done 

debug: target/debug/cjp2p
target/debug/cjp2p: Makefile Cargo.toml src/*.rs  src/bin/*.rs
	BUILD_VERSION="debug: `git log --pretty=format:"Rust %ad %h %s" -1`" cargo build
	rm -f target/*/libcjp

release: target/release/cjp2p
target/release/cjp2p:	Makefile Cargo.toml src/*.rs  src/bin/*.rs
	BUILD_VERSION="release `git log --pretty=format:"Rust %ad %h %s" -1`" cargo build --release
	rm -f target/*/libcjp

check: Makefile Cargo.toml src/*.rs src/bin/*.rs
	BUILD_VERSION="check `git log --pretty=format:"Rust %ad %h %s" -1`" cargo check 

pretty: check 
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

pull: Makefile
	rm -f cjp2p.bundle
	curl -Ss http://localhost:24255/latest/0xe13a614dff88de239a986bea20ca129c3dc77bb727fac18f2f092eed27cfb3fb/cjp2p.bundle > /dev/null
	sleep .3
	wget  -q http://localhost:24255/latest/0xe13a614dff88de239a986bea20ca129c3dc77bb727fac18f2f092eed27cfb3fb/cjp2p.bundle
	git pull cjp2p.bundle master
