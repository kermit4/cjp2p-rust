SHELL = /bin/bash -ue


export BUILD_VERSION=$@ $(shell TZ= git log --pretty=format:"Rust %ad %h %s" -1)

default: check debug release bundle

bundle: cjp2p/origin/cjp2p.bundle

cjp2p/origin/cjp2p.bundle: .git/logs/refs/heads/master
	mkdir -p cjp2p/origin
	git bundle create --quiet cjp2p/origin/cjp2p.bundle_ master
	mv cjp2p/origin/cjp2p.bundle_ cjp2p/origin/cjp2p.bundle

# your IP address can't do this to my server so this is a NOOP for you
pins: bundle
	if [[ ` hostname ` == t470s.azai.net ]];then \
	find cjp2p/origin/ -not -name '.*' -type f -not -path '*/.*' -exec cat {} \;|wc -c  ;\
	for _x in . .;do find cjp2p/origin/ -not -name '.*' -type f -not -path '*/.*' -printf "%P\n"|xargs -P 0 -i curl    -Ss http://azai.net:24255/latest/0xe13a614dff88de239a986bea20ca129c3dc77bb727fac18f2f092eed27cfb3fb/{}  |wc -c;sleep .3;done ;fi

debug: target/debug/cjp2p bundle
target/debug/cjp2p: Makefile Cargo.toml src/*.rs  src/bin/*.rs
	cargo build
	rm -f target/*/libcjp

release: target/release/cjp2p bundle
target/release/cjp2p:	Makefile Cargo.toml src/*.rs  src/bin/*.rs
	RUSTFLAGS="-C target-cpu=native"  cargo build --release
	rm -f target/*/libcjp

check: Makefile Cargo.toml src/*.rs src/bin/*.rs
	cargo check 

pretty: check 
	cargo fmt --  --config skip_macro_invocations='["*"]' --config match_arm_blocks=false

APK = android/app/build/outputs/apk/debug/app-debug.apk
APK_SRCS = $(wildcard src/*.rs) Cargo.toml build_android.sh \
           android/app/src/main/AndroidManifest.xml \
           $(wildcard android/app/src/main/java/com/cjp2p/*.java) \
           android/app/build.gradle \
           $(wildcard cjp2p/public/*.html) \
		   src/bin/cjp2p.rs

# this one uses a status page that the links open in native browser, though with a built in file share function, unlike all the Tauri stuff below that is a single app (though probably mulitple processes)
apk: $(APK)
$(APK): $(APK_SRCS)
	./build_android.sh

all: check release debug apk

pull: Makefile
	wget  -q http://localhost:24255/latest/0xe13a614dff88de239a986bea20ca129c3dc77bb727fac18f2f092eed27cfb3fb/cjp2p.bundle -O cjp2p.bundle
	git pull cjp2p.bundle master

# -- Tauri targets (Android APK + Linux .deb) ---------------------------------
#
# Tauri wraps cjp2p as a native app: pong.html is the WebView frontend,
# cjp2p runs in a background thread serving ws://localhost:24255/wt.
#
# First-time setup:
#   sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
#   make tauri-cli        # installs cargo-tauri v2
#   make tauri-apk needs Android SDK; run build_android.sh once first (sets up SDK/NDK).
#   make tauri-android-init   # run once to scaffold Android project
#
# Then just: make tauri-deb   or   make tauri-apk

ANDROID_SDK_ROOT ?= $(HOME)/Android/Sdk
CARGO_TAURI = $(HOME)/.cargo/bin/cargo-tauri
TAURI_APP_DIR = tauri-app

.PHONY: tauri-cli tauri-icons tauri-android-init tauri-deb tauri-apk

$(CARGO_TAURI):
	cargo install tauri-cli --version "^2" --locked

tauri-cli: $(CARGO_TAURI)

$(TAURI_APP_DIR)/src-tauri/icons/128x128.png: $(TAURI_APP_DIR)/gen-icons.py
	cd $(TAURI_APP_DIR)/src-tauri && python3 ../gen-icons.py

tauri-icons: $(TAURI_APP_DIR)/src-tauri/icons/128x128.png

tauri-deb: $(CARGO_TAURI) tauri-icons
	cd $(TAURI_APP_DIR) && cargo tauri build --bundles deb

# Run once after SDK is set up (build_android.sh does the SDK setup).
tauri-android-init: $(CARGO_TAURI)
	cd $(TAURI_APP_DIR) && ANDROID_SDK_ROOT=$(ANDROID_SDK_ROOT) cargo tauri android init

tauri-apk: $(CARGO_TAURI) tauri-icons
	cd $(TAURI_APP_DIR) && ANDROID_SDK_ROOT=$(ANDROID_SDK_ROOT) cargo tauri android build --target aarch64 --debug

# Release (signed, smaller) APK.  Run once to create the keystore:  make tauri-keystore
# The keystore and key.properties are gitignored -- keep cjp2p.jks somewhere safe.
KEYSTORE      = $(shell pwd)/$(TAURI_APP_DIR)/cjp2p.jks
KEYSTORE_PROPS = $(TAURI_APP_DIR)/src-tauri/gen/android/key.properties

.PHONY: tauri-keystore tauri-apk-release

tauri-keystore: $(KEYSTORE)
$(KEYSTORE):
	keytool -genkey -v -keystore $(KEYSTORE) -alias cjp2p \
		-keyalg RSA -keysize 2048 -validity 10000 \
		-storepass cjp2pdev -keypass cjp2pdev \
		-dname "CN=cjp2p,OU=Dev,O=cjp2p,L=Dev,ST=Dev,C=US"
	printf 'storeFile=%s\nstorePassword=cjp2pdev\nkeyAlias=cjp2p\nkeyPassword=cjp2pdev\n' \
		"$(KEYSTORE)" > $(KEYSTORE_PROPS)
	@echo "Keystore created. Back up $(KEYSTORE) -- losing it means you cannot update the app."

tauri-apk-release: $(CARGO_TAURI) tauri-icons $(KEYSTORE_PROPS)
	cd $(TAURI_APP_DIR) && ANDROID_SDK_ROOT=$(ANDROID_SDK_ROOT) cargo tauri android build --target aarch64
