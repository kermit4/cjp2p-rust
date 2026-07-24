SHELL = /bin/bash -ue


export BUILD_VERSION=$@ $(shell TZ= git log --pretty=format:"Rust %ad %h %d %s" -1)
export GIT_HASH=$(shell git log --pretty=format:"%h" -1)

default: check debug release bundle

bundle: cjp2p/origin/cjp2p.bundle

cjp2p/origin/cjp2p.bundle: .git/logs/refs/heads/master
	mkdir -p cjp2p/origin
	git bundle create --quiet cjp2p/origin/cjp2p.bundle_ master --tags
	mv cjp2p/origin/cjp2p.bundle_ cjp2p/origin/cjp2p.bundle

# your IP address can't do this to my server so this is a NOOP for you
pins: bundle
	if [[ ` hostname ` == t470s.azai.net ]];then \
	find cjp2p/origin/ -not -name '.*' -type f -not -path '*/.*' -exec cat {} \;|wc -c  ;\
	for _x in . .;do find cjp2p/origin/ -not -name '.*' -type f -not -path '*/.*' -printf "%P\n"|xargs -P 0 -i curl    -Ss http://azai.net:24255/latest/0xe13a614dff88de239a986bea20ca129c3dc77bb727fac18f2f092eed27cfb3fb/{}  |wc -c;sleep .3;done ;fi

debug: target/debug/cjp2p bundle
target/debug/cjp2p: Makefile Cargo.toml src/*.rs  src/bin/*.rs   src/favicon.png 
	cargo build
	rm -f target/*/libcjp

release: target/release/cjp2p bundle
target/release/cjp2p:	Makefile Cargo.toml src/*.rs  src/bin/*.rs   src/favicon.png 
	cargo build --release
	rm -f target/*/libcjp
	strip $@



check: Makefile Cargo.toml src/*.rs src/bin/*.rs src/favicon.png
	cargo check 

# Format a single file (used by editors / the Claude PostToolUse hook):
#   make pretty-file FILE=path/to/x.rs
.PHONY: pretty-file
pretty-file:
	rustup run nightly rustfmt --edition 2021 $(FMT_FLAGS) "$(FILE)"

# Fail if anything is unformatted (CI / pre-commit backstop).
.PHONY: pretty-check
pretty-check:
	cargo fmt --check -- $(FMT_FLAGS)

APK = android/app/build/outputs/apk/debug/app-debug.apk
APK_SRCS = $(wildcard src/*.rs) Cargo.toml build_android.sh \
           android/app/src/main/AndroidManifest.xml \
           $(wildcard android/app/src/main/java/com/cjp2p/*.java) \
           android/app/build.gradle \
           $(wildcard cjp2p/public/*.html) \
		   src/bin/cjp2p.rs

# this one uses a status page that the links open in native browser, though with a built in file share function, unlike all the Tauri stuff below that is a single app (though probably mulitple processes)
apk: $(APK)
$(APK): $(APK_SRCS) icons
	./build_android.sh

all: check release debug apk

pull: Makefile
	wget  -q http://localhost:24255/latest/0xe13a614dff88de239a986bea20ca129c3dc77bb727fac18f2f092eed27cfb3fb/cjp2p.bundle -O bundle
	git pull bundle master

# -- publish a feature branch over lcdp for review ----------------------------
# cjp2p is local-first: you always talk to YOUR node at 127.0.0.1:24255, which
# serves your published bundle to peers. This hands a bundle of your branch to
# your running node (over local HTTP, so it works no matter where the node's
# working dir is -- e.g. a systemd system-user node). Reviewers then git-fetch
# it from /latest/0x<yourpub>/<NAME>.bundle.
# Override:  make publish BRANCH=feat/x NAME=my-thing
# (If instead you run the node FROM this dir, kermit's `bundle` target / a direct
#  write into cjp2p/origin/ also works -- same result, no HTTP.)
BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD)
NAME   ?= $(shell git rev-parse --abbrev-ref HEAD | tr '/() ' '-' | tr -s '-')
.PHONY: publish

ctl/target/debug/cjp2pctl:
	$(MAKE) -C ctl

publish: ctl/target/debug/cjp2pctl
	git bundle create --quiet /tmp/$(NAME).bundle "$(BRANCH)" --tags
	ctl/target/debug/cjp2pctl publish /tmp/$(NAME).bundle --name $(NAME).bundle
	@rm -f /tmp/$(NAME).bundle
	@echo "reviewer: wget http://127.0.0.1:24255/latest/`cjp2pctl status|awk '/^identity/{print $$NF}'`/$(NAME).bundle && git fetch $(NAME).bundle '$(BRANCH):$(BRANCH)' && git checkout $(NAME).bundle && git rebase master && git diff -w master"

# -- Tauri targets (Android APK) ----------------------------------------------
#
# First-time setup:
#   make tauri-cli            # installs cargo-tauri v2
#   run build_android.sh once to set up Android SDK/NDK
#   make tauri-android-init   # run once to scaffold Android project
#
# Then just: make tauri-apk   or   make tauri-apk-release

ANDROID_SDK_ROOT ?= $(HOME)/Android/Sdk
CARGO_TAURI = $(HOME)/.cargo/bin/cargo-tauri
TAURI_APP_DIR = tauri-app

.PHONY: tauri-cli icons tauri-android-init tauri-apk ctl/target/debug/cjp2pctl

$(CARGO_TAURI):
	cargo install tauri-cli --version "^2" --locked

tauri-cli: $(CARGO_TAURI)

src/favicon.png: gen-icons.py
	[[ -e $@ ]] || which rsvg-convert ||   pkg install librsvg || sudo apt install librsvg2-bin
	[[ -e $@ ]] || ./gen-icons.py

icons:  src/favicon.png

# Run once after SDK is set up (build_android.sh does the SDK setup).
tauri-android-init: $(CARGO_TAURI)
	cd $(TAURI_APP_DIR) && ANDROID_SDK_ROOT=$(ANDROID_SDK_ROOT) cargo tauri android init

tauri-apk: $(CARGO_TAURI) icons
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

tauri-apk-release: $(CARGO_TAURI) icons $(KEYSTORE_PROPS)
	cd $(TAURI_APP_DIR) && ANDROID_SDK_ROOT=$(ANDROID_SDK_ROOT) cargo tauri android build --target aarch64
