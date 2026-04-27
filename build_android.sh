#!/bin/bash
# Builds cjp2p as an Android APK.
#
# SYSTEM PREREQUISITES (must be installed manually before first run):
#
#   Java 17+:
#     Ubuntu/Debian:  sudo apt install openjdk-17-jdk
#     Fedora/RHEL:    sudo dnf install java-17-openjdk-devel
#     Arch:           sudo pacman -S jdk17-openjdk
#   curl:
#     Ubuntu/Debian:  sudo apt install curl
#   unzip:
#     Ubuntu/Debian:  sudo apt install unzip
#   Rust + cargo (https://rustup.rs):
#     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
#
# Everything else (Android SDK, NDK, Gradle, Rust Android target) is
# downloaded automatically by this script on first run.

set -e

echo "=== Checking prerequisites ==="
fail=0
if ! command -v java &>/dev/null; then
    echo "ERROR: java not found. Install Java 17+:  sudo apt install openjdk-17-jdk"
    fail=1
else
    jver=$(java -version 2>&1 | awk -F'"' '/version/{print $2}' | cut -d. -f1)
    [ "$jver" = "1" ] && jver=$(java -version 2>&1 | awk -F'"' '/version/{print $2}' | cut -d. -f2)
    if [ "${jver:-0}" -lt 17 ] 2>/dev/null; then
        echo "ERROR: Java 17+ required, found version $jver.  sudo apt install openjdk-17-jdk"
        fail=1
    else
        echo "java: ok (version $jver)"
    fi
fi
for cmd in curl unzip cargo; do
    if ! command -v $cmd &>/dev/null; then
        case $cmd in
            curl|unzip) echo "ERROR: $cmd not found.  sudo apt install $cmd" ;;
            cargo) echo "ERROR: cargo not found. Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" ;;
        esac
        fail=1
    else
        echo "$cmd: ok"
    fi
done
[ $fail -ne 0 ] && exit 1

ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}"
NDK_VERSION="27.2.12479018"
API_LEVEL="24"
RUST_TARGET="aarch64-linux-android"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
ANDROID_DIR="$PROJECT_DIR/android"
SDKMANAGER="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"

echo "=== Step 1: Android command-line tools ==="
if [ ! -f "$SDKMANAGER" ]; then
    echo "Downloading Android command-line tools..."
    mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools"
    cd /tmp
    curl -s -o cmdline-tools.zip \
        "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
    unzip -q cmdline-tools.zip -d cmdline-tools-tmp
    mv cmdline-tools-tmp/cmdline-tools "$ANDROID_SDK_ROOT/cmdline-tools/latest"
    rm -rf cmdline-tools-tmp cmdline-tools.zip
    cd "$PROJECT_DIR"
    echo "Done."
else
    echo "Already installed."
fi

echo "=== Step 2: NDK and build tools ==="
yes | "$SDKMANAGER" --licenses > /dev/null 2>&1 || true
"$SDKMANAGER" "ndk;$NDK_VERSION" "build-tools;35.0.0" "platforms;android-35"

NDK_HOME="$ANDROID_SDK_ROOT/ndk/$NDK_VERSION"
TOOLCHAIN="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
CLANG="$TOOLCHAIN/bin/${RUST_TARGET}${API_LEVEL}-clang"

echo "=== Step 3: Rust Android target ==="
rustup target add "$RUST_TARGET"

# Write cargo config for this cross-compilation
mkdir -p "$PROJECT_DIR/.cargo"
cat > "$PROJECT_DIR/.cargo/config.toml" << EOF
[target.aarch64-linux-android]
linker = "$CLANG"
EOF
echo "Wrote .cargo/config.toml"

echo "=== Step 4: Compiling Rust library for Android ==="
cd "$PROJECT_DIR"
export CC_aarch64_linux_android="$CLANG"
export AR_aarch64_linux_android="$TOOLCHAIN/bin/llvm-ar"
export BUILD_VERSION="apk `git log --pretty=format:"Rust %ad %h %s" -1`" 
cargo build --target "$RUST_TARGET" --release
echo "Compiled."

echo "=== Step 5: Copying binary and assets into Android project ==="

# cdylib goes into jniLibs so Android can load it with System.loadLibrary("cjp2p")
JNILIBS="$ANDROID_DIR/app/src/main/jniLibs/arm64-v8a"
mkdir -p "$JNILIBS"
cp "target/$RUST_TARGET/release/libcjp2p.so" "$JNILIBS/libcjp2p.so"
echo "Copied libcjp2p.so -> jniLibs/arm64-v8a/libcjp2p.so"

# HTML assets go into assets/public/ and get extracted to filesDir at runtime
ASSETS_PUB="$ANDROID_DIR/app/src/main/assets/public"
mkdir -p "$ASSETS_PUB"
for f in cjp2p/public/*.html cjp2p/public/*.js cjp2p/public/*.css; do
    [ -f "$f" ] && cp "$f" "$ASSETS_PUB/" && echo "  asset: $(basename $f)"
done

echo "=== Step 6: Building APK ==="
cd "$ANDROID_DIR"

echo "sdk.dir=$ANDROID_SDK_ROOT" > local.properties

GRADLE_VERSION="8.9"
GRADLE_INSTALL="$HOME/.gradle/gradle-${GRADLE_VERSION}"
GRADLE_BIN="$GRADLE_INSTALL/bin/gradle"

if [ ! -f "$GRADLE_BIN" ]; then
    echo "Downloading Gradle $GRADLE_VERSION..."
    curl -L -o /tmp/gradle-${GRADLE_VERSION}.zip \
        "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip"
    unzip -q /tmp/gradle-${GRADLE_VERSION}.zip -d "$HOME/.gradle"
    rm /tmp/gradle-${GRADLE_VERSION}.zip
    echo "Done."
else
    echo "Gradle $GRADLE_VERSION already installed."
fi

"$GRADLE_BIN" assembleDebug

APK="$ANDROID_DIR/app/build/outputs/apk/debug/app-debug.apk"
echo ""
echo "======================================"
echo "APK ready: $APK"
echo ""
echo "Install on connected device:"
echo "  adb install $APK"
echo ""
echo "Or copy the APK to the phone and install manually."
echo "======================================"
