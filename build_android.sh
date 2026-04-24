#!/bin/bash
# Builds cjp2p as an Android APK.
# Requires: curl, unzip, gradle (for first run), Java 17+
set -e

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

echo "=== Step 4: Compiling Rust binary for Android ==="
cd "$PROJECT_DIR"
export CC_aarch64_linux_android="$CLANG"
export AR_aarch64_linux_android="$TOOLCHAIN/bin/llvm-ar"
export BUILD_VERSION="apk `git log --pretty=format:"Rust %ad %h %s" -1`" 
cargo build --target "$RUST_TARGET" --release
echo "Compiled."

echo "=== Step 5: Copying binary and assets into Android project ==="

# Binary goes into jniLibs so Android installs it to nativeLibraryDir (executable)
JNILIBS="$ANDROID_DIR/app/src/main/jniLibs/arm64-v8a"
mkdir -p "$JNILIBS"
cp "target/$RUST_TARGET/release/cjp2p" "$JNILIBS/libcjp2p.so"
echo "Copied binary -> jniLibs/arm64-v8a/libcjp2p.so"

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
