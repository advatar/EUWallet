#!/usr/bin/env bash
# Generate the Kotlin UniFFI contract and package the Rust core for Android.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST_TOOLCHAIN_BIN="$(dirname "$(rustup which --toolchain 1.97.1 rustc)")"
export PATH="$RUST_TOOLCHAIN_BIN:$PATH"

GEN="android/wallet-shell/src/main/kotlin"
JNI="android/wallet-shell/src/main/jniLibs"
case "$(uname -s)" in
  Darwin) HOST_LIBRARY="target/debug/libwallet_core.dylib" ;;
  Linux) HOST_LIBRARY="target/debug/libwallet_core.so" ;;
  *) echo "Unsupported UniFFI generation host: $(uname -s)" >&2; exit 1 ;;
esac

# UniFFI extracts proc-macro metadata from the host cdylib.
cargo build -p wallet-core
cargo run -p wallet-core --bin uniffi-bindgen -- generate \
  --no-format \
  --library "$HOST_LIBRARY" \
  --language kotlin \
  --out-dir "$GEN"
# Kotlin 2.3 diagnoses one conversion emitted by UniFFI 0.28. Keep application warnings fatal while
# suppressing that generator-owned diagnostic at the generated-file boundary.
perl -pi -e \
  's/\@file:Suppress\("NAME_SHADOWING"\)/\@file:Suppress("NAME_SHADOWING", "REDUNDANT_CALL_OF_CONVERSION_METHOD")/' \
  "$GEN/uniffi/wallet_core/wallet_core.kt"
grep -Fq \
  '@file:Suppress("NAME_SHADOWING", "REDUNDANT_CALL_OF_CONVERSION_METHOD")' \
  "$GEN/uniffi/wallet_core/wallet_core.kt"

# Production devices and Google Play use arm64. Emulator x86_64 is built in CI after its Rust
# target is installed; cargo-ndk creates the ABI directory layout consumed by AGP.
cargo ndk --target arm64-v8a --platform 31 --output-dir "$JNI" \
  build -p wallet-core --release

test -s "$GEN/uniffi/wallet_core/wallet_core.kt"
test -s "$JNI/arm64-v8a/libwallet_core.so"
echo "Generated Kotlin UniFFI bindings and Android arm64 Rust core."
