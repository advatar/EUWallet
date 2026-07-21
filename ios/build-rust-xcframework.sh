#!/usr/bin/env bash
# Build the wallet-core Rust staticlib for Apple targets and package an xcframework the iOS app
# links against. Regenerate the Swift bindings first (see docs/IMPLEMENTATION_PLAN.md Section 3).
#
# Usage: ./build-rust-xcframework.sh
set -euo pipefail
cd "$(dirname "$0")/.."   # euwallet/

# Xcode and Homebrew may put a different Cargo ahead of rustup. Use the pinned
# repository toolchain explicitly so its Apple targets (and UniFFI ABI) match
# the generated Swift bindings.
RUST_TOOLCHAIN_BIN="$(dirname "$(rustup which --toolchain 1.97.1 rustc)")"
export PATH="$RUST_TOOLCHAIN_BIN:$PATH"

LIB=libwallet_core.a
OUT=ios/WalletCore.xcframework
GEN=ios/Generated

# 1) Regenerate Swift bindings from a host build of the cdylib.
cargo build -p wallet-core
cargo run -p wallet-core --bin uniffi-bindgen -- generate \
  --library target/debug/libwallet_core.dylib --language swift --out-dir "$GEN"

# 2) Build ONLY the static library for device + simulator (arm64). We use `cargo rustc
#    --crate-type staticlib` (not `cargo build`) so cargo does not also try to LINK a cdylib for
#    iOS — that link fails on `___chkstk_darwin` (a compiler-rt stack-probe builtin), and an iOS
#    .dylib is useless to us anyway. Archiving a staticlib skips symbol resolution; the builtin
#    resolves at final app-link against the iOS SDK. Pin the deployment target so the aws-lc
#    objects (built for a modern iOS) and the archive agree (silences the version-mismatch warns).
export IPHONEOS_DEPLOYMENT_TARGET=16.0
cargo rustc -p wallet-core --lib --release --target aarch64-apple-ios --crate-type staticlib
cargo rustc -p wallet-core --lib --release --target aarch64-apple-ios-sim --crate-type staticlib

# 3) Assemble the modulemap headers directory expected by xcframework.
HDR=target/uniffi-headers
mkdir -p "$HDR"
cp "$GEN"/wallet_coreFFI.h "$HDR"/
cp "$GEN"/wallet_coreFFI.modulemap "$HDR"/module.modulemap

# 4) Package the xcframework.
rm -rf "$OUT"
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/$LIB -headers "$HDR" \
  -library target/aarch64-apple-ios-sim/release/$LIB -headers "$HDR" \
  -output "$OUT"

echo "Built $OUT and refreshed $GEN. Add both to the Swift package (binary target + generated source)."
