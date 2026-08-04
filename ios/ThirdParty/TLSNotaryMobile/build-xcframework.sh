#!/bin/sh
set -eu

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$package_dir/../.." && pwd)
artifact_dir="$package_dir/Artifacts/TLSNMobile.xcframework"
build_dir="$repo_dir/target/tlsn-mobile-xcframework"
rustc_bin=$(rustup which rustc)

RUSTC="$rustc_bin" cargo build --manifest-path "$repo_dir/Cargo.toml" --release -p tlsn-ios --target aarch64-apple-ios
RUSTC="$rustc_bin" cargo build --manifest-path "$repo_dir/Cargo.toml" --release -p tlsn-ios --target aarch64-apple-ios-sim
RUSTC="$rustc_bin" cargo build --manifest-path "$repo_dir/Cargo.toml" --release -p tlsn-ios --target x86_64-apple-ios
RUSTC="$rustc_bin" cargo build --manifest-path "$repo_dir/Cargo.toml" --release -p tlsn-ios --target aarch64-apple-darwin
RUSTC="$rustc_bin" cargo build --manifest-path "$repo_dir/Cargo.toml" --release -p tlsn-ios --target x86_64-apple-darwin

mkdir -p "$build_dir/simulator"
lipo -create \
  "$repo_dir/target/aarch64-apple-ios-sim/release/libtlsn_mobile.a" \
  "$repo_dir/target/x86_64-apple-ios/release/libtlsn_mobile.a" \
  -output "$build_dir/simulator/libtlsn_mobile.a"
mkdir -p "$build_dir/macos"
lipo -create \
  "$repo_dir/target/aarch64-apple-darwin/release/libtlsn_mobile.a" \
  "$repo_dir/target/x86_64-apple-darwin/release/libtlsn_mobile.a" \
  -output "$build_dir/macos/libtlsn_mobile.a"

if [ -d "$artifact_dir" ]; then
  rm -rf "$artifact_dir"
fi

xcodebuild -create-xcframework \
  -library "$repo_dir/target/aarch64-apple-ios/release/libtlsn_mobile.a" \
  -headers "$repo_dir/crates/ios/include" \
  -library "$build_dir/simulator/libtlsn_mobile.a" \
  -headers "$repo_dir/crates/ios/include" \
  -library "$build_dir/macos/libtlsn_mobile.a" \
  -headers "$repo_dir/crates/ios/include" \
  -output "$artifact_dir"
