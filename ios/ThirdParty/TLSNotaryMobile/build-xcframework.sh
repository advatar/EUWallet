#!/bin/sh
set -eu

# Rebuild TLSNMobile.xcframework from the TLSNotary fork ON GITHUB — never from a local sibling
# checkout. Building from GitHub at a pinned ref is deliberate: it guarantees the artifact-signing
# fix (canonical, sorted-key signing bytes — advatar/tlsn commit 89a638f6a) is present, and it avoids
# the "vendoring changes the dependency graph" trap that can flip serde_json's `preserve_order` and
# make a vendored verifier disagree with the notary about the signed bytes.
#
# Override the source with TLSN_REPO / TLSN_REF (e.g. once the fix lands on main, set TLSN_REF=main).
TLSN_REPO="${TLSN_REPO:-https://github.com/advatar/tlsn.git}"
TLSN_REF="${TLSN_REF:-main}"

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
artifact_dir="$package_dir/Artifacts/TLSNMobile.xcframework"
checkout_dir="$package_dir/.tlsn-src"          # git-ignored GitHub checkout (the "dependency")
build_dir="$checkout_dir/target/tlsn-mobile-xcframework"
rustc_bin=$(rustup which rustc)

# Fetch the pinned ref from GitHub (shallow), refreshing an existing checkout in place.
if [ -d "$checkout_dir/.git" ]; then
  git -C "$checkout_dir" fetch --depth 1 origin "$TLSN_REF"
  git -C "$checkout_dir" checkout -q FETCH_HEAD
else
  git clone --depth 1 --branch "$TLSN_REF" "$TLSN_REPO" "$checkout_dir"
fi
repo_dir="$checkout_dir"
echo "Building tlsn-ios from $TLSN_REPO @ $TLSN_REF ($(git -C "$repo_dir" rev-parse --short HEAD))"

# The Apple targets tlsn-ios ships to (x86_64-apple-ios is the Intel Simulator slice).
for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin; do
  rustup target add "$target" >/dev/null 2>&1 || true
  RUSTC="$rustc_bin" cargo build --manifest-path "$repo_dir/Cargo.toml" --release -p tlsn-ios --target "$target"
done

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

echo "Rebuilt $artifact_dir from GitHub. Now run repack-framework-style.sh."
