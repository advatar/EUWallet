//! In-crate UniFFI binding generator. Run e.g.:
//!   cargo run -p wallet-core --bin uniffi-bindgen -- generate \
//!     --library target/debug/libwallet_core.dylib --language swift --out-dir ios/Generated
fn main() {
    uniffi::uniffi_bindgen_main()
}
