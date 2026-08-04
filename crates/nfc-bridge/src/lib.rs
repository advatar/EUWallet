#![forbid(unsafe_code)]
//! Wallet-side bridge over the iProov `reader-rust` sans-IO relay for reading an
//! eMRTD (ePassport / eID) chip over NFC.
//!
//! ## Boundary
//!
//! The relay is **sans-IO**: [`RelayDriver`] consumes bytes from the service-nfc
//! WebSocket and returns [`Effect`]s the host executes (transceive an APDU against
//! the chip, write a frame to the socket, show progress, end the NFC session,
//! complete with a document / result-token). This crate re-exports that vocabulary
//! under one namespace and will grow the wallet-facing orchestration + UniFFI
//! surface (the shells' second, small reader FFI) on top of it.
//!
//! ## Why this crate is out-of-tree
//!
//! The reader crates live in the `iProov/credentials-platform` submodule under a
//! Proprietary licence. This crate is **excluded from the EUWallet Cargo workspace**
//! (root `Cargo.toml` `exclude`) so advatar's GitHub-hosted CI builds only the
//! default members and never resolves the submodule path — it therefore never needs
//! iProov credentials. Build it explicitly, where the submodule is present:
//!
//! ```sh
//! cargo test --manifest-path crates/nfc-bridge/Cargo.toml
//! ```
//!
//! The read outcome ([`Effect::CompleteDocument`] CBOR, or [`Effect::CompleteResultToken`])
//! plus a fresh liveness capture is what the wallet forwards to VCIssuer's NFC-PID
//! endpoint (`ship_encrypted` reader-token flow → the issuer's proved chip+liveness
//! gate); see `docs/delegation/happ-liveness-nfc-strategy.md` and VCIssuer PR #35.

// Re-export the reader relay vocabulary under one surface, so the rest of the wallet
// depends on `nfc_bridge::…` rather than three separate crate paths.
pub use chipmunk_relay::{
    build_apdu, decode_server, Effect, RelayCommand, RelayDriver, RelayError, ServerMessage,
    CLIENT_CAPS, PROTOCOL_VERSION, SDK_NAME,
};

pub use chipmunk_reader_models::{
    CredentialError, DocumentCredentials, ProgressStyle, ReadOptions, TagCapabilities,
};

pub use chipmunk_mrz::{parse as parse_mrz, parse_ocr as parse_mrz_from_ocr, MrzError, MrzFormat, MrzResult};

/// The SDK identifier this wallet advertises to the server in the relay `init` frame.
pub const WALLET_SDK: &str = concat!("EUWallet/", env!("CARGO_PKG_VERSION"));

/// Build a fresh relay driver for one eMRTD read, advertising the wallet SDK id.
///
/// Each read owns one driver (it is `&mut self`, sans-IO, deterministic); build a new
/// one to retry after a terminal [`Effect::Failed`].
#[must_use]
pub fn new_reader() -> RelayDriver {
    let mut driver = RelayDriver::new();
    driver.set_sdk(WALLET_SDK);
    driver
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_connects_with_a_single_init_frame() {
        // The very first step of the read lifecycle is pure: connect() emits exactly one
        // outgoing binary frame (the `init` handshake) and touches no I/O. This proves the
        // relay crate links and drives inside the EUWallet tree.
        let mut driver = new_reader();
        let effects = driver.connect().expect("connect is infallible from Idle");
        assert_eq!(effects.len(), 1, "connect emits exactly the init frame");
        match &effects[0] {
            Effect::Send(bytes) => assert!(!bytes.is_empty(), "init frame is non-empty"),
            other => panic!("expected Effect::Send(init), got {other:?}"),
        }
    }

    #[test]
    fn parses_the_icao_9303_td3_specimen_mrz() {
        // The canonical ICAO 9303 Appendix TD3 specimen — all check digits valid.
        let raw = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\n\
                   L898902C36UTO7408122F1204159ZE184226B<<<<<10";
        let mrz = parse_mrz(raw).expect("specimen MRZ parses");
        assert_eq!(mrz.format, MrzFormat::Td3);
        assert_eq!(mrz.document_number, "L898902C3");
        assert_eq!(mrz.birth_date, "740812");
        assert_eq!(mrz.expiry_date, "120415");
        assert_eq!(mrz.nationality, "UTO");
        assert!(mrz.all_check_digits_valid, "specimen check digits are valid");
    }

    #[test]
    fn constructs_document_credentials_for_the_read_policy() {
        // The BAC/PACE access key is derived from the MRZ; the scanned form is preferred
        // (the server O/0-corrects against the printed check digit). Proves the models crate
        // links and its constructors validate.
        let scanned = DocumentCredentials::scanned(
            "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
        )
        .expect("raw MRZ credentials validate");
        assert!(scanned.validate().is_ok());

        let manual = DocumentCredentials::manual("L898902C3", "740812", "351012")
            .expect("manual credentials validate");
        assert!(manual.validate().is_ok());

        // Read options + tag capabilities are constructible for start(); defaults exist for
        // options/progress, and capabilities are always populated from the real tag.
        let _options = ReadOptions::default();
        let _style = ProgressStyle::default();
        let _caps = TagCapabilities {
            extended_format: true,
            chaining: false,
            max_length: 256,
            pace_supported: true,
            card_access_data: None,
        };
    }
}
