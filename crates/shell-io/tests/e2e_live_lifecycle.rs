//! Credential issuance over live TCP followed by fail-closed OpenID4VP delivery policy:
//!
//!   ISSUANCE   offer (issuer trusted in-core, real chain) → live POST /token → in-core WUA
//!              key-attestation gate → device signs the proof → live POST /credential → the wallet
//!              stores the SD-JWT exactly as received over the wire;
//!   PRESENTATION  an RP-signed DCQL request targeting plaintext HTTP is rejected before consent,
//!              signing, or a network effect.
//!
//! This preserves live issuance coverage while proving that the reference shell's local-only HTTP
//! transport cannot accidentally become a presentation confidentiality downgrade.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;

use presenter::ScreenDescription;
use shell_io::{DeviceSigner, IssuerEndpoints, ShellRunner, TrustFetcher};
use wallet_core::{Core, DemoWallet, Event};

struct DemoSigner<'a>(&'a DemoWallet);
impl DeviceSigner for DemoSigner<'_> {
    fn sign(&self, _key_ref: &str, payload: &[u8]) -> Vec<u8> {
        self.0.sign_device(payload.to_vec())
    }
}

struct DemoTrust {
    chain: Vec<Vec<u8>>,
    uris: Vec<String>,
}
impl TrustFetcher for DemoTrust {
    fn fetch(&self, _client_id: &str) -> (Vec<Vec<u8>>, Vec<String>) {
        (self.chain.clone(), self.uris.clone())
    }
}

/// One live server playing the issuer, routing by path over real TCP:
///   POST /token       → {"bound":true,"cNonce":111}
///   POST /credential  → {"format":"dc+sd-jwt","credential":"<jwt~d1~d2~>"} (captures the proof)
fn spawn_issuer(issuance_compact: String) -> (u16, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let (proof_tx, proof_rx) = mpsc::channel();
    std::thread::spawn(move || {
        // Issuance makes exactly two sequential requests. Presentation is rejected before I/O.
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("accept");
            let (path, body) = read_request(&mut stream);
            match path.as_str() {
                "/token" => {
                    respond_json(&mut stream, r#"{"bound":true,"cNonce":111}"#);
                }
                "/credential" => {
                    proof_tx.send(body).expect("hand proof to test");
                    let json =
                        format!(r#"{{"format":"dc+sd-jwt","credential":"{issuance_compact}"}}"#);
                    respond_json(&mut stream, &json);
                }
                other => panic!("unexpected path {other}"),
            }
        }
    });
    (port, proof_rx)
}

/// Read one HTTP request; return (path, body).
fn read_request(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut buf).expect("read");
        raw.extend_from_slice(&buf[..n]);
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        assert!(n > 0, "closed before headers");
    };
    let head = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let path = head
        .split_whitespace()
        .nth(1)
        .expect("request path")
        .to_string();
    let content_length: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse().unwrap())
        })
        .unwrap_or(0);
    let mut body = raw[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut buf).expect("read body");
        assert!(n > 0, "closed mid-body");
        body.extend_from_slice(&buf[..n]);
    }
    (path, body)
}

fn respond_json(stream: &mut std::net::TcpStream, body: &str) {
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes()).expect("respond");
}

#[test]
fn live_issuance_then_plaintext_presentation_is_rejected() {
    let wallet = DemoWallet::new();
    // The live issuer returns the device-bound PID fixture with every mandatory type claim.
    let issuance = wallet.issuance_scenario();
    let issuance_compact = issuance.pid_credential_compact;
    let issuer_cert_chain = issuance.issuer_cert_chain;

    let (port, proof_rx) = spawn_issuer(issuance_compact.clone());
    let s = wallet.scenario_with_response_uri(&format!("http://127.0.0.1:{port}/response"));

    // One core for the whole lifecycle: trust list anchors BOTH issuance (pid) and RP access.
    let mut core = Core::new("wallet.example", "device-key");
    core.handle_event(Event::SetClock { epoch: s.epoch });
    core.load_device_key(s.device_public_key.clone());
    core.load_trust_list(
        &wallet.signed_trust_list_with_pid_anchor(),
        &s.operator_public_key,
    )
    .expect("trust list loads");
    core.load_wua(&wallet.wua_jwt(), &wallet.wallet_provider_public_key())
        .expect("WUA verifies and binds the device key");

    let mut shell = ShellRunner::new(
        core,
        DemoSigner(&wallet),
        DemoTrust {
            chain: s.rp_cert_chain.clone(),
            uris: s.registered_redirect_uris.clone(),
        },
    )
    .with_issuer(IssuerEndpoints {
        token_url: format!("http://127.0.0.1:{port}/token"),
        credential_url: format!("http://127.0.0.1:{port}/credential"),
    });

    // ---- ISSUANCE, live: offer → /token → in-core WUA gate → proof → /credential → issued. ----
    let outcome = shell.handle(Event::CredentialOfferReceived {
        offer: br#"{"format":"dc+sd-jwt","grant":"pre-authorized","tx_code_required":false}"#
            .to_vec(),
        issuer_cert_chain,
        issuer_id: "https://issuer.example".into(),
    });
    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    assert_eq!(outcome.http_posts.len(), 2, "live /token + /credential");

    // The issuer received a real proof JWT over the socket.
    let proof = proof_rx.recv().expect("issuer received the proof");
    assert!(!proof.is_empty());

    // The core holds the credential exactly as issued over the wire.
    let (fmt, wire_bytes) = shell.core.issued_credential().expect("credential issued");
    assert_eq!(fmt, "dc+sd-jwt");
    assert_eq!(wire_bytes, issuance_compact.as_bytes());

    // The authenticated response crossed the verified storage boundary without an out-of-band
    // loader, and all mandatory claims travelled even though only one will be presented.
    let held = shell.core.held_credentials_json();
    assert!(
        held.contains("urn:eudi:pid:1"),
        "issued PID is held: {held}"
    );
    assert!(
        held.contains("birthdate"),
        "mandatory claims travelled: {held}"
    );

    // ---- PRESENTATION: the signed request's plaintext HTTP endpoint is rejected before consent. ----
    let outcome = shell.handle(Event::AuthorizationRequestReceived {
        request: s.presentation_request.clone(),
    });
    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    assert!(
        outcome.http_posts.is_empty(),
        "unsafe endpoint must never be contacted"
    );
    assert!(outcome.persisted_nonces.is_empty());
    assert!(outcome.closed);
    assert_eq!(
        shell.core.state(),
        &oid4vp::State::Aborted(oid4vp::AbortReason::ResponseUriInvalid)
    );
    assert!(matches!(
        shell.last_screen(),
        Some(ScreenDescription::Error { code, .. })
            if code == "presentation_response_uri_invalid"
    ));
}
