//! The FULL credential lifecycle over live TCP — one core, one process, real sockets end to end:
//!
//!   ISSUANCE   offer (issuer trusted in-core, real chain) → live POST /token → in-core WUA
//!              key-attestation gate → device signs the proof → live POST /credential → the wallet
//!              stores the SD-JWT exactly as received over the wire;
//!   PRESENTATION  RP-signed DCQL request → minimised consent → device-signed KB-JWT →
//!              live POST /response → the RP verifies the presentation with real crypto.
//!
//! The credential the RP verifies at the end is the one that travelled the wire at issuance —
//! nothing is loaded out-of-band. This is the "issue → hold → present" loop a production wallet
//! runs, minus only TLS and real endpoints.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;

use crypto_backend::AwsLc;
use crypto_traits::Alg;
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

/// One live server playing issuer AND relying party, routing by path over real TCP:
///   POST /token       → {"bound":true,"cNonce":111}
///   POST /credential  → {"format":"dc+sd-jwt","credential":"<jwt~d1~d2~>"} (captures the proof)
///   POST /response    → 200 (captures the vp_token)
fn spawn_issuer_and_rp(
    issuance_compact: String,
) -> (u16, mpsc::Receiver<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let (proof_tx, proof_rx) = mpsc::channel();
    let (vp_tx, vp_rx) = mpsc::channel();
    std::thread::spawn(move || {
        // The flow makes exactly three sequential requests.
        for _ in 0..3 {
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
                "/response" => {
                    vp_tx.send(body).expect("hand vp_token to test");
                    respond_json(&mut stream, "");
                }
                other => panic!("unexpected path {other}"),
            }
        }
    });
    (port, proof_rx, vp_rx)
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
fn full_lifecycle_issue_then_present_over_live_tcp() {
    let wallet = DemoWallet::new();
    // The live issuer returns the device-bound PID fixture with every mandatory type claim.
    let issuance_compact = wallet.issuance_scenario().pid_credential_compact;

    let (port, proof_rx, vp_rx) = spawn_issuer_and_rp(issuance_compact.clone());
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
        issuer_cert_chain: s.rp_cert_chain.clone(), // demo leaf chains to the trusted CA
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
    assert!(held.contains("urn:eudi:pid:1"), "issued PID is held: {held}");
    assert!(held.contains("birthdate"), "mandatory claims travelled: {held}");

    // ---- PRESENTATION, live: DCQL request → consent → KB-JWT → /response → RP verifies. ----
    let outcome = shell.handle(Event::AuthorizationRequestReceived {
        request: s.presentation_request.clone(),
    });
    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    match shell.last_screen() {
        Some(ScreenDescription::Consent(c)) => {
            assert_eq!(c.requested_claims, vec!["age_over_18".to_string()]);
        }
        other => panic!("expected the consent screen, got {other:?}"),
    }

    let outcome = shell.handle(Event::UserConsented);
    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    assert!(outcome.closed);
    assert_eq!(shell.core.state(), &oid4vp::State::Done);

    // The RP verifies the LIVE-delivered presentation of the LIVE-issued credential.
    let vp_token = vp_token_from_form(&vp_rx.recv().expect("vp_token received"));
    let sd = sdjwt::SdJwtVc::parse(&vp_token).expect("well-formed presentation");
    let claims = sd
        .verify_presentation(
            &AwsLc,
            &AwsLc,
            &wallet.issuer_public_key(),
            Alg::Es256,
            &sdjwt::KeyBindingCheck {
                device_public_key: &s.device_public_key,
                expected_aud: "rp.example",
                expected_nonce: wallet.demo_nonce(),
                device_alg: Alg::Es256,
            },
        )
        .expect("RP accepts");
    assert_eq!(claims.get("age_over_18"), Some(&serde_json::json!(true)));
    assert!(
        claims.get("family_name").is_none(),
        "family_name was issued over the wire but never disclosed"
    );
}

/// Extract the SD-JWT presentation from an OpenID4VP 1.0 `direct_post` form body (DCQL id "pid").
fn vp_token_from_form(body: &[u8]) -> String {
    let s = String::from_utf8(body.to_vec()).expect("utf8 body");
    let raw = s
        .strip_prefix("vp_token=")
        .and_then(|v| v.split('&').next())
        .expect("vp_token form field");
    let decoded = percent_decode(raw);
    let obj: serde_json::Value = serde_json::from_str(&decoded).expect("vp_token JSON object");
    obj.get("pid")
        .and_then(|v| v.as_str())
        .expect("pid presentation")
        .to_string()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b[i + 1] as char).to_digit(16).unwrap();
            let lo = (b[i + 2] as char).to_digit(16).unwrap();
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}
