//! The gap this closes: every prior E2E test stubbed the network. Here the wallet completes a full
//! OpenID4VP presentation against a LIVE relying-party endpoint over real TCP:
//!
//!   RP-signed request (real DCQL query) → in-core trust decision (real chain, signed trust list)
//!   → data-minimised consent → device signs the KB-JWT → the shell HTTP-POSTs the vp_token over
//!   an actual socket → the RP server VERIFIES the presentation with real crypto → 200 → the core
//!   reaches Done.
//!
//! If this passes, the sans-IO core + reference shell demonstrably drive a real network round-trip
//! end to end — the remaining delta to production is TLS + endpoints, not architecture.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;

use crypto_backend::AwsLc;
use crypto_traits::Alg;
use presenter::ScreenDescription;
use shell_io::{DeviceSigner, ShellRunner, TrustFetcher};
use wallet_core::{Core, DemoWallet, Event, HeldCredential};

/// Device signer backed by the demo wallet's software key (the test stand-in for the enclave).
struct DemoSigner<'a>(&'a DemoWallet);
impl DeviceSigner for DemoSigner<'_> {
    fn sign(&self, _key_ref: &str, payload: &[u8]) -> Vec<u8> {
        self.0.sign_device(payload.to_vec())
    }
}

/// Trust fetcher returning the demo RP chain (production fetches this over the network).
struct DemoTrust {
    chain: Vec<Vec<u8>>,
    uris: Vec<String>,
}
impl TrustFetcher for DemoTrust {
    fn fetch(&self, _client_id: &str) -> (Vec<Vec<u8>>, Vec<String>) {
        (self.chain.clone(), self.uris.clone())
    }
}

/// A one-shot RP response endpoint on a real TCP socket: accepts one HTTP POST, hands the body to
/// the test, answers 200.
fn spawn_rp_server() -> (u16, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        // Read headers.
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        let header_end = loop {
            let n = stream.read(&mut buf).expect("read");
            raw.extend_from_slice(&buf[..n]);
            if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
            assert!(n > 0, "connection closed before headers");
        };
        // Read the declared body length.
        let head = String::from_utf8_lossy(&raw[..header_end]).to_string();
        let content_length: usize = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|v| v.trim().parse().unwrap())
            })
            .expect("Content-Length");
        let mut body = raw[header_end + 4..].to_vec();
        while body.len() < content_length {
            let n = stream.read(&mut buf).expect("read body");
            assert!(n > 0, "connection closed mid-body");
            body.extend_from_slice(&buf[..n]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .expect("respond");
        tx.send(body).expect("hand body to test");
    });
    (port, rx)
}

#[test]
fn full_presentation_over_live_tcp() {
    let (port, received) = spawn_rp_server();

    // Fixtures whose signed request answers to the LIVE local endpoint, via a real DCQL query.
    let wallet = DemoWallet::new();
    let s = wallet.scenario_with_response_uri(&format!("http://127.0.0.1:{port}/response"));

    let mut core = Core::new("wallet.example", "device-key");
    core.load_unverified_credential_for_testing(HeldCredential {
        issuer_jwt: s.issuer_jwt.clone(),
        disclosures_by_claim: serde_json::from_str(&s.disclosures_by_claim_json).unwrap(),
        status_index: None,
    });
    core.load_device_key(s.device_public_key.clone());
    core.handle_event(Event::SetClock { epoch: s.epoch });
    core.load_trust_list(&s.trust_list, &s.operator_public_key)
        .expect("trust list loads");

    let mut shell = ShellRunner::new(
        core,
        DemoSigner(&wallet),
        DemoTrust {
            chain: s.rp_cert_chain.clone(),
            uris: s.registered_redirect_uris.clone(),
        },
    );

    // 1) Request arrives → the shell fetches trust, the core decides registration and renders the
    //    data-minimised consent — then the cascade stops: consent belongs to the human.
    let outcome = shell.handle(Event::AuthorizationRequestReceived {
        request: s.presentation_request.clone(),
    });
    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    match shell.last_screen() {
        Some(ScreenDescription::Consent(c)) => {
            assert_eq!(
                c.requested_claims,
                vec!["age_over_18".to_string()],
                "DCQL query minimised to the one requested-and-held claim"
            );
        }
        other => panic!("expected the consent screen, got {other:?}"),
    }

    // 2) The human consents → device signs the KB-JWT → REAL HTTP POST → 200 → delivered → Done.
    let outcome = shell.handle(Event::UserConsented);
    assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
    assert_eq!(outcome.http_posts.len(), 1, "exactly one live POST");
    let (url, status, _) = &outcome.http_posts[0];
    assert!(url.contains("/response"));
    assert_eq!(*status, 200);
    assert!(outcome.closed, "core closed the flow after delivery");
    assert_eq!(shell.core.state(), &oid4vp::State::Done);

    // 3) The RP SERVER received the OpenID4VP direct_post body over the socket — extract the
    //    DCQL-keyed vp_token and verify the presentation with real crypto.
    let posted = received.recv().expect("server received the vp_token");
    let vp_token = vp_token_from_form(&posted);
    let sd = sdjwt::SdJwtVc::parse(&vp_token).expect("well-formed SD-JWT presentation");
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
        .expect("RP accepts the live-delivered presentation");
    assert_eq!(claims.get("age_over_18"), Some(&serde_json::json!(true)));
    assert!(
        claims.get("family_name").is_none(),
        "data minimisation held across the wire: family_name was never disclosed"
    );
}

/// Extract the SD-JWT presentation from an OpenID4VP 1.0 `direct_post` form body. The request
/// carried a DCQL query with id "pid", so `vp_token` is a percent-encoded JSON object
/// `{"pid":"<presentation>"}` (§8.1).
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
