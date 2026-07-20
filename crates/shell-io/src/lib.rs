#![forbid(unsafe_code)]
//! `shell-io` — the reference shell with **real I/O**.
//!
//! The core is sans-IO: it returns [`Effect`]s and expects the shell to execute them and feed the
//! results back as [`Event`]s until the cascade drains. The iOS app does this in Swift
//! (`EffectExecutor`); this crate is the same loop in Rust, with REAL side effects:
//!
//!  * OpenID4VP [`Effect::Http`] → an actual HTTP/1.1 POST over a [`std::net::TcpStream`]; payment
//!    and QES profiles fail closed because this reference harness has no PSP/CSC adapter;
//!  * [`Effect::Sign`] → a caller-supplied [`DeviceSigner`] (Secure Enclave on device, a software
//!    key in tests);
//!  * [`Effect::ResolveRpTrust`] → a caller-supplied [`TrustFetcher`] (the RP's cert chain — over
//!    the network in production, canned in tests).
//!
//! Two design rules carried over from the platform shells:
//!  1. **The consent decision stays with the human.** A rendered consent/confirmation screen
//!     produces no follow-up event, so [`ShellRunner::handle`] drains and returns — the caller
//!     inspects [`ShellRunner::last_screen`] and sends `UserConsented` / `PaymentApproved` itself.
//!  2. **TLS is the platform's job.** This client speaks plain `http://` for loopback/E2E use;
//!     production shells terminate TLS with the OS stack (URLSession/OkHttp). It refuses other
//!     schemes rather than pretending.

use presenter::ScreenDescription;
use wallet_core::{Core, Effect, Event, HttpDeliveryProfile};

pub mod http;

const MAX_OPENID4VP_DIRECT_POST_RESPONSE_BYTES: usize = 64 * 1024;

fn validate_openid4vp_direct_post_response(response: &http::HttpResponse) -> Result<(), String> {
    if response.status != 200 {
        return Err(format!(
            "HTTP {} from OpenID4VP response endpoint",
            response.status
        ));
    }
    if response.content_type.as_deref() != Some("application/json") {
        return Err("OpenID4VP response endpoint did not return application/json".into());
    }
    if response.body.len() > MAX_OPENID4VP_DIRECT_POST_RESPONSE_BYTES {
        return Err("OpenID4VP response endpoint body is too large".into());
    }
    let value: serde_json::Value = serde_json::from_slice(&response.body)
        .map_err(|error| format!("OpenID4VP response endpoint returned invalid JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "OpenID4VP response endpoint did not return a JSON object".to_string())?;
    // This reference shell intentionally has no browser/app routing dependency. Any redirect
    // member therefore fails closed, including duplicates collapsed by last-member-wins parsing.
    if object.contains_key("redirect_uri") {
        return Err("OpenID4VP redirect handler is not configured in shell-io".into());
    }
    Ok(())
}

/// Signs with the device key — the Secure Enclave on hardware, a software key in tests/simulator.
pub trait DeviceSigner {
    fn sign(&self, key_ref: &str, payload: &[u8]) -> Vec<u8>;
}

/// Fetches an RP's certificate chain + authenticated delivery endpoints. The tuple retains the
/// legacy redirect-URI shape; the core also exact-matches presentation response URIs against it.
/// The registration DECISION is made in-core against the trusted list; this only performs the fetch.
pub trait TrustFetcher {
    fn fetch(&self, client_id: &str) -> (Vec<Vec<u8>>, Vec<String>);
}

/// Authenticated result of fetching a Token Status List. The provider certificate chain identifies
/// the JWS signer; the core validates it against StatusProvider trust anchors before using bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusResponse {
    pub status_code: u16,
    pub body: Vec<u8>,
    pub provider_cert_chain: Vec<Vec<u8>>,
}

/// Fetches Token Status Lists. Platform shells implement this with URLSession/OkHttp and must cap
/// the body while streaming; the core independently enforces its compact-token limit.
pub trait StatusFetcher {
    fn fetch(&self, uri: &str) -> Result<StatusResponse, String>;
}

/// Default for callers that have not configured status transport. It fails closed and feeds an
/// explicit failed response back to the core; a status-bearing credential can never be disclosed.
#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledStatusFetcher;

impl StatusFetcher for DisabledStatusFetcher {
    fn fetch(&self, _uri: &str) -> Result<StatusResponse, String> {
        Err("Token Status List transport is not configured".into())
    }
}

/// The live issuer endpoints the shell POSTs to during OID4VCI issuance. The wire contract of the
/// reference shell (a production shell speaks the full OAuth token endpoint over TLS):
///  * `token_url` — POST, response `{"bound": bool, "cNonce": u64}`;
///  * `credential_url` — POST body is the proof JWT, response
///    `{"format": "dc+sd-jwt"|"mso_mdoc", "credential": "<compact credential>"}`.
#[derive(Clone, Debug)]
pub struct IssuerEndpoints {
    pub token_url: String,
    pub credential_url: String,
}

/// What happened while draining one event's effect cascade.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    /// Every screen the core rendered, in order (the last one is what the user sees).
    pub screens: Vec<ScreenDescription>,
    /// (url, status, response_body) for every real HTTP POST performed.
    pub http_posts: Vec<(String, u16, Vec<u8>)>,
    /// (URI, HTTP status, body length) for status-list fetches.
    pub status_fetches: Vec<(String, u16, usize)>,
    /// Nonces the core asked to persist.
    pub persisted_nonces: Vec<u64>,
    /// Whether the core closed the flow.
    pub closed: bool,
    /// The wallet-to-wallet offer key the core asked to publish, if any (TS09).
    pub published_offer_key: Option<Vec<u8>>,
    /// Errors from I/O effects (an HTTP failure aborts the cascade for that branch).
    pub errors: Vec<String>,
}

/// Drives the sans-IO core with real side effects until the effect cascade drains.
pub struct ShellRunner<S: DeviceSigner, T: TrustFetcher, F: StatusFetcher = DisabledStatusFetcher> {
    pub core: Core,
    signer: S,
    trust: T,
    status: F,
    issuer: Option<IssuerEndpoints>,
    last_screen: Option<ScreenDescription>,
}

impl<S: DeviceSigner, T: TrustFetcher> ShellRunner<S, T, DisabledStatusFetcher> {
    pub fn new(core: Core, signer: S, trust: T) -> Self {
        ShellRunner {
            core,
            signer,
            trust,
            status: DisabledStatusFetcher,
            issuer: None,
            last_screen: None,
        }
    }
}

impl<S: DeviceSigner, T: TrustFetcher, F: StatusFetcher> ShellRunner<S, T, F> {
    /// Configure the authenticated Token Status List transport.
    pub fn with_status_fetcher<N: StatusFetcher>(self, status: N) -> ShellRunner<S, T, N> {
        ShellRunner {
            core: self.core,
            signer: self.signer,
            trust: self.trust,
            status,
            issuer: self.issuer,
            last_screen: self.last_screen,
        }
    }

    /// Configure live issuer endpoints so the issuance effects (`RequestToken`,
    /// `RequestCredential`) perform real POSTs instead of being ignored.
    pub fn with_issuer(mut self, issuer: IssuerEndpoints) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// The most recently rendered screen — what a UI would currently show.
    pub fn last_screen(&self) -> Option<&ScreenDescription> {
        self.last_screen.as_ref()
    }

    /// Send one event and fully drain the resulting effect cascade (mirrors the Swift executor's
    /// breadth-first queue). Returns everything that happened.
    pub fn handle(&mut self, event: Event) -> Outcome {
        let mut outcome = Outcome::default();
        let mut queue: Vec<Effect> = self.core.handle_event(event);
        while !queue.is_empty() {
            let effect = queue.remove(0);
            if let Some(follow_up) = self.execute(effect, &mut outcome) {
                queue.extend(self.core.handle_event(follow_up));
            }
        }
        outcome
    }

    /// Execute one effect with real I/O; return the follow-up event when it produces a result.
    fn execute(&mut self, effect: Effect, outcome: &mut Outcome) -> Option<Event> {
        match effect {
            Effect::Render { screen } => {
                self.last_screen = Some(screen.clone());
                outcome.screens.push(screen);
                None
            }
            Effect::ResolveRpTrust { client_id } => {
                let (rp_cert_chain, registered_redirect_uris) = self.trust.fetch(&client_id);
                Some(Event::RpCertChainResolved {
                    rp_cert_chain,
                    registered_redirect_uris,
                })
            }
            Effect::Sign { key_ref, payload } => {
                let signature = self.signer.sign(&key_ref, &payload);
                Some(Event::DeviceSignatureProduced { signature })
            }
            Effect::Http { profile, url, body } => {
                if profile != HttpDeliveryProfile::Openid4vpDirectPost {
                    outcome
                        .errors
                        .push(format!("{profile:?} requires a dedicated protocol adapter"));
                    return None;
                }
                match http::post(&url, &body) {
                    Ok(response) => {
                        outcome
                            .http_posts
                            .push((url, response.status, response.body.clone()));
                        if let Err(error) = validate_openid4vp_direct_post_response(&response) {
                            outcome.errors.push(error);
                            return None;
                        }
                        Some(Event::PresentationDelivered)
                    }
                    Err(e) => {
                        outcome
                            .errors
                            .push(format!("HTTP POST to {url} failed: {e}"));
                        None
                    }
                }
            }
            Effect::PersistNonce { nonce } => {
                outcome.persisted_nonces.push(nonce);
                None
            }
            Effect::Close => {
                outcome.closed = true;
                None
            }
            Effect::RequestToken => {
                let issuer = self.issuer.as_ref()?;
                match http::post(&issuer.token_url, b"") {
                    Ok(response) if (200..300).contains(&response.status) => {
                        let status = response.status;
                        let body = response.body;
                        outcome
                            .http_posts
                            .push((issuer.token_url.clone(), status, body.clone()));
                        let v: serde_json::Value = match serde_json::from_slice(&body) {
                            Ok(v) => v,
                            Err(e) => {
                                outcome.errors.push(format!("token response not JSON: {e}"));
                                return None;
                            }
                        };
                        Some(Event::TokenReceived {
                            bound: v["bound"].as_bool().unwrap_or(false),
                            c_nonce: v["cNonce"].as_u64().unwrap_or(0),
                        })
                    }
                    Ok(response) => {
                        outcome
                            .errors
                            .push(format!("token endpoint HTTP {}", response.status));
                        None
                    }
                    Err(e) => {
                        outcome.errors.push(format!("token POST failed: {e}"));
                        None
                    }
                }
            }
            Effect::RequestCredential { proof_jwt } => {
                let issuer = self.issuer.as_ref()?;
                match http::post(&issuer.credential_url, &proof_jwt) {
                    Ok(response) if (200..300).contains(&response.status) => {
                        let status = response.status;
                        let body = response.body;
                        outcome.http_posts.push((
                            issuer.credential_url.clone(),
                            status,
                            body.clone(),
                        ));
                        let v: serde_json::Value = match serde_json::from_slice(&body) {
                            Ok(v) => v,
                            Err(e) => {
                                outcome
                                    .errors
                                    .push(format!("credential response not JSON: {e}"));
                                return None;
                            }
                        };
                        let format = v["format"].as_str().unwrap_or_default().to_string();
                        let bytes = v["credential"]
                            .as_str()
                            .unwrap_or_default()
                            .as_bytes()
                            .to_vec();
                        Some(Event::CredentialReceived { format, bytes })
                    }
                    Ok(response) => {
                        outcome
                            .errors
                            .push(format!("credential endpoint HTTP {}", response.status));
                        None
                    }
                    Err(e) => {
                        outcome.errors.push(format!("credential POST failed: {e}"));
                        None
                    }
                }
            }
            Effect::FetchStatusList { uri } => match self.status.fetch(&uri) {
                Ok(response) => {
                    outcome.status_fetches.push((
                        uri.clone(),
                        response.status_code,
                        response.body.len(),
                    ));
                    Some(Event::StatusListReceived {
                        uri,
                        http_status: response.status_code,
                        token: response.body,
                        provider_cert_chain: response.provider_cert_chain,
                    })
                }
                Err(error) => {
                    outcome
                        .errors
                        .push(format!("status-list fetch from {uri} failed: {error}"));
                    // A synthetic non-HTTP status drives the core's deterministic failure/close
                    // transition instead of silently leaving consent pending.
                    Some(Event::StatusListReceived {
                        uri,
                        http_status: 0,
                        token: Vec::new(),
                        provider_cert_chain: Vec::new(),
                    })
                }
            },
            Effect::PublishTransferOffer { offered_key } => {
                outcome.published_offer_key = Some(offered_key);
                None
            }
            // Browser/PAR/tx-code prompts need a UI or an authorization server; the reference
            // shell leaves them to the platform (the pre-authorized flow doesn't emit them).
            Effect::PushPar | Effect::OpenAuthBrowser | Effect::PromptTxCode => None,
        }
    }
}

#[cfg(test)]
mod typed_delivery_tests {
    use super::*;

    fn response(body: &[u8]) -> http::HttpResponse {
        http::HttpResponse {
            status: 200,
            content_type: Some("application/json".into()),
            body: body.to_vec(),
        }
    }

    #[test]
    fn reference_shell_rejects_every_redirect_member_including_duplicates() {
        for body in [
            br#"{"redirect_uri":"https://one.example"}"#.as_slice(),
            br#"{"redirect_uri":"https://one.example","redirect_uri":"https://two.example"}"#
                .as_slice(),
            br#"{"redirect_uri":"https://one.example","\u0072edirect_uri":"https://two.example"}"#
                .as_slice(),
        ] {
            assert!(validate_openid4vp_direct_post_response(&response(body)).is_err());
        }
    }

    #[test]
    fn reference_shell_accepts_only_exact_bounded_json_object_without_redirect() {
        assert!(validate_openid4vp_direct_post_response(&response(br#"{"future":true}"#)).is_ok());
        let mut wrong_status = response(b"{}");
        wrong_status.status = 201;
        assert!(validate_openid4vp_direct_post_response(&wrong_status).is_err());
        let mut wrong_mime = response(b"{}");
        wrong_mime.content_type = Some("text/html".into());
        assert!(validate_openid4vp_direct_post_response(&wrong_mime).is_err());
        assert!(validate_openid4vp_direct_post_response(&response(b"[]")).is_err());
        assert!(validate_openid4vp_direct_post_response(&response(&vec![
            b' ';
            MAX_OPENID4VP_DIRECT_POST_RESPONSE_BYTES
                + 1
        ]))
        .is_err());
    }
}
