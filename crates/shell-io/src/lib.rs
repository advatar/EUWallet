#![forbid(unsafe_code)]
//! `shell-io` — the reference shell with **real I/O**.
//!
//! The core is sans-IO: it returns [`Effect`]s and expects the shell to execute them and feed the
//! results back as [`Event`]s until the cascade drains. The iOS app does this in Swift
//! (`EffectExecutor`); this crate is the same loop in Rust, with REAL side effects:
//!
//!  * [`Effect::Http`] → an actual HTTP/1.1 POST over a [`std::net::TcpStream`];
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
use wallet_core::{Core, Effect, Event};

pub mod http;

/// Signs with the device key — the Secure Enclave on hardware, a software key in tests/simulator.
pub trait DeviceSigner {
    fn sign(&self, key_ref: &str, payload: &[u8]) -> Vec<u8>;
}

/// Fetches an RP's certificate chain + registered redirect URIs. The registration DECISION is made
/// in-core against the trusted list; this only performs the fetch.
pub trait TrustFetcher {
    fn fetch(&self, client_id: &str) -> (Vec<Vec<u8>>, Vec<String>);
}

/// What happened while draining one event's effect cascade.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    /// Every screen the core rendered, in order (the last one is what the user sees).
    pub screens: Vec<ScreenDescription>,
    /// (url, status, response_body) for every real HTTP POST performed.
    pub http_posts: Vec<(String, u16, Vec<u8>)>,
    /// Nonces the core asked to persist.
    pub persisted_nonces: Vec<u64>,
    /// Whether the core closed the flow.
    pub closed: bool,
    /// Errors from I/O effects (an HTTP failure aborts the cascade for that branch).
    pub errors: Vec<String>,
}

/// Drives the sans-IO core with real side effects until the effect cascade drains.
pub struct ShellRunner<S: DeviceSigner, T: TrustFetcher> {
    pub core: Core,
    signer: S,
    trust: T,
    last_screen: Option<ScreenDescription>,
}

impl<S: DeviceSigner, T: TrustFetcher> ShellRunner<S, T> {
    pub fn new(core: Core, signer: S, trust: T) -> Self {
        ShellRunner {
            core,
            signer,
            trust,
            last_screen: None,
        }
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
            Effect::Http { url, body } => match http::post(&url, &body) {
                Ok((status, response_body)) => {
                    outcome.http_posts.push((url, status, response_body));
                    if (200..300).contains(&status) {
                        Some(Event::PresentationDelivered)
                    } else {
                        outcome
                            .errors
                            .push(format!("HTTP {status} from response endpoint"));
                        None
                    }
                }
                Err(e) => {
                    outcome
                        .errors
                        .push(format!("HTTP POST to {url} failed: {e}"));
                    None
                }
            },
            Effect::PersistNonce { nonce } => {
                outcome.persisted_nonces.push(nonce);
                None
            }
            Effect::Close => {
                outcome.closed = true;
                None
            }
            // Issuance browser/PAR/token effects need an authorization server; the reference shell
            // records nothing for them here (the E2E issuance harness drives them explicitly).
            Effect::PushPar
            | Effect::OpenAuthBrowser
            | Effect::PromptTxCode
            | Effect::RequestToken
            | Effect::RequestCredential { .. } => None,
        }
    }
}
