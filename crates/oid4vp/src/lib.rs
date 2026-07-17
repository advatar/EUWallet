#![forbid(unsafe_code)]
//! `oid4vp` — OpenID4VP 1.0 remote presentation as an exhaustive, sans-IO state machine.
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 5.1.
//!
//! The machine is a pure function `step(state, input, env) -> (next_state, effects)`: it never
//! touches the network, a screen, or the clock. All I/O is an [`Output`] the shell executes,
//! feeding results back as an [`Input`]. Signature verification is pure CPU through the
//! `crypto-traits` boundary. Every state/transition/guard carries an `HLR-VP-*` id for the
//! traceability matrix (plan Section 12), and this machine is the refinement of the Lean model
//! in [`model`] (plan Section 10) and the subject of the Tamarin analysis (plan Section 11).

use base64ct::{Base64UrlUnpadded, Encoding};
use crypto_traits::{Alg, Digest, Verifier};
use serde_json::Value as Json;

/// States of the remote-presentation flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// HLR-VP-S-001 — no exchange in progress.
    Idle,
    /// HLR-VP-S-002 — request parsed; waiting for the shell to resolve RP trust + JWKS.
    ResolvingTrust(Box<AuthRequest>),
    /// HLR-VP-S-003 — all guards passed; request is signed, bound, fresh, purposeful.
    RequestValidated(Box<AuthRequest>),
    /// HLR-VP-S-004 — consent granted; the key-binding JWT is being signed by the device key
    /// (Secure Enclave), via a `SignKeyBinding` effect. Nothing has left the wallet yet.
    AwaitingDeviceSignature(Box<PendingPresentation>),
    /// HLR-VP-S-005 — vp_token emitted; awaiting the shell's delivery acknowledgement.
    Presenting,
    /// HLR-VP-S-006 — exchange finished successfully.
    Done,
    /// HLR-VP-S-007 — exchange refused; the reason is the tripped guard.
    Aborted(AbortReason),
}

/// The SD-JWT VC the wallet will present, chosen during consent (data-minimised upstream).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedCredential {
    /// The issuer-signed JWT (compact JWS).
    pub issuer_jwt: String,
    /// The disclosures to reveal (already minimised to the requested-and-held set).
    pub disclosures: Vec<String>,
}

/// In-flight presentation awaiting the device signature over the key-binding JWT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingPresentation {
    /// `<issuer-jwt>~<disclosure>~...~` (no KB-JWT yet).
    pub presentation: String,
    /// ASCII(`<kb-header-b64>.<kb-payload-b64>`) — the bytes the device key signs.
    pub kb_signing_input: String,
}

/// Every abort reason is the name of the guard that tripped (or an explicit user refusal).
/// Tamarin (Section 11) enumerates exactly these as the attacker-reachable bad states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortReason {
    /// HLR-VP-G-001 — request_object_is_signed_and_bound failed.
    RequestNotSignedOrBound,
    /// HLR-VP-G-002 — rp_is_registered failed.
    RelyingPartyNotRegistered,
    /// HLR-VP-G-003 — nonce_is_fresh failed (replay).
    NonceReplayed,
    /// HLR-VP-G-004 — purpose_is_declared failed.
    PurposeUndeclared,
    /// HLR-VP-G-005 — audience_matches failed (mix-up / wrong wallet).
    AudienceMismatch,
    /// HLR-VP-G-006 — redirect_uri_is_registered failed (redirect attack).
    RedirectUriNotRegistered,
    /// HLR-VP-G-007 — the request could not be parsed.
    MalformedRequest,
    /// HLR-VP-G-008 — user declined at the consent screen.
    UserDeclined,
    /// HLR-VP-G-009 — consent granted but no credential was selected to present.
    NoCredential,
}

/// Parsed, still-untrusted Authorization Request. Parsing does NOT imply validity; the guards
/// decide that. `nonce` is modelled as a `u64` to line up with the Lean model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRequest {
    pub client_id: String,
    pub nonce: u64,
    pub audience: String,
    pub response_uri: String,
    pub redirect_uri: Option<String>,
    pub purpose: Option<String>,
    /// Claim names the RP asked for (a simplified stand-in for the DCQL query). Used for data
    /// minimisation upstream (the wallet discloses only the requested-and-held subset).
    pub requested_claims: Vec<String>,
    pub signed_payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub request_alg: Alg,
}

/// Trust facts the SHELL resolves for us (effect result). No I/O happens in-core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTrust {
    pub registered: bool,
    pub rp_public_key: Vec<u8>,
    pub registered_redirect_uris: Vec<String>,
}

/// Inputs (events) into the machine.
#[derive(Clone, Debug)]
pub enum Input {
    AuthorizationRequest(Vec<u8>),
    RpTrustResolved(ResolvedTrust),
    ConsentGranted,
    ConsentDeclined,
    /// The device (Secure Enclave) produced the key-binding signature we requested.
    DeviceSignatureProduced(Vec<u8>),
    PresentationDelivered,
}

/// Outputs (effects) the shell must perform. The core NEVER performs these itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// Fetch RP metadata / trust status / JWKS for this client_id (network I/O in the shell).
    ResolveRpTrust { client_id: String },
    /// Durably remember this nonce so replay is caught across restarts (idempotent in the shell).
    PersistNonce(u64),
    /// Render the consent UI with exactly what will be disclosed.
    RenderConsent {
        rp_client_id: String,
        purpose: String,
    },
    /// Sign the key-binding JWT with the device key (Secure Enclave / StrongBox in the shell).
    /// The private key never crosses the FFI — only these bytes go out and a signature comes back.
    SignKeyBinding {
        key_ref: String,
        signing_input: Vec<u8>,
    },
    /// Post the vp_token to the response_uri (direct_post.jwt).
    SendVpToken(Vec<u8>),
    /// Tear down the exchange.
    Close,
}

/// Pure, already-resolved data the machine reads. The shell assembles this; the core does no I/O.
pub struct Env<'a> {
    /// The value RPs MUST put in `aud`; anything else is a mix-up attempt.
    pub wallet_client_id: &'a str,
    /// Nonces already seen (durable replay set snapshot).
    pub seen_nonces: &'a [u64],
    /// Signature verifier over the crypto boundary (pure CPU, no I/O).
    pub verifier: &'a dyn Verifier,
    /// Digest for the KB-JWT `sd_hash` (pure CPU).
    pub digest: &'a dyn Digest,
    /// Unix seconds supplied by the shell (the core has no clock) for the KB-JWT `iat`.
    pub now_epoch: i64,
    /// The credential chosen to present (set once consent is granted).
    pub selected_credential: Option<&'a SelectedCredential>,
    /// Opaque handle to the device key the shell will sign the KB-JWT with.
    pub device_key_ref: &'a str,
}

/// Security guards — each pure, individually testable, and mapped 1:1 to an [`AbortReason`].
pub mod guards {
    use super::{AuthRequest, ResolvedTrust};
    use crypto_traits::Verifier;

    /// HLR-VP-G-001 — the request object is signed by the RP key AND the signature covers the
    /// exact bytes we parsed. Rejects the "unsigned request" and "swapped payload" attacks.
    pub fn request_object_is_signed_and_bound(
        req: &AuthRequest,
        trust: &ResolvedTrust,
        verifier: &dyn Verifier,
    ) -> bool {
        !req.signature.is_empty()
            && verifier
                .verify(
                    req.request_alg,
                    &trust.rp_public_key,
                    &req.signed_payload,
                    &req.signature,
                )
                .is_ok()
    }

    /// HLR-VP-G-002 — the RP is in the trust list / registrar (CIR 2024/2982 registration).
    pub fn rp_is_registered(_req: &AuthRequest, trust: &ResolvedTrust) -> bool {
        trust.registered
    }

    /// HLR-VP-G-003 — the nonce has not been seen before (replay protection).
    pub fn nonce_is_fresh(nonce: u64, seen: &[u64]) -> bool {
        !seen.contains(&nonce)
    }

    /// HLR-VP-G-004 — the RP declared a non-empty purpose (no silent over-asking).
    pub fn purpose_is_declared(req: &AuthRequest) -> bool {
        req.purpose
            .as_deref()
            .map(|p| !p.trim().is_empty())
            .unwrap_or(false)
    }

    /// HLR-VP-G-005 — the request is addressed to THIS wallet (defeats OAuth mix-up).
    pub fn audience_matches(req: &AuthRequest, wallet_client_id: &str) -> bool {
        req.audience == wallet_client_id
    }

    /// HLR-VP-G-006 — any redirect_uri is one the RP pre-registered (defeats response injection).
    pub fn redirect_uri_is_registered(req: &AuthRequest, trust: &ResolvedTrust) -> bool {
        match &req.redirect_uri {
            None => true,
            Some(uri) => trust.registered_redirect_uris.iter().any(|r| r == uri),
        }
    }
}

/// Pure transition function — exhaustive match. Refines [`model::step`].
pub fn step(state: &State, input: &Input, env: &Env) -> (State, Vec<Output>) {
    match (state, input) {
        // HLR-VP-T-001 — receive & parse; ask the shell to resolve RP trust.
        (State::Idle, Input::AuthorizationRequest(bytes)) => match parse_request(bytes) {
            Ok(req) => {
                let client_id = req.client_id.clone();
                (
                    State::ResolvingTrust(Box::new(req)),
                    vec![Output::ResolveRpTrust { client_id }],
                )
            }
            // HLR-VP-T-002 — unparseable request → abort, disclose nothing.
            Err(()) => (State::Aborted(AbortReason::MalformedRequest), vec![]),
        },

        // HLR-VP-T-003 — trust resolved: run every guard, in order, before consent.
        (State::ResolvingTrust(req), Input::RpTrustResolved(trust)) => {
            if !guards::rp_is_registered(req, trust) {
                return (
                    State::Aborted(AbortReason::RelyingPartyNotRegistered),
                    vec![],
                );
            }
            if !guards::redirect_uri_is_registered(req, trust) {
                return (
                    State::Aborted(AbortReason::RedirectUriNotRegistered),
                    vec![],
                );
            }
            if !guards::audience_matches(req, env.wallet_client_id) {
                return (State::Aborted(AbortReason::AudienceMismatch), vec![]);
            }
            if !guards::purpose_is_declared(req) {
                return (State::Aborted(AbortReason::PurposeUndeclared), vec![]);
            }
            if !guards::nonce_is_fresh(req.nonce, env.seen_nonces) {
                return (State::Aborted(AbortReason::NonceReplayed), vec![]);
            }
            if !guards::request_object_is_signed_and_bound(req, trust, env.verifier) {
                return (State::Aborted(AbortReason::RequestNotSignedOrBound), vec![]);
            }
            let purpose = req.purpose.clone().unwrap_or_default();
            let rp = req.client_id.clone();
            (
                State::RequestValidated(req.clone()),
                vec![
                    Output::PersistNonce(req.nonce),
                    Output::RenderConsent {
                        rp_client_id: rp,
                        purpose,
                    },
                ],
            )
        }

        // HLR-VP-T-004 — user consents → build the presentation + KB-JWT signing input, then ask
        // the device (Secure Enclave) to sign it. Nothing leaves the wallet yet.
        (State::RequestValidated(req), Input::ConsentGranted) => {
            let Some(cred) = env.selected_credential else {
                return (State::Aborted(AbortReason::NoCredential), vec![]);
            };
            let presentation = build_presentation(&cred.issuer_jwt, &cred.disclosures);
            let sd_hash = base64url(&env.digest.sha256(presentation.as_bytes()));
            let kb_signing_input =
                kb_jwt_signing_input(req.nonce, &req.client_id, env.now_epoch, &sd_hash);
            let signing_bytes = kb_signing_input.clone().into_bytes();
            (
                State::AwaitingDeviceSignature(Box::new(PendingPresentation {
                    presentation,
                    kb_signing_input,
                })),
                vec![Output::SignKeyBinding {
                    key_ref: env.device_key_ref.to_string(),
                    signing_input: signing_bytes,
                }],
            )
        }
        // HLR-VP-T-005 — user refuses → abort, disclose nothing.
        (State::RequestValidated(_), Input::ConsentDeclined) => (
            State::Aborted(AbortReason::UserDeclined),
            vec![Output::Close],
        ),

        // HLR-VP-T-006 — device signature ready → assemble the key-bound vp_token and send it.
        (State::AwaitingDeviceSignature(p), Input::DeviceSignatureProduced(sig)) => {
            let kb_jwt = format!("{}.{}", p.kb_signing_input, base64url(sig));
            // `presentation` already ends with '~'; the KB-JWT occupies the final slot.
            let vp_token = format!("{}{}", p.presentation, kb_jwt);
            (
                State::Presenting,
                vec![Output::SendVpToken(vp_token.into_bytes())],
            )
        }

        // HLR-VP-T-007 — delivery acknowledged → done.
        (State::Presenting, Input::PresentationDelivered) => (State::Done, vec![Output::Close]),

        // HLR-VP-T-999 — any other (state, input) pair is a defensive no-op.
        (s, _) => (s.clone(), vec![]),
    }
}

fn base64url(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Build `<issuer-jwt>~<disclosure>~...~` (the SD-JWT VC presentation without the KB-JWT).
fn build_presentation(issuer_jwt: &str, disclosures: &[String]) -> String {
    let mut s = String::from(issuer_jwt);
    for d in disclosures {
        s.push('~');
        s.push_str(d);
    }
    s.push('~');
    s
}

/// Construct the key-binding JWT signing input: ASCII(`<header-b64>.<payload-b64>`) over a
/// `kb+jwt` binding the presentation (`sd_hash`) to this RP (`aud`) and this request (`nonce`).
fn kb_jwt_signing_input(nonce: u64, aud: &str, iat: i64, sd_hash: &str) -> String {
    let header = base64url(br#"{"alg":"ES256","typ":"kb+jwt"}"#);
    let payload = serde_json::json!({
        "nonce": nonce,
        "aud": aud,
        "iat": iat,
        "sd_hash": sd_hash,
    });
    let payload_b64 = base64url(
        serde_json::to_string(&payload)
            .unwrap_or_default()
            .as_bytes(),
    );
    format!("{header}.{payload_b64}")
}

/// Parse an authorization request object (a compact JWS). Extracts the claims and the exact
/// signing input + signature so the `request_object_is_signed_and_bound` guard can verify it
/// against the RP key the shell resolves. Returns `Err(())` on malformed input.
fn parse_request(bytes: &[u8]) -> Result<AuthRequest, ()> {
    let s = core::str::from_utf8(bytes).map_err(|_| ())?;
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return Err(());
    }
    let header_bytes = Base64UrlUnpadded::decode_vec(parts[0]).map_err(|_| ())?;
    let header: Json = serde_json::from_slice(&header_bytes).map_err(|_| ())?;
    let request_alg = match header.get("alg").and_then(|v| v.as_str()) {
        Some("ES256") => Alg::Es256,
        Some("ES384") => Alg::Es384,
        Some("EdDSA") => Alg::EdDsa,
        _ => return Err(()),
    };
    let payload_bytes = Base64UrlUnpadded::decode_vec(parts[1]).map_err(|_| ())?;
    let p: Json = serde_json::from_slice(&payload_bytes).map_err(|_| ())?;

    let client_id = p
        .get("client_id")
        .and_then(|v| v.as_str())
        .ok_or(())?
        .to_string();
    // The OpenID4VP nonce is a string on the wire; we model it as u64 to line up with the Lean
    // model, so accept either a JSON number or a numeric string.
    let nonce = p
        .get("nonce")
        .and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .ok_or(())?;
    let audience = p.get("aud").and_then(|v| v.as_str()).ok_or(())?.to_string();
    let response_uri = p
        .get("response_uri")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let redirect_uri = p
        .get("redirect_uri")
        .and_then(|v| v.as_str())
        .map(String::from);
    let purpose = p.get("purpose").and_then(|v| v.as_str()).map(String::from);
    let requested_claims = p
        .get("claims")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let signed_payload = format!("{}.{}", parts[0], parts[1]).into_bytes();
    let signature = Base64UrlUnpadded::decode_vec(parts[2]).map_err(|_| ())?;

    Ok(AuthRequest {
        client_id,
        nonce,
        audience,
        response_uri,
        redirect_uri,
        purpose,
        requested_claims,
        signed_payload,
        signature,
        request_alg,
    })
}

/// Reference model that MIRRORS the Lean Tier-2 model (formal/lean/WalletModel.lean).
///
/// The Lean model proves the safety invariants and emits conformance traces; this module
/// is the Rust side those traces are replayed against (plan Section 10). The production
/// `step` above must refine this model. Keeping them byte-for-byte behaviourally identical
/// is exactly what the conformance test (`tests/conformance.rs`) checks.
pub mod model {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum St {
        Idle,
        Requested,
        Validated,
        AwaitingConsent,
        Presenting,
        Aborted,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Ev {
        Request(u64),
        ValidateSig,
        Consent,
        Disclose,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Ctx {
        pub st: St,
        pub sig_validated: bool,
        pub consented: bool,
        pub used_nonces: Vec<u64>,
        pub disclosed: bool,
    }

    impl Ctx {
        pub fn init() -> Self {
            Ctx {
                st: St::Idle,
                sig_validated: false,
                consented: false,
                used_nonces: Vec::new(),
                disclosed: false,
            }
        }
    }

    /// Transition function — the exact analogue of `WalletModel.step` in Lean.
    pub fn step(mut c: Ctx, ev: &Ev) -> Ctx {
        match ev {
            Ev::Request(n) => {
                if c.used_nonces.contains(n) {
                    c.st = St::Aborted; // guard: nonce_is_fresh (replay → abort)
                } else {
                    c.st = St::Requested;
                    c.used_nonces.push(*n);
                }
            }
            Ev::ValidateSig => {
                if c.st == St::Requested {
                    c.st = St::Validated;
                    c.sig_validated = true;
                }
            }
            Ev::Consent => {
                if c.st == St::Validated {
                    c.st = St::AwaitingConsent;
                    c.consented = true;
                }
            }
            Ev::Disclose => {
                if c.consented && c.sig_validated {
                    c.st = St::Presenting;
                    c.disclosed = true;
                } else {
                    c.st = St::Aborted; // guard: no disclosure before consent + validation
                }
            }
        }
        c
    }

    /// Run a whole trace from `init`.
    pub fn run(evs: &[Ev]) -> Ctx {
        evs.iter().fold(Ctx::init(), step)
    }

    /// Stable string form of a state, matching the Lean exporter's `stJson`.
    pub fn state_name(st: St) -> &'static str {
        match st {
            St::Idle => "idle",
            St::Requested => "requested",
            St::Validated => "validated",
            St::AwaitingConsent => "awaitingConsent",
            St::Presenting => "presenting",
            St::Aborted => "aborted",
        }
    }
}
