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

pub mod dcql;

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

/// The credential the wallet will present, chosen during consent (data-minimised upstream).
/// OpenID4VP carries either an SD-JWT VC or an ISO 18013-5 mdoc, so this is format-tagged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectedCredential {
    /// SD-JWT VC: the issuer-signed JWT and the disclosures to reveal (already minimised).
    SdJwt {
        issuer_jwt: String,
        disclosures: Vec<String>,
        /// The DCQL credential-query id this credential answers — the `vp_token` object key. `None`
        /// for the legacy `claims` path (a bare presentation under `vp_token`).
        dcql_id: Option<String>,
    },
    /// mdoc (ISO 18013-5) presented over OpenID4VP: the (already-minimised) issuer-signed
    /// structure, the doctype, the OpenID4VP SessionTranscript the device auth binds, and the
    /// device-namespaces bytes.
    Mdoc {
        doctype: String,
        issuer_signed: mdoc::IssuerSigned,
        session_transcript: Vec<u8>,
        device_namespaces: Vec<u8>,
        /// The wallet's `mdoc_generated_nonce`. It is folded into `session_transcript`; the verifier
        /// needs it to rebuild the same transcript, so the response conveys it (see `direct_post`).
        mdoc_generated_nonce: String,
        /// The DCQL credential-query id this credential answers — the `vp_token` object key.
        dcql_id: Option<String>,
    },
}

/// One credential's contribution to the response, awaiting its device signature. SD-JWT signs a
/// key-binding JWT; mdoc signs the COSE `DeviceAuthentication` — different assembly, same handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubPresentation {
    SdJwt {
        /// `<issuer-jwt>~<disclosure>~...~` (no KB-JWT yet).
        presentation: String,
        /// ASCII(`<kb-header-b64>.<kb-payload-b64>`) — the bytes the device key signs.
        kb_signing_input: String,
        dcql_id: Option<String>,
    },
    Mdoc {
        doctype: String,
        issuer_signed: mdoc::IssuerSigned,
        device_namespaces: Vec<u8>,
        /// The COSE protected header the device signature is produced under (reassembled into the
        /// detached-payload `CoseSign1`).
        protected_header: Vec<u8>,
        /// The exact `Sig_structure` bytes the device signs.
        signing_input: Vec<u8>,
        /// Conveyed to the verifier so it can rebuild the SessionTranscript the device auth binds.
        mdoc_generated_nonce: String,
        dcql_id: Option<String>,
    },
}

impl SubPresentation {
    /// The bytes the device key must sign for this sub-presentation.
    fn signing_input(&self) -> Vec<u8> {
        match self {
            SubPresentation::SdJwt {
                kb_signing_input, ..
            } => kb_signing_input.clone().into_bytes(),
            SubPresentation::Mdoc { signing_input, .. } => signing_input.clone(),
        }
    }
}

/// One completed sub-presentation: its DCQL id, the `vp_token` entry (SD-JWT compact or base64url
/// `DeviceResponse`), and the mdoc_generated_nonce if it was an mdoc.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CompletedPresentation {
    dcql_id: Option<String>,
    vp_token: String,
    mdoc_generated_nonce: Option<String>,
}

/// In-flight presentation across ONE OR MORE credentials (one per DCQL query). The device signs
/// each sub-presentation in turn: `queue[0]` is the one being signed now; `done` accumulates the
/// finished entries; when the queue drains the assembled multi-key `vp_token` is sent. A single
/// credential ⇒ a one-element queue whose wire output is byte-identical to the pre-multi machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingPresentation {
    queue: Vec<SubPresentation>,
    done: Vec<CompletedPresentation>,
    state: Option<String>,
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
    /// The request selected a response mode outside the wallet's closed supported set.
    ResponseModeUnsupported,
    /// The direct-post response URI was absent, malformed, or not HTTPS.
    ResponseUriInvalid,
    /// The direct-post response URI was not authenticated as an RP-registered endpoint.
    ResponseUriNotRegistered,
    /// `direct_post.jwt` was requested without a usable response-encryption key.
    ResponseEncryptionMetadataInvalid,
    /// Response encryption failed after request validation (for example, an off-curve EC key).
    ResponseEncryptionFailed,
    /// The trusted clock was asked to move backwards during a presentation.
    ClockRollback,
    /// A selected credential expired after it entered storage.
    CredentialExpired,
    /// A selected credential is not yet valid at the current trusted time.
    CredentialNotYetValid,
    /// A selected credential no longer has valid authenticated issuer provenance.
    CredentialProvenanceInvalid,
    /// RP/trust evidence used by the presentation is no longer current.
    PresentationTrustInvalid,
    /// A selected credential is revoked or suspended.
    CredentialStatusInvalid,
    /// Current authenticated status evidence is unavailable for a selected credential.
    CredentialStatusUnavailable,
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
    /// The RP's opaque `state`, echoed verbatim in the response (OpenID4VP 1.0 §8).
    pub state: Option<String>,
    /// The response mode (`direct_post` is implemented; `direct_post.jwt` adds JWE encryption).
    pub response_mode: String,
    /// The id of the first DCQL credential query — the key the `vp_token` response object uses.
    pub dcql_id: Option<String>,
    /// Acceptable SD-JWT VC types (`meta.vct_values`) — used to select a held credential of the
    /// requested TYPE, not merely one that carries the requested claim names.
    pub requested_vcts: Vec<String>,
    /// Acceptable mdoc doctypes (`meta.doctype_value`) — the mso_mdoc analogue of `requested_vcts`.
    pub requested_doctypes: Vec<String>,
    /// The full parsed DCQL query, when present — one credential query per credential the RP wants.
    /// The wallet selects a credential for EACH entry (multi-credential presentation).
    pub dcql: Option<dcql::DcqlQuery>,
    /// The verifier's response-encryption public key (uncompressed SEC1 P-256), parsed from
    /// `client_metadata.jwks` when the RP asks for `direct_post.jwt`. `None` is valid only for
    /// plaintext `direct_post`; encrypted mode fails closed before consent.
    pub response_encryption_key: Option<Vec<u8>>,
    pub signed_payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub request_alg: Alg,
}

/// Trust facts the SHELL resolves for us (effect result). No I/O happens in-core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTrust {
    pub registered: bool,
    pub rp_public_key: Vec<u8>,
    /// Authenticated RP delivery endpoints. The legacy field name is retained for FFI/wire
    /// compatibility; both `response_uri` and an optional `redirect_uri` must exact-match it.
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
    /// Post the assembled OpenID4VP `direct_post` response body (`application/x-www-form-urlencoded`
    /// with `vp_token` + echoed `state`) to the `response_uri`. (`direct_post.jwt` response
    /// encryption is a HAIP follow-on.)
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
    /// The credentials chosen to present — one per DCQL credential query (set once consent is
    /// granted). Empty means nothing satisfied the request. A single-credential request yields a
    /// one-element slice, and the machine's behaviour + wire output are identical to before.
    pub selected_credentials: &'a [SelectedCredential],
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

    /// Only the two direct-post modes implemented by this wallet are accepted. Exact comparison
    /// prevents lookalike or extension modes from falling through to plaintext delivery.
    pub fn response_mode_is_supported(req: &AuthRequest) -> bool {
        matches!(
            req.response_mode.as_str(),
            "direct_post" | "direct_post.jwt"
        )
    }

    /// A presentation endpoint must be a non-empty, absolute HTTPS URI with an authority. Userinfo,
    /// fragments, whitespace, controls, and backslashes are rejected to avoid parser differentials.
    pub fn response_uri_is_https(req: &AuthRequest) -> bool {
        is_valid_https_uri(&req.response_uri)
    }

    /// The signed request may deliver only to an endpoint authenticated in the RP registration
    /// metadata. Matching is deliberately exact: metadata ingestion owns URI canonicalisation.
    pub fn response_uri_is_registered(req: &AuthRequest, trust: &ResolvedTrust) -> bool {
        trust
            .registered_redirect_uris
            .iter()
            .any(|registered| registered == &req.response_uri)
    }

    /// Encrypted direct-post requires a parsed uncompressed P-256 point. Full on-curve validation
    /// occurs in the crypto backend when ECDH runs; failure there is also handled fail-closed.
    pub fn response_encryption_metadata_is_valid(req: &AuthRequest) -> bool {
        match req.response_mode.as_str() {
            "direct_post" => true,
            "direct_post.jwt" => req
                .response_encryption_key
                .as_deref()
                .is_some_and(|key| key.len() == 65 && key[0] == 0x04),
            _ => false,
        }
    }

    fn is_valid_https_uri(uri: &str) -> bool {
        if uri.is_empty()
            || uri
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
            || uri.contains(['\\', '#'])
        {
            return false;
        }
        let Some((scheme, remainder)) = uri.split_once("://") else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("https") || remainder.is_empty() {
            return false;
        }

        let authority_end = remainder
            .find('/')
            .into_iter()
            .chain(remainder.find('?'))
            .min()
            .unwrap_or(remainder.len());
        let authority = &remainder[..authority_end];
        if authority.is_empty() || authority.contains('@') {
            return false;
        }

        if let Some(ipv6) = authority.strip_prefix('[') {
            let Some(close) = ipv6.find(']') else {
                return false;
            };
            if close == 0 || ipv6[..close].parse::<std::net::Ipv6Addr>().is_err() {
                return false;
            }
            return valid_optional_port(&ipv6[close + 1..]);
        }

        if authority.matches(':').count() > 1 {
            return false; // IPv6 literals must use brackets.
        }
        match authority.rsplit_once(':') {
            Some((host, port)) => valid_host(host) && valid_port(port),
            None => valid_host(authority),
        }
    }

    fn valid_host(host: &str) -> bool {
        if host.is_empty() || host.len() > 253 {
            return false;
        }
        host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    }

    fn valid_optional_port(suffix: &str) -> bool {
        suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_port)
    }

    fn valid_port(port: &str) -> bool {
        !port.is_empty()
            && port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|p| p != 0)
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
            if !guards::response_mode_is_supported(req) {
                return (State::Aborted(AbortReason::ResponseModeUnsupported), vec![]);
            }
            if !guards::response_uri_is_https(req) {
                return (State::Aborted(AbortReason::ResponseUriInvalid), vec![]);
            }
            if !guards::response_uri_is_registered(req, trust) {
                return (
                    State::Aborted(AbortReason::ResponseUriNotRegistered),
                    vec![],
                );
            }
            if !guards::response_encryption_metadata_is_valid(req) {
                return (
                    State::Aborted(AbortReason::ResponseEncryptionMetadataInvalid),
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
            if env.selected_credentials.is_empty() {
                return (State::Aborted(AbortReason::NoCredential), vec![]);
            }
            // Build one sub-presentation per selected credential (one per DCQL query). The device
            // signs them in turn; a single credential ⇒ a one-element queue (unchanged behaviour).
            let mut queue = Vec::with_capacity(env.selected_credentials.len());
            for cred in env.selected_credentials {
                match cred {
                    // SD-JWT VC: sign the key-binding JWT over the presentation's sd_hash.
                    SelectedCredential::SdJwt {
                        issuer_jwt,
                        disclosures,
                        dcql_id,
                    } => {
                        let presentation = build_presentation(issuer_jwt, disclosures);
                        let sd_hash = base64url(&env.digest.sha256(presentation.as_bytes()));
                        let kb_signing_input = kb_jwt_signing_input(
                            req.nonce,
                            &req.client_id,
                            env.now_epoch,
                            &sd_hash,
                        );
                        queue.push(SubPresentation::SdJwt {
                            presentation,
                            kb_signing_input,
                            dcql_id: dcql_id.clone(),
                        });
                    }
                    // mdoc: sign the COSE DeviceAuthentication over the OpenID4VP SessionTranscript.
                    SelectedCredential::Mdoc {
                        doctype,
                        issuer_signed,
                        session_transcript,
                        device_namespaces,
                        mdoc_generated_nonce,
                        dcql_id,
                    } => {
                        let Ok(device_auth) = mdoc::device_authentication_bytes(
                            session_transcript,
                            doctype,
                            device_namespaces,
                        ) else {
                            return (State::Aborted(AbortReason::NoCredential), vec![]);
                        };
                        let protected_header = cose::encode_protected_header(Alg::Es256);
                        let signing_input =
                            cose::sig_structure(&protected_header, &[], &device_auth);
                        queue.push(SubPresentation::Mdoc {
                            doctype: doctype.clone(),
                            issuer_signed: issuer_signed.clone(),
                            device_namespaces: device_namespaces.clone(),
                            protected_header,
                            signing_input,
                            mdoc_generated_nonce: mdoc_generated_nonce.clone(),
                            dcql_id: dcql_id.clone(),
                        });
                    }
                }
            }
            let first_signing_input = queue[0].signing_input();
            let pending = PendingPresentation {
                queue,
                done: Vec::new(),
                state: req.state.clone(),
            };
            (
                State::AwaitingDeviceSignature(Box::new(pending)),
                vec![Output::SignKeyBinding {
                    key_ref: env.device_key_ref.to_string(),
                    signing_input: first_signing_input,
                }],
            )
        }
        // HLR-VP-T-005 — user refuses → abort, disclose nothing.
        (State::RequestValidated(_), Input::ConsentDeclined) => (
            State::Aborted(AbortReason::UserDeclined),
            vec![Output::Close],
        ),

        // HLR-VP-T-006 — device signature ready → assemble the key-bound presentation and the
        // OpenID4VP 1.0 `direct_post` response body, then send it.
        (State::AwaitingDeviceSignature(p), Input::DeviceSignatureProduced(sig)) => {
            let mut pending = (**p).clone();
            if pending.queue.is_empty() {
                return (State::Aborted(AbortReason::NoCredential), vec![]);
            }
            // The signature belongs to the sub-presentation at the front of the queue; finish it.
            let completed = match pending.queue.remove(0) {
                SubPresentation::SdJwt {
                    presentation,
                    kb_signing_input,
                    dcql_id,
                } => {
                    let kb_jwt = format!("{}.{}", kb_signing_input, base64url(sig));
                    // `presentation` already ends with '~'; the KB-JWT occupies the final slot.
                    CompletedPresentation {
                        dcql_id,
                        vp_token: format!("{presentation}{kb_jwt}"),
                        mdoc_generated_nonce: None,
                    }
                }
                SubPresentation::Mdoc {
                    doctype,
                    issuer_signed,
                    device_namespaces,
                    protected_header,
                    mdoc_generated_nonce,
                    dcql_id,
                    ..
                } => {
                    // Reassemble the DeviceAuth as a detached-payload COSE_Sign1 with the enclave
                    // signature, then serialise the full DeviceResponse as this entry's vp_token.
                    let device_auth = cose::CoseSign1 {
                        protected: protected_header,
                        unprotected: cose::UnprotectedHeader::default(),
                        payload: None,
                        signature: sig.clone(),
                    };
                    let device_response = mdoc::device_response(
                        &doctype,
                        &issuer_signed,
                        &device_namespaces,
                        &device_auth,
                    );
                    CompletedPresentation {
                        dcql_id,
                        vp_token: base64url(&device_response),
                        mdoc_generated_nonce: Some(mdoc_generated_nonce),
                    }
                }
            };
            pending.done.push(completed);

            match pending.queue.first() {
                // More credentials to sign → ask the device for the next signature. Nothing sent yet.
                Some(next) => {
                    let signing_input = next.signing_input();
                    (
                        State::AwaitingDeviceSignature(Box::new(pending)),
                        vec![Output::SignKeyBinding {
                            key_ref: env.device_key_ref.to_string(),
                            signing_input,
                        }],
                    )
                }
                // Every credential is signed → assemble the (multi-key) direct_post response.
                None => {
                    let body = assemble_direct_post_body(&pending.done, pending.state.as_deref());
                    (
                        State::Presenting,
                        vec![Output::SendVpToken(body.into_bytes())],
                    )
                }
            }
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

/// Assemble the OpenID4VP 1.0 `direct_post` response body: `application/x-www-form-urlencoded`
/// carrying `vp_token`, the echoed `state`, and (for any mdoc entry) the `mdoc_generated_nonce`.
///
/// Per §8.1 the `vp_token` for a DCQL request is a JSON object keyed by each credential query `id`
/// (`{"<id>":"<presentation>", …}`) — so one OR MANY credentials share one response object. The
/// sole legacy exception (one entry, no DCQL id — the flat `claims` path) sends the bare
/// presentation string, which pre-1.0 verifiers accept.
///
/// `mdoc_generated_nonce` lets the verifier rebuild the SessionTranscript the DeviceAuth binds (it
/// is the `apu` of an encrypted response; for unencrypted `direct_post` a companion form field).
/// All mdoc entries in one session share the wallet's nonce, so a single field suffices.
fn assemble_direct_post_body(done: &[CompletedPresentation], state: Option<&str>) -> String {
    let vp_value = if done.len() == 1 && done[0].dcql_id.is_none() {
        done[0].vp_token.clone()
    } else {
        let mut obj = serde_json::Map::new();
        for c in done {
            obj.insert(
                c.dcql_id.clone().unwrap_or_default(),
                serde_json::Value::String(c.vp_token.clone()),
            );
        }
        serde_json::to_string(&serde_json::Value::Object(obj)).unwrap_or_default()
    };
    let mut body = format!("vp_token={}", form_urlencode(&vp_value));
    if let Some(s) = state {
        body.push_str("&state=");
        body.push_str(&form_urlencode(s));
    }
    if let Some(mgn) = done.iter().find_map(|c| c.mdoc_generated_nonce.as_deref()) {
        body.push_str("&mdoc_generated_nonce=");
        body.push_str(&form_urlencode(mgn));
    }
    body
}

/// Percent-encode a value for `application/x-www-form-urlencoded` (RFC 3986 unreserved set kept;
/// everything else, including spaces, percent-encoded — never `+`, so decoding is unambiguous).
fn form_urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
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
    let state = p.get("state").and_then(|v| v.as_str()).map(String::from);
    // Preserve an absent/non-string mode as unsupported instead of silently selecting plaintext.
    let response_mode = p
        .get("response_mode")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    // Prefer the real DCQL query (OpenID4VP 1.0 §6); fall back to the legacy flat `claims` array.
    // The parsed query is carried whole so the wallet can select one credential PER query entry.
    let dcql = p.get("dcql_query").and_then(dcql::DcqlQuery::from_value);
    let (requested_claims, dcql_id, requested_vcts, requested_doctypes) = match &dcql {
        Some(dq) => (
            dq.requested_claim_paths(),
            dq.first_credential_id(),
            dq.requested_vcts(),
            dq.requested_doctypes(),
        ),
        None => {
            let claims = p
                .get("claims")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            (claims, None, Vec::new(), Vec::new())
        }
    };

    // For direct_post.jwt, the verifier publishes its response-encryption key in client_metadata.
    // Parsing is intentionally strict enough that malformed metadata becomes `None` and therefore
    // trips the fail-closed guard before consent.
    let response_encryption_key = p.get("client_metadata").and_then(parse_enc_jwk);

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
        state,
        response_mode,
        dcql_id,
        requested_vcts,
        requested_doctypes,
        dcql,
        response_encryption_key,
        signed_payload,
        signature,
        request_alg,
    })
}

/// Validate the response-encryption profile in `client_metadata` (`ECDH-ES` + `A256GCM`) and
/// extract the first EC P-256 key in `jwks.keys` marked for encryption (`use == "enc"`, or an
/// ECDH-ES `alg`). Returns it as an uncompressed SEC1 point (`0x04 || X || Y`), or `None` if any
/// required metadata is absent or unsupported.
fn parse_enc_jwk(md: &serde_json::Value) -> Option<Vec<u8>> {
    if md
        .get("authorization_encrypted_response_alg")
        .and_then(|v| v.as_str())
        != Some("ECDH-ES")
        || md
            .get("authorization_encrypted_response_enc")
            .and_then(|v| v.as_str())
            != Some("A256GCM")
    {
        return None;
    }
    let keys = md.get("jwks")?.get("keys")?.as_array()?;
    for k in keys {
        let key_alg = k.get("alg").and_then(|v| v.as_str());
        let key_use = k.get("use").and_then(|v| v.as_str());
        let is_enc = key_use == Some("enc") || key_alg == Some("ECDH-ES");
        let use_is_compatible = key_use.is_none() || key_use == Some("enc");
        let alg_is_compatible = key_alg.is_none() || key_alg == Some("ECDH-ES");
        if !is_enc
            || !use_is_compatible
            || !alg_is_compatible
            || k.get("kty").and_then(|v| v.as_str()) != Some("EC")
        {
            continue;
        }
        if k.get("crv").and_then(|v| v.as_str()) != Some("P-256") {
            continue;
        }
        let x = k.get("x").and_then(|v| v.as_str())?;
        let y = k.get("y").and_then(|v| v.as_str())?;
        let x = Base64UrlUnpadded::decode_vec(x).ok()?;
        let y = Base64UrlUnpadded::decode_vec(y).ok()?;
        if x.len() == 32 && y.len() == 32 {
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            return Some(point);
        }
    }
    None
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

#[cfg(test)]
mod response_tests {
    use super::{assemble_direct_post_body, form_urlencode, CompletedPresentation};

    fn entry(id: Option<&str>, vp: &str, mgn: Option<&str>) -> CompletedPresentation {
        CompletedPresentation {
            dcql_id: id.map(String::from),
            vp_token: vp.to_string(),
            mdoc_generated_nonce: mgn.map(String::from),
        }
    }

    #[test]
    fn dcql_response_is_form_encoded_vp_token_object_with_state() {
        // A DCQL request → vp_token is a JSON object keyed by the query id, form-encoded, + state.
        let body = assemble_direct_post_body(
            &[entry(Some("pid"), "issuer.jwt~disc~kb.jwt", None)],
            Some("xyz 123"),
        );
        // vp_token value is the JSON object {"pid":"<presentation>"} percent-encoded.
        assert!(body.starts_with("vp_token=%7B%22pid%22%3A%22issuer.jwt~disc~kb.jwt%22%7D"));
        // state is echoed and its space is percent-encoded (never '+').
        assert!(body.ends_with("&state=xyz%20123"));
        // A verifier that form-decodes then JSON-parses vp_token recovers the presentation.
        let vp = body
            .strip_prefix("vp_token=")
            .and_then(|s| s.split("&state=").next())
            .map(percent_decode)
            .unwrap();
        let obj: serde_json::Value = serde_json::from_str(&vp).unwrap();
        assert_eq!(obj["pid"], serde_json::json!("issuer.jwt~disc~kb.jwt"));
    }

    #[test]
    fn legacy_response_sends_bare_presentation_under_vp_token() {
        let body = assemble_direct_post_body(&[entry(None, "issuer.jwt~disc~kb.jwt", None)], None);
        // The SD-JWT compact is entirely RFC3986-unreserved, so it is unchanged by encoding.
        assert_eq!(body, "vp_token=issuer.jwt~disc~kb.jwt");
    }

    #[test]
    fn mdoc_response_conveys_generated_nonce_as_companion_field() {
        // An mdoc response carries mdoc_generated_nonce so the verifier can rebuild the transcript.
        let body = assemble_direct_post_body(
            &[entry(
                Some("mdl"),
                "ZGV2aWNlcmVzcG9uc2U",
                Some("mgn-abc123"),
            )],
            None,
        );
        assert!(body.starts_with("vp_token=%7B%22mdl%22%3A%22ZGV2aWNlcmVzcG9uc2U%22%7D"));
        assert!(body.ends_with("&mdoc_generated_nonce=mgn-abc123"));
    }

    #[test]
    fn multi_credential_response_is_a_single_multi_key_vp_token_object() {
        // Two credentials (SD-JWT PID + mdoc mDL) share ONE vp_token object, keyed by DCQL id.
        let body = assemble_direct_post_body(
            &[
                entry(Some("pid"), "issuer.jwt~disc~kb.jwt", None),
                entry(Some("mdl"), "ZGV2aWNlcmVzcG9uc2U", Some("mgn-xyz")),
            ],
            Some("st-1"),
        );
        let vp = body
            .strip_prefix("vp_token=")
            .and_then(|s| s.split("&state=").next())
            .map(percent_decode)
            .unwrap();
        let obj: serde_json::Value = serde_json::from_str(&vp).unwrap();
        assert_eq!(obj["pid"], serde_json::json!("issuer.jwt~disc~kb.jwt"));
        assert_eq!(obj["mdl"], serde_json::json!("ZGV2aWNlcmVzcG9uc2U"));
        assert!(body.contains("&state=st-1"));
        assert!(
            body.contains("&mdoc_generated_nonce=mgn-xyz"),
            "the mdoc entry contributes its nonce"
        );
    }

    #[test]
    fn urlencode_keeps_unreserved_and_percent_encodes_the_rest() {
        assert_eq!(form_urlencode("aZ0-_.~"), "aZ0-_.~");
        assert_eq!(form_urlencode("{}:\" "), "%7B%7D%3A%22%20");
    }

    /// Minimal percent-decoder for the test's round-trip check.
    fn percent_decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hi = (bytes[i + 1] as char).to_digit(16).unwrap();
                let lo = (bytes[i + 2] as char).to_digit(16).unwrap();
                out.push((hi * 16 + lo) as u8);
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(out).unwrap()
    }
}

#[cfg(test)]
mod internal_tests {
    use super::{
        base64url, guards, kb_jwt_signing_input, parse_request, AuthRequest, ResolvedTrust,
    };
    use base64ct::{Base64UrlUnpadded, Encoding};
    use crypto_traits::Alg;

    fn req_jws(alg: &str) -> Vec<u8> {
        let header = Base64UrlUnpadded::encode_string(format!(r#"{{"alg":"{alg}"}}"#).as_bytes());
        let payload = Base64UrlUnpadded::encode_string(
            br#"{"client_id":"rp.example","nonce":1,"aud":"wallet.example"}"#,
        );
        let sig = Base64UrlUnpadded::encode_string(&[0u8; 64]);
        format!("{header}.{payload}.{sig}").into_bytes()
    }

    #[test]
    fn parse_request_accepts_each_supported_alg() {
        assert_eq!(
            parse_request(&req_jws("ES256")).unwrap().request_alg,
            Alg::Es256
        );
        assert_eq!(
            parse_request(&req_jws("ES384")).unwrap().request_alg,
            Alg::Es384
        );
        assert_eq!(
            parse_request(&req_jws("EdDSA")).unwrap().request_alg,
            Alg::EdDsa
        );
    }

    #[test]
    fn parse_request_rejects_unknown_alg_and_wrong_part_count() {
        assert!(
            parse_request(&req_jws("RS256")).is_err(),
            "unsupported alg must be rejected"
        );
        assert!(
            parse_request(b"only.two").is_err(),
            "a non-3-part JWS must be rejected"
        );
        assert!(parse_request(b"not-a-jws").is_err());
    }

    #[test]
    fn base64url_encodes_expected() {
        assert_eq!(base64url(b"abc"), "YWJj");
        assert_eq!(base64url(&[]), "");
    }

    #[test]
    fn kb_jwt_signing_input_binds_nonce_and_aud() {
        let s = kb_jwt_signing_input(42, "rp.example", 100, "sd-hash");
        assert_eq!(
            s.matches('.').count(),
            1,
            "header.payload, no signature yet"
        );
        let payload_b64 = s.split('.').nth(1).unwrap();
        let bytes = Base64UrlUnpadded::decode_vec(payload_b64).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["nonce"], serde_json::json!(42));
        assert_eq!(v["aud"], serde_json::json!("rp.example"));
        assert_eq!(v["sd_hash"], serde_json::json!("sd-hash"));
    }

    fn auth_request(redirect: Option<&str>) -> AuthRequest {
        AuthRequest {
            client_id: "rp.example".into(),
            nonce: 1,
            audience: "wallet.example".into(),
            response_uri: "https://rp.example/resp".into(),
            redirect_uri: redirect.map(String::from),
            purpose: Some("p".into()),
            requested_claims: vec![],
            state: None,
            response_mode: "direct_post".into(),
            dcql_id: None,
            requested_vcts: vec![],
            requested_doctypes: vec![],
            dcql: None,
            response_encryption_key: None,
            signed_payload: b"x".to_vec(),
            signature: b"y".to_vec(),
            request_alg: Alg::Es256,
        }
    }

    #[test]
    fn redirect_uri_guard_matches_registered_only() {
        let trust = ResolvedTrust {
            registered: true,
            rp_public_key: vec![],
            registered_redirect_uris: vec!["https://rp.example/cb".into()],
        };
        assert!(guards::redirect_uri_is_registered(
            &auth_request(Some("https://rp.example/cb")),
            &trust
        ));
        assert!(!guards::redirect_uri_is_registered(
            &auth_request(Some("https://evil.example/cb")),
            &trust
        ));
        assert!(
            guards::redirect_uri_is_registered(&auth_request(None), &trust),
            "absent redirect is allowed"
        );
    }
}
