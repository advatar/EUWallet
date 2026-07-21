#![forbid(unsafe_code)]
//! `oid4vci` — OpenID4VCI 1.0 credential issuance as a sans-IO state machine (HAIP flows only).
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 5.2.
//!
//! Like `oid4vp`, this is a pure `step(state, input, env) -> (next_state, effects)` machine: no
//! network, clock, or keys inside. HAIP admits exactly two grants — pre-authorized code and
//! authorization code (with mandatory PAR + PKCE S256) — and exactly two credential formats
//! (mso_mdoc, dc+sd-jwt); anything else is rejected, not extended. The proof-of-possession over
//! the issuer's `c_nonce` is signed by the device key via a `SignProof` effect, so the private
//! key never crosses the FFI. Every state/transition/guard carries an `HLR-VCI-*` id.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value as Json;

pub mod authorization;
pub mod bounded_json;
pub mod credential;
pub mod foundation;

/// The only two grant types HAIP permits. There is deliberately no "other" variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HaipGrant {
    /// HLR-VCI-S-010 — pre-authorized_code (optionally gated by a transaction code / PIN).
    PreAuthorized { tx_code_required: bool },
    /// HLR-VCI-S-011 — authorization_code (PAR + PKCE S256 are mandatory).
    AuthorizationCode,
}

/// The only two credential formats the wallet issues into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialFormat {
    /// ISO mdoc, becomes `mdoc::IssuerSigned`.
    MsoMdoc,
    /// SD-JWT VC, becomes `sdjwt::SdJwtVc`.
    DcSdJwt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// HLR-VCI-S-001
    Idle,
    /// HLR-VCI-S-002 — offer parsed; grant + format chosen and validated.
    OfferParsed {
        grant: HaipGrant,
        format: CredentialFormat,
    },
    /// HLR-VCI-S-003 — (auth-code) PAR pushed; waiting for the browser redirect result.
    Authorizing { format: CredentialFormat },
    /// HLR-VCI-S-004 — (pre-auth) waiting for the user's transaction code / PIN.
    AwaitingTxCode { format: CredentialFormat },
    /// HLR-VCI-S-005 — token request in flight.
    RequestingToken { format: CredentialFormat },
    /// HLR-VCI-S-006 — access token held; the device is signing the proof over `c_nonce`.
    ProvingPossession {
        format: CredentialFormat,
        proof_signing_input: String,
    },
    /// HLR-VCI-S-007 — credential request (with the key-bound proof) in flight.
    RequestingCredential { format: CredentialFormat },
    /// HLR-VCI-S-008 — credential received and structurally validated (terminal).
    CredentialIssued {
        format: CredentialFormat,
        credential: Vec<u8>,
    },
    /// HLR-VCI-S-009 — aborted (terminal).
    Aborted(AbortReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortReason {
    /// HLR-VCI-G-001 — grant_type_is_haip_allowed failed / offer unparseable.
    UnsupportedGrant,
    /// HLR-VCI-G-002 — credential_format_is_supported failed.
    UnsupportedFormat,
    /// HLR-VCI-G-003 — issuer_is_trusted failed.
    IssuerNotTrusted,
    /// HLR-VCI-G-004 — pkce_s256_present failed (auth-code without PKCE S256).
    PkceMissing,
    /// HLR-VCI-G-005 — tx_code_valid failed.
    TxCodeInvalid,
    /// HLR-VCI-G-006 — access_token_is_bound failed (not DPoP / sender-constrained).
    TokenNotBound,
    /// HLR-VCI-G-007 — c_nonce_is_fresh failed (proof replay).
    CNonceStale,
    /// HLR-VCI-G-008 — proof_key_is_attested failed (WUA / key attestation).
    ProofKeyNotAttested,
    /// HLR-VCI-G-009 — the issued credential failed its format validator.
    CredentialInvalid,
    /// HLR-VCI-G-010 — user declined.
    UserDeclined,
}

#[derive(Clone, Debug)]
pub enum Input {
    CredentialOffer(Vec<u8>),
    ParPushed {
        pkce_s256: bool,
    },
    AuthCodeReturned(Vec<u8>),
    TxCodeEntered(Vec<u8>),
    TokenResponse {
        bound: bool,
        c_nonce: u64,
    },
    ProofSignatureProduced(Vec<u8>),
    CredentialResponse {
        format: CredentialFormat,
        bytes: Vec<u8>,
        /// The wallet facade authenticated the credential signature against the trusted issuer
        /// and applied credential-type policy. Structural parsing alone is never sufficient.
        issuer_authenticated: bool,
    },
    /// The transport returned a response that cannot even be represented as a supported format.
    CredentialResponseRejected,
    Decline,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    /// Push a PAR request (network I/O in the shell).
    PushPar,
    /// Open the browser for the authorization-code flow.
    OpenAuthBrowser,
    /// Prompt the user for the transaction code / PIN.
    PromptTxCode,
    /// Exchange the (pre-auth or auth) code for a token.
    RequestToken,
    /// Sign the proof-of-possession JWT with the device key (Secure Enclave in the shell).
    SignProof {
        key_ref: String,
        signing_input: Vec<u8>,
    },
    /// Request the credential, presenting the assembled key-bound proof JWT.
    RequestCredential { proof_jwt: Vec<u8> },
    /// Tear down.
    Close,
}

/// Pure, already-resolved facts the machine reads. The shell assembles these; no I/O in-core.
pub struct Env<'a> {
    /// The issuer is on the trust list (shell-resolved).
    pub issuer_trusted: bool,
    /// The proof key is hardware-attested (WUA / key attestation).
    pub proof_key_attested: bool,
    /// c_nonces already used (proof-replay protection).
    pub seen_c_nonces: &'a [u64],
    /// The device key the shell signs the proof with.
    pub device_key_ref: &'a str,
    /// The credential issuer identifier — the proof JWT `aud`.
    pub issuer_id: &'a str,
    /// Unix seconds from the shell (the core has no clock) for the proof `iat`.
    pub now_epoch: i64,
}

/// Security guards — pure, individually testable, each mapped to an [`AbortReason`].
pub mod guards {
    use super::{CredentialFormat, Env, HaipGrant};

    /// HLR-VCI-G-001 — only the two HAIP grants are ever allowed. Total by construction, but the
    /// guard is the single choke point a future careless `parse_offer` still cannot bypass.
    pub fn grant_type_is_haip_allowed(_g: HaipGrant) -> bool {
        true
    }

    /// HLR-VCI-G-002 — only mso_mdoc and dc+sd-jwt are accepted.
    pub fn credential_format_is_supported(f: CredentialFormat) -> bool {
        matches!(f, CredentialFormat::MsoMdoc | CredentialFormat::DcSdJwt)
    }

    /// HLR-VCI-G-003 — the issuer is on the trust list.
    pub fn issuer_is_trusted(env: &Env) -> bool {
        env.issuer_trusted
    }

    /// HLR-VCI-G-004 — the auth-code flow uses PKCE S256 (HAIP + OAuth Security BCP).
    pub fn pkce_s256_present(pkce_s256: bool) -> bool {
        pkce_s256
    }

    /// HLR-VCI-G-005 — the transaction code is present (non-empty; issuer checks the value).
    pub fn tx_code_valid(code: &[u8]) -> bool {
        !code.is_empty()
    }

    /// HLR-VCI-G-006 — the access token is sender-constrained (DPoP), never a bearer token.
    pub fn access_token_is_bound(bound: bool) -> bool {
        bound
    }

    /// HLR-VCI-G-007 — the proof-of-possession c_nonce is fresh (no proof replay).
    pub fn c_nonce_is_fresh(c_nonce: u64, seen: &[u64]) -> bool {
        !seen.contains(&c_nonce)
    }

    /// HLR-VCI-G-008 — the proof key is hardware-attested (WUA / key attestation).
    pub fn proof_key_is_attested(env: &Env) -> bool {
        env.proof_key_attested
    }
}

/// Pure transition function — exhaustive match.
pub fn step(state: &State, input: &Input, env: &Env) -> (State, Vec<Output>) {
    match (state, input) {
        // HLR-VCI-T-001 — parse offer; reject untrusted issuer / non-HAIP grant / bad format.
        (State::Idle, Input::CredentialOffer(bytes)) => match parse_offer(bytes) {
            Ok((grant, format)) => {
                if !guards::issuer_is_trusted(env) {
                    return (State::Aborted(AbortReason::IssuerNotTrusted), vec![]);
                }
                if !guards::grant_type_is_haip_allowed(grant) {
                    return (State::Aborted(AbortReason::UnsupportedGrant), vec![]);
                }
                if !guards::credential_format_is_supported(format) {
                    return (State::Aborted(AbortReason::UnsupportedFormat), vec![]);
                }
                match grant {
                    HaipGrant::AuthorizationCode => {
                        (State::OfferParsed { grant, format }, vec![Output::PushPar])
                    }
                    HaipGrant::PreAuthorized {
                        tx_code_required: true,
                    } => (State::AwaitingTxCode { format }, vec![Output::PromptTxCode]),
                    HaipGrant::PreAuthorized {
                        tx_code_required: false,
                    } => (
                        State::RequestingToken { format },
                        vec![Output::RequestToken],
                    ),
                }
            }
            Err(()) => (State::Aborted(AbortReason::UnsupportedGrant), vec![]),
        },

        // HLR-VCI-T-002 — auth-code: PAR must carry PKCE S256, or abort.
        (
            State::OfferParsed {
                grant: HaipGrant::AuthorizationCode,
                format,
            },
            Input::ParPushed { pkce_s256 },
        ) => {
            if !guards::pkce_s256_present(*pkce_s256) {
                return (State::Aborted(AbortReason::PkceMissing), vec![]);
            }
            (
                State::Authorizing { format: *format },
                vec![Output::OpenAuthBrowser],
            )
        }

        // HLR-VCI-T-003 — browser returned the auth code → request token.
        (State::Authorizing { format }, Input::AuthCodeReturned(_code)) => (
            State::RequestingToken { format: *format },
            vec![Output::RequestToken],
        ),

        // HLR-VCI-T-004 — pre-auth PIN entered → validate, then request token.
        (State::AwaitingTxCode { format }, Input::TxCodeEntered(code)) => {
            if !guards::tx_code_valid(code) {
                return (State::Aborted(AbortReason::TxCodeInvalid), vec![]);
            }
            (
                State::RequestingToken { format: *format },
                vec![Output::RequestToken],
            )
        }

        // HLR-VCI-T-005 — token must be sender-bound and give a fresh c_nonce with an attested
        // proof key; then ask the device to sign the proof-of-possession.
        (State::RequestingToken { format }, Input::TokenResponse { bound, c_nonce }) => {
            if !guards::access_token_is_bound(*bound) {
                return (State::Aborted(AbortReason::TokenNotBound), vec![]);
            }
            if !guards::c_nonce_is_fresh(*c_nonce, env.seen_c_nonces) {
                return (State::Aborted(AbortReason::CNonceStale), vec![]);
            }
            if !guards::proof_key_is_attested(env) {
                return (State::Aborted(AbortReason::ProofKeyNotAttested), vec![]);
            }
            let proof_signing_input = proof_signing_input(env.issuer_id, *c_nonce, env.now_epoch);
            let bytes = proof_signing_input.clone().into_bytes();
            (
                State::ProvingPossession {
                    format: *format,
                    proof_signing_input,
                },
                vec![Output::SignProof {
                    key_ref: env.device_key_ref.to_string(),
                    signing_input: bytes,
                }],
            )
        }

        // HLR-VCI-T-006 — proof signed → assemble the proof JWT and request the credential.
        (
            State::ProvingPossession {
                format,
                proof_signing_input,
            },
            Input::ProofSignatureProduced(sig),
        ) => {
            let proof_jwt = format!("{}.{}", proof_signing_input, base64url(sig));
            (
                State::RequestingCredential { format: *format },
                vec![Output::RequestCredential {
                    proof_jwt: proof_jwt.into_bytes(),
                }],
            )
        }

        // HLR-VCI-T-007 — credential returned: accept only the requested, structurally valid format.
        (
            State::RequestingCredential { format },
            Input::CredentialResponse {
                format: got,
                bytes,
                issuer_authenticated,
            },
        ) => {
            if got != format || !guards::credential_format_is_supported(*got) {
                return (
                    State::Aborted(AbortReason::UnsupportedFormat),
                    vec![Output::Close],
                );
            }
            if !issuer_authenticated || !validate_issued_credential(*got, bytes) {
                return (
                    State::Aborted(AbortReason::CredentialInvalid),
                    vec![Output::Close],
                );
            }
            (
                State::CredentialIssued {
                    format: *got,
                    credential: bytes.clone(),
                },
                vec![Output::Close],
            )
        }

        (State::RequestingCredential { .. }, Input::CredentialResponseRejected) => (
            State::Aborted(AbortReason::CredentialInvalid),
            vec![Output::Close],
        ),

        // HLR-VCI-T-008 — user declines at any pre-terminal step.
        (_, Input::Decline) => (
            State::Aborted(AbortReason::UserDeclined),
            vec![Output::Close],
        ),

        // HLR-VCI-T-999 — defensive no-op keeps the match exhaustive.
        (s, _) => (s.clone(), vec![]),
    }
}

fn base64url(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Build the OpenID4VCI proof-of-possession JWT signing input (`openid4vci-proof+jwt`), binding
/// the wallet's key to the issuer (`aud`) and the issuer's `c_nonce`.
fn proof_signing_input(issuer_id: &str, c_nonce: u64, iat: i64) -> String {
    let header = base64url(br#"{"alg":"ES256","typ":"openid4vci-proof+jwt"}"#);
    let payload = serde_json::json!({ "aud": issuer_id, "iat": iat, "nonce": c_nonce });
    let payload_b64 = base64url(
        serde_json::to_string(&payload)
            .unwrap_or_default()
            .as_bytes(),
    );
    format!("{header}.{payload_b64}")
}

/// Parse a (simplified) credential offer: `{ "format": "...", "grant": "...", "tx_code_required": bool }`.
/// A full offer carries `credential_issuer` + `credential_configuration_ids` + `grants`; this is
/// the minimal shape the machine needs. Returns `Err(())` on anything non-HAIP.
fn parse_offer(bytes: &[u8]) -> Result<(HaipGrant, CredentialFormat), ()> {
    let v: Json = serde_json::from_slice(bytes).map_err(|_| ())?;
    let format = match v.get("format").and_then(|f| f.as_str()) {
        Some("mso_mdoc") => CredentialFormat::MsoMdoc,
        Some("dc+sd-jwt") | Some("vc+sd-jwt") => CredentialFormat::DcSdJwt,
        _ => return Err(()),
    };
    let grant = match v.get("grant").and_then(|g| g.as_str()) {
        Some("pre-authorized") | Some("urn:ietf:params:oauth:grant-type:pre-authorized_code") => {
            HaipGrant::PreAuthorized {
                tx_code_required: v
                    .get("tx_code_required")
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false),
            }
        }
        Some("authorization_code") => HaipGrant::AuthorizationCode,
        _ => return Err(()),
    };
    Ok((grant, format))
}

/// Structural validation of the issued credential (delegates to the single codec stack — never a
/// second validation path). Full issuer-signature verification against the trust anchor happens in
/// `wallet-core` when the credential is stored.
fn validate_issued_credential(format: CredentialFormat, bytes: &[u8]) -> bool {
    match format {
        CredentialFormat::DcSdJwt => core::str::from_utf8(bytes)
            .ok()
            .and_then(|s| sdjwt::SdJwtVc::parse(s).ok())
            .is_some(),
        // A full mdoc decode needs the issuer-signed structure; here we require non-empty bytes and
        // defer signature/structure verification to the storage step.
        CredentialFormat::MsoMdoc => !bytes.is_empty(),
    }
}

/// Reference model that MIRRORS the Lean Tier-2 model (formal/lean/IssuanceModel.lean).
///
/// The Lean model proves the issuer-trust / token-binding / key-attestation invariants and emits
/// conformance traces; this module is the Rust side those traces replay against (plan Section 10).
/// The production `step` above must refine it. `tests/conformance.rs` checks they agree.
pub mod model {
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub enum St {
        Idle,
        OfferParsed,
        ProvingPossession,
        RequestingCredential,
        CredentialIssued,
        Aborted,
    }

    #[derive(Clone, Debug)]
    pub enum Ev {
        Offer(bool),                           // issuer trusted in-core
        Token { bound: bool, attested: bool }, // sender-bound token + proof-key attested (WUA High)
        Proof,
        Credential(bool),
    }

    #[derive(Clone, Debug)]
    pub struct Ctx {
        pub st: St,
        pub issuer_trusted: bool,
        pub token_bound: bool,
        pub proof_key_attested: bool,
    }

    impl Ctx {
        pub fn init() -> Self {
            Ctx {
                st: St::Idle,
                issuer_trusted: false,
                token_bound: false,
                proof_key_attested: false,
            }
        }
    }

    /// Transition function — the exact analogue of `IssuanceModel.step` in Lean.
    pub fn step(mut c: Ctx, ev: &Ev) -> Ctx {
        match ev {
            Ev::Offer(trusted) => {
                if c.st == St::Idle {
                    if *trusted {
                        c.st = St::OfferParsed;
                        c.issuer_trusted = true;
                    } else {
                        c.st = St::Aborted; // guard: IssuerNotTrusted
                    }
                }
            }
            Ev::Token { bound, attested } => {
                if c.st == St::OfferParsed {
                    if !*bound {
                        c.st = St::Aborted; // guard: TokenNotBound
                    } else if !*attested {
                        c.st = St::Aborted; // guard: ProofKeyNotAttested
                    } else {
                        c.st = St::ProvingPossession;
                        c.token_bound = true;
                        c.proof_key_attested = true;
                    }
                }
            }
            Ev::Proof => {
                if c.st == St::ProvingPossession {
                    c.st = St::RequestingCredential;
                }
            }
            Ev::Credential(valid) => {
                if c.st == St::RequestingCredential {
                    if *valid {
                        c.st = St::CredentialIssued;
                    } else {
                        c.st = St::Aborted; // guard: CredentialInvalid
                    }
                }
            }
        }
        c
    }

    pub fn run(evs: &[Ev]) -> Ctx {
        evs.iter().fold(Ctx::init(), step)
    }

    /// Stable state string, matching the Lean exporter's `stJson`.
    pub fn state_name(st: &St) -> &'static str {
        match st {
            St::Idle => "idle",
            St::OfferParsed => "offerParsed",
            St::ProvingPossession => "provingPossession",
            St::RequestingCredential => "requestingCredential",
            St::CredentialIssued => "credentialIssued",
            St::Aborted => "aborted",
        }
    }
}
