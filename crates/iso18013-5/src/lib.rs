#![forbid(unsafe_code)]
//! `iso18013_5` — ISO/IEC 18013-5 proximity presentation (device engagement + session), sans-IO
//!
//! See docs/IMPLEMENTATION_PLAN.md Section 5.
//! Skeleton only: public shapes are sketched; implementation follows the plan.

/// Proximity session states. Transport (BLE/NFC/QR) is handled by the shell; this crate
/// only consumes and produces opaque byte payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Idle,
    Engaged,
    SessionEstablished,
    Responded,
    Terminated,
}
