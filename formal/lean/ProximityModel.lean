/-
  ProximityModel — Tier-2 formal model of the ISO 18013-5 proximity state machine.

  The SAME machine that `crates/iso18013-5` implements in Rust: device engagement → reader
  session establishment (with session-transcript binding) → holder consent → signed device
  response. We prove the safety properties the standard requires:

    1. (consent)          no device response is emitted without holder consent;
    2. (session binding)  no device response is emitted without an established, transcript-bound
                          session (defends against relay / unbound-session attacks);
    3. (ordering)         a consent that arrives before the session is established is rejected.

  Same style as `WalletModel.lean` / `PaymentModel.lean`; no `mathlib`.
-/

namespace ProximityModel

inductive Ev where
  | startEngagement
  | readerEstablish (valid : Bool)   -- valid ⇔ reader key + auth ok AND transcript binds
  | consentGrant
  | consentDecline
  | deviceSign                       -- device produced the response signature
  | terminate
  deriving Repr

/-- Machine states (mirror of `iso18013_5::State`). -/
inductive St where
  | idle
  | engaged
  | sessionEstablished
  | signingResponse
  | responded            -- accepting/terminal: a signed device response was emitted
  | aborted
  | terminated
  deriving DecidableEq, Repr

structure Ctx where
  st          : St
  sessionBound : Bool    -- an established session with a bound transcript
  consented   : Bool
  deriving Repr

def init : Ctx := { st := .idle, sessionBound := false, consented := false }

def step (c : Ctx) : Ev → Ctx
  | .startEngagement =>
      match c.st with
      | .idle => { c with st := .engaged }
      | _ => c
  | .readerEstablish valid =>
      match c.st with
      | .engaged =>
          if valid then { c with st := .sessionEstablished, sessionBound := true }
          else { c with st := .aborted }                              -- guard: reader/transcript invalid
      | _ => c
  | .consentGrant =>
      match c.st with
      | .sessionEstablished => { c with st := .signingResponse, consented := true }
      | .engaged => { c with st := .aborted }                         -- guard: RequestOutOfOrder
      | _ => c
  | .consentDecline =>
      match c.st with
      | .sessionEstablished => { c with st := .aborted }              -- guard: NoConsent
      | _ => c
  | .deviceSign =>
      match c.st with
      | .signingResponse => { c with st := .responded }
      | _ => c
  | .terminate => { c with st := .terminated }

def run (evs : List Ev) : Ctx := evs.foldl step init

/-! ## Inductive invariant: consent and session binding hold through to the response. -/

def Inv (c : Ctx) : Prop :=
  (c.st = St.sessionEstablished → c.sessionBound = true) ∧
  (c.st = St.signingResponse → c.sessionBound = true ∧ c.consented = true) ∧
  (c.st = St.responded → c.sessionBound = true ∧ c.consented = true)

theorem step_preserves_inv (c : Ctx) (e : Ev) (h : Inv c) : Inv (step c e) := by
  obtain ⟨h1, h2, h3⟩ := h
  cases e with
  | startEngagement =>
      simp only [step]; split
      · refine ⟨?_, ?_, ?_⟩ <;> intro hst <;> simp_all
      · exact ⟨h1, h2, h3⟩
  | readerEstablish valid =>
      simp only [step]; split
      · split
        · refine ⟨?_, ?_, ?_⟩ <;> intro hst <;> simp_all
        · refine ⟨?_, ?_, ?_⟩ <;> intro hst <;> simp_all
      · exact ⟨h1, h2, h3⟩
  | consentGrant =>
      simp only [step]; split
      · rename_i hst; refine ⟨?_, ?_, ?_⟩ <;> intro hnew <;> simp_all [h1 hst]
      · refine ⟨?_, ?_, ?_⟩ <;> intro hst <;> simp_all
      · exact ⟨h1, h2, h3⟩
  | consentDecline =>
      simp only [step]; split
      · refine ⟨?_, ?_, ?_⟩ <;> intro hst <;> simp_all
      · exact ⟨h1, h2, h3⟩
  | deviceSign =>
      simp only [step]; split
      · rename_i hst; refine ⟨?_, ?_, ?_⟩ <;> intro hnew <;> simp_all [h2 hst]
      · exact ⟨h1, h2, h3⟩
  | terminate =>
      simp only [step]; refine ⟨?_, ?_, ?_⟩ <;> intro hst <;> simp_all

theorem inv_foldl (evs : List Ev) (c : Ctx) (h : Inv c) : Inv (evs.foldl step c) := by
  induction evs generalizing c with
  | nil => simpa using h
  | cons e rest ih => simpa [List.foldl_cons] using ih (step c e) (step_preserves_inv c e h)

theorem inv_run (evs : List Ev) : Inv (run evs) :=
  inv_foldl evs init (by refine ⟨?_, ?_, ?_⟩ <;> intro h <;> simp [init] at h)

/-- **Theorem (consent required).** A device response is emitted only after holder consent. -/
theorem response_requires_consent (evs : List Ev) :
    (run evs).st = St.responded → (run evs).consented = true :=
  fun h => ((inv_run evs).2.2 h).2

/-- **Theorem (session binding).** A device response is emitted only over an established,
    transcript-bound session. -/
theorem response_requires_bound_session (evs : List Ev) :
    (run evs).st = St.responded → (run evs).sessionBound = true :=
  fun h => ((inv_run evs).2.2 h).1

/-- **Theorem (ordering).** Consent that arrives before the session is established is rejected. -/
theorem premature_consent_is_rejected (c : Ctx) (h : c.st = St.engaged) :
    (step c .consentGrant).st = St.aborted := by
  simp only [step, h]

end ProximityModel
