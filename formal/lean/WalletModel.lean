/-
  WalletModel — Tier-2 formal model of the wallet's remote-presentation state machine.

  See docs/IMPLEMENTATION_PLAN.md Section 10.

  This is the SAME machine that `crates/oid4vp` implements in Rust. Because the Rust core
  is sans-IO (a pure `event → effects` function), we can:
    1. prove safety invariants about this model here, once and for all, and
    2. enumerate traces from this model and replay them against the Rust core as
       conformance tests (the model is an executable ORACLE — see `Traces.lean`).

  We deliberately avoid `mathlib` so the project builds offline in seconds.
-/

namespace WalletModel

/-- Events the machine can receive. `request` carries a nonce so we can model replay. -/
inductive Ev where
  | request (nonce : Nat)
  | validateSig
  | consent
  | disclose
  deriving DecidableEq, Repr

/-- Machine states (mirror of `oid4vp::State`). -/
inductive St where
  | idle
  | requested
  | validated
  | awaitingConsent
  | presenting        -- the accepting state: a presentation was disclosed
  | aborted
  deriving DecidableEq, Repr

/-- Full context: the state plus the security-relevant history the guards depend on. -/
structure Ctx where
  st           : St
  sigValidated : Bool
  consented    : Bool
  usedNonces   : List Nat
  disclosed    : Bool
  deriving Repr

/-- The initial context. -/
def init : Ctx :=
  { st := .idle, sigValidated := false, consented := false, usedNonces := [], disclosed := false }

/--
  The transition function — the exact analogue of the Rust `oid4vp::step` `match`.
  Security guards live here:
   * a `request` whose nonce was already seen is REJECTED (replay → aborted);
   * `disclose` only succeeds when the signature was validated AND the user consented,
     otherwise it aborts.
-/
def step (c : Ctx) : Ev → Ctx
  | .request n =>
      if c.usedNonces.contains n then
        { c with st := .aborted }                                   -- guard: nonce_is_fresh
      else
        { c with st := .requested, usedNonces := n :: c.usedNonces }
  | .validateSig =>
      match c.st with
      | .requested => { c with st := .validated, sigValidated := true }
      | _          => c
  | .consent =>
      match c.st with
      | .validated => { c with st := .awaitingConsent, consented := true }
      | _          => c
  | .disclose =>
      if c.consented && c.sigValidated then
        { c with st := .presenting, disclosed := true }             -- guards satisfied
      else
        { c with st := .aborted }                                   -- guard: no disclose w/o consent+sig

/-- Run a whole trace of events from `init`. -/
def run (evs : List Ev) : Ctx := evs.foldl step init

/-! ## Invariant 1 & 2 — nothing is disclosed without a validated signature AND consent. -/

/-- The safety property carried along every trace. -/
def Safe (c : Ctx) : Prop :=
  c.disclosed = true → (c.consented = true ∧ c.sigValidated = true)

/-- `step` preserves `Safe`. -/
theorem step_preserves_safe (c : Ctx) (e : Ev) (h : Safe c) : Safe (step c e) := by
  unfold Safe at h ⊢
  intro hd
  cases e with
  | request n =>
      simp only [step] at hd ⊢; split at hd <;> simp_all
  | validateSig =>
      simp only [step] at hd ⊢; split at hd <;> simp_all
  | consent =>
      simp only [step] at hd ⊢; split at hd <;> simp_all
  | disclose =>
      simp only [step] at hd ⊢
      by_cases hc : (c.consented && c.sigValidated) = true <;> simp_all

/-- Generalised fold lemma: `Safe` is preserved across any trace. -/
theorem safe_foldl (evs : List Ev) (c : Ctx) (h : Safe c) : Safe (evs.foldl step c) := by
  induction evs generalizing c with
  | nil => simpa using h
  | cons e rest ih => simpa [List.foldl_cons] using ih (step c e) (step_preserves_safe c e h)

/-- **Theorem (no disclosure without consent + signature validation).**
    For every trace, if anything was disclosed then the user consented and the signature
    was validated. This is HLR-traceable invariants (1) and (2) from the plan. -/
theorem disclose_requires_consent_and_validation (evs : List Ev) :
    (run evs).disclosed = true → ((run evs).consented = true ∧ (run evs).sigValidated = true) := by
  have hinit : Safe init := by intro h; simp [init] at h
  exact safe_foldl evs init hinit

/-! ## Invariant: reaching the accepting state implies disclosure happened. -/

def PresentImpliesDisclosed (c : Ctx) : Prop := c.st = St.presenting → c.disclosed = true

theorem step_preserves_present (c : Ctx) (e : Ev) (h : PresentImpliesDisclosed c) :
    PresentImpliesDisclosed (step c e) := by
  unfold PresentImpliesDisclosed at h ⊢
  intro hst
  cases e with
  | request n =>
      simp only [step] at hst ⊢; split at hst <;> simp_all
  | validateSig =>
      simp only [step] at hst ⊢; split at hst <;> simp_all
  | consent =>
      simp only [step] at hst ⊢; split at hst <;> simp_all
  | disclose =>
      simp only [step] at hst ⊢
      by_cases hc : (c.consented && c.sigValidated) = true <;> simp_all

theorem present_foldl (evs : List Ev) (c : Ctx) (h : PresentImpliesDisclosed c) :
    PresentImpliesDisclosed (evs.foldl step c) := by
  induction evs generalizing c with
  | nil => simpa using h
  | cons e rest ih =>
      simpa [List.foldl_cons] using ih (step c e) (step_preserves_present c e h)

/-- **Theorem (accepting state implies validated signature).**
    If a trace ends in the `presenting` (accepting) state, the signature was validated —
    invariant (1) in its state-level form. -/
theorem present_requires_validation (evs : List Ev) :
    (run evs).st = St.presenting → (run evs).sigValidated = true := by
  intro hst
  have hpres : PresentImpliesDisclosed init := by intro h; simp [init] at h
  have hd : (run evs).disclosed = true := present_foldl evs init hpres hst
  exact (disclose_requires_consent_and_validation evs hd).2

/-! ## Invariant 3 — a replayed nonce is always rejected. -/

/-- **Theorem (replay protection).** Presenting a request whose nonce was already used
    moves the machine to `aborted`; the request is never accepted. -/
theorem replay_is_rejected (c : Ctx) (n : Nat) (h : c.usedNonces.contains n = true) :
    (step c (.request n)).st = St.aborted := by
  simp only [step]
  rw [if_pos h]

end WalletModel
