/-
  QesModel — Tier-2 formal model of the QES (qualified e-signature) authorization machine.

  The SAME machine that `crates/qes` implements in Rust. A qualified signature must be
  what-you-see-is-what-you-sign: the authorization the device produces must bind the exact document
  AND the exact confirmation the user approved, and the user must have explicitly authorized. We
  prove:

    1. (SCA)             no signature authorization exists without explicit user authorization;
    2. (WYSIWYS binding) the signed document is EXACTLY the one the user confirmed — no swap of the
                         document (or its consent representation) between confirmation and signing;
    3. (replay)          a request reusing a nonce is rejected.

  States carry the document, so it physically flows through unchanged. Same discipline and proof
  structure as `PaymentModel.lean`; no `mathlib`.
-/

namespace QesModel

/-- The signable essence: an abstract document id (stands for the document + consent hash) + nonce. -/
structure Doc where
  docId : Nat   -- 0 models "document hash missing"
  nonce : Nat
  deriving DecidableEq, Repr

inductive Ev where
  | request (d : Doc)
  | authorize
  | decline
  | sign            -- device produced the SCA signature over the DTBS/R authorization binding
  deriving Repr

inductive St where
  | idle
  | awaitingAuthorization (d : Doc)
  | awaitingSca (d : Doc)
  | signed (d : Doc)          -- accepting/terminal: an authorization bound to `d`
  | aborted
  deriving DecidableEq, Repr

structure Ctx where
  st         : St
  seen       : List Nat
  confirmed  : Option Doc      -- ghost: what the user saw and authorized
  authorized : Bool
  deriving Repr

def init : Ctx := { st := .idle, seen := [], confirmed := none, authorized := false }

def step (c : Ctx) : Ev → Ctx
  | .request d =>
      match c.st with
      | .idle =>
          if d.docId = 0 then
            { c with st := .aborted }                                   -- guard: DocumentHashMissing
          else if c.seen.contains d.nonce then
            { c with st := .aborted }                                   -- guard: NonceReplayed
          else
            { c with st := .awaitingAuthorization d, confirmed := some d,
                     seen := d.nonce :: c.seen }
      | _ => c
  | .authorize =>
      match c.st with
      | .awaitingAuthorization d => { c with st := .awaitingSca d, authorized := true }
      | _ => c
  | .decline =>
      match c.st with
      | .awaitingAuthorization _ => { c with st := .aborted }
      | _ => c
  | .sign =>
      match c.st with
      | .awaitingSca d => { c with st := .signed d }   -- binds the document carried in-flight
      | _ => c

def run (evs : List Ev) : Ctx := evs.foldl step init

def Inv (c : Ctx) : Prop :=
  (∀ d, c.st = St.awaitingAuthorization d → c.confirmed = some d) ∧
  (∀ d, c.st = St.awaitingSca d → c.authorized = true ∧ c.confirmed = some d) ∧
  (∀ d, c.st = St.signed d → c.authorized = true ∧ c.confirmed = some d)

theorem step_preserves_inv (c : Ctx) (e : Ev) (h : Inv c) : Inv (step c e) := by
  obtain ⟨h1, h2, h3⟩ := h
  cases e with
  | request d =>
      simp only [step]
      split
      · split
        · refine ⟨?_, ?_, ?_⟩ <;> intro q hst <;> simp_all
        · split
          · refine ⟨?_, ?_, ?_⟩ <;> intro q hst <;> simp_all
          · refine ⟨?_, ?_, ?_⟩ <;> intro q hst <;> simp_all
      · exact ⟨h1, h2, h3⟩
  | authorize =>
      simp only [step]
      split
      · rename_i d hst
        refine ⟨?_, ?_, ?_⟩ <;> intro q hnew <;> simp_all [h1 d hst]
      · exact ⟨h1, h2, h3⟩
  | decline =>
      simp only [step]
      split
      · refine ⟨?_, ?_, ?_⟩ <;> intro q hst <;> simp_all
      · exact ⟨h1, h2, h3⟩
  | sign =>
      simp only [step]
      split
      · rename_i d hst
        refine ⟨?_, ?_, ?_⟩ <;> intro q hnew <;> simp_all [h2 d hst]
      · exact ⟨h1, h2, h3⟩

theorem inv_foldl (evs : List Ev) (c : Ctx) (h : Inv c) : Inv (evs.foldl step c) := by
  induction evs generalizing c with
  | nil => simpa using h
  | cons e rest ih => simpa [List.foldl_cons] using ih (step c e) (step_preserves_inv c e h)

theorem inv_run (evs : List Ev) : Inv (run evs) :=
  inv_foldl evs init (by refine ⟨?_, ?_, ?_⟩ <;> intro d h <;> simp [init] at h)

/-- **Theorem (SCA).** A signature authorization is produced only after explicit user authorization. -/
theorem signed_requires_authorization (evs : List Ev) (d : Doc) :
    (run evs).st = St.signed d → (run evs).authorized = true :=
  fun h => ((inv_run evs).2.2 d h).1

/-- **Theorem (WYSIWYS binding).** The signed document is exactly the one the user confirmed. -/
theorem signed_binds_confirmed_document (evs : List Ev) (d : Doc) :
    (run evs).st = St.signed d → (run evs).confirmed = some d :=
  fun h => ((inv_run evs).2.2 d h).2

/-- **Theorem (replay protection).** A request reusing a seen nonce is rejected. -/
theorem replay_is_rejected (c : Ctx) (d : Doc)
    (hidle : c.st = St.idle) (hdoc : d.docId ≠ 0) (h : c.seen.contains d.nonce = true) :
    (step c (.request d)).st = St.aborted := by
  simp only [step, hidle]
  rw [if_neg hdoc, if_pos h]

end QesModel
