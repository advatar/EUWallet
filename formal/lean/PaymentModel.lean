/-
  PaymentModel — Tier-2 formal model of the payment SCA state machine.

  The SAME machine that `crates/payment` implements in Rust. Payment authorisation under PSD2
  requires Strong Customer Authentication with DYNAMIC LINKING (RTS Art. 5): the authentication
  code the device produces must be bound to the exact amount and payee the user authorised, and
  the user must have explicitly approved that transaction. We prove:

    1. (SCA)             no authorisation code exists without explicit user approval;
    2. (dynamic linking) the authorised payment is EXACTLY the one the user confirmed — what you
                         see is what you authorise, with no swap between confirmation and signing;
    3. (replay)          a request reusing a nonce is rejected.

  States carry the payment payload, so the amount/payee physically flow through unchanged: there
  is no transition that mutates them. A ghost `confirmed` field records what was shown at
  confirmation time, letting us state dynamic linking as an equality. No `mathlib`.
-/

namespace PaymentModel

/-- The payer-visible essence of a payment request (the fields dynamic linking binds). -/
structure Payment where
  payee  : String
  amount : Nat
  nonce  : Nat
  deriving DecidableEq, Repr

inductive Ev where
  | request (p : Payment)
  | approve
  | decline
  | sign            -- device produced the SCA signature over the dynamic-linking binding
  deriving Repr

/-- Machine states (mirror of `payment::State`); non-idle states carry the payment in flight. -/
inductive St where
  | idle
  | awaitingConfirmation (p : Payment)
  | awaitingSca (p : Payment)
  | authorized (p : Payment)          -- accepting/terminal: auth code bound to `p`
  | aborted
  deriving DecidableEq, Repr

structure Ctx where
  st        : St
  seen      : List Nat
  confirmed : Option Payment          -- ghost: what the user saw & approved (set once, never mutated)
  approved  : Bool
  deriving Repr

def init : Ctx := { st := .idle, seen := [], confirmed := none, approved := false }

/-- Transition function — the analogue of the Rust `payment::step` match. -/
def step (c : Ctx) : Ev → Ctx
  | .request p =>
      match c.st with
      | .idle =>
          if p.amount = 0 then
            { c with st := .aborted }                                   -- guard: InvalidAmount
          else if c.seen.contains p.nonce then
            { c with st := .aborted }                                   -- guard: NonceReplayed
          else
            { c with st := .awaitingConfirmation p, confirmed := some p,
                     seen := p.nonce :: c.seen }
      | _ => c
  | .approve =>
      match c.st with
      | .awaitingConfirmation p => { c with st := .awaitingSca p, approved := true }
      | _ => c
  | .decline =>
      match c.st with
      | .awaitingConfirmation _ => { c with st := .aborted }
      | _ => c
  | .sign =>
      match c.st with
      | .awaitingSca p => { c with st := .authorized p }   -- binds the payment carried in-flight
      | _ => c

def run (evs : List Ev) : Ctx := evs.foldl step init

/-! ## Inductive invariant tying approval and dynamic linking through the intermediate states. -/

def Inv (c : Ctx) : Prop :=
  (∀ p, c.st = St.awaitingConfirmation p → c.confirmed = some p) ∧
  (∀ p, c.st = St.awaitingSca p → c.approved = true ∧ c.confirmed = some p) ∧
  (∀ p, c.st = St.authorized p → c.approved = true ∧ c.confirmed = some p)

theorem step_preserves_inv (c : Ctx) (e : Ev) (h : Inv c) : Inv (step c e) := by
  obtain ⟨h1, h2, h3⟩ := h
  cases e with
  | request p =>
      simp only [step]
      split
      · split
        · refine ⟨?_, ?_, ?_⟩ <;> intro q hst <;> simp_all
        · split
          · refine ⟨?_, ?_, ?_⟩ <;> intro q hst <;> simp_all
          · refine ⟨?_, ?_, ?_⟩ <;> intro q hst <;> simp_all
      · exact ⟨h1, h2, h3⟩
  | approve =>
      simp only [step]
      split
      · rename_i p hst
        refine ⟨?_, ?_, ?_⟩ <;> intro q hnew <;> simp_all [h1 p hst]
      · exact ⟨h1, h2, h3⟩
  | decline =>
      simp only [step]
      split
      · refine ⟨?_, ?_, ?_⟩ <;> intro q hst <;> simp_all
      · exact ⟨h1, h2, h3⟩
  | sign =>
      simp only [step]
      split
      · rename_i p hst
        refine ⟨?_, ?_, ?_⟩ <;> intro q hnew <;> simp_all [h2 p hst]
      · exact ⟨h1, h2, h3⟩

theorem inv_foldl (evs : List Ev) (c : Ctx) (h : Inv c) : Inv (evs.foldl step c) := by
  induction evs generalizing c with
  | nil => simpa using h
  | cons e rest ih => simpa [List.foldl_cons] using ih (step c e) (step_preserves_inv c e h)

theorem inv_run (evs : List Ev) : Inv (run evs) :=
  inv_foldl evs init (by refine ⟨?_, ?_, ?_⟩ <;> intro p h <;> simp [init] at h)

/-- **Theorem (SCA).** An authorisation code is produced only after explicit user approval. -/
theorem authorized_requires_approval (evs : List Ev) (p : Payment) :
    (run evs).st = St.authorized p → (run evs).approved = true :=
  fun h => ((inv_run evs).2.2 p h).1

/-- **Theorem (dynamic linking / WYSIWYS).** The authorised payment is exactly the one the user
    confirmed — no substitution of amount or payee between confirmation and signing. -/
theorem authorized_binds_confirmed_payment (evs : List Ev) (p : Payment) :
    (run evs).st = St.authorized p → (run evs).confirmed = some p :=
  fun h => ((inv_run evs).2.2 p h).2

/-- **Theorem (replay protection).** A request reusing a seen nonce is rejected. -/
theorem replay_is_rejected (c : Ctx) (p : Payment)
    (hidle : c.st = St.idle) (hpos : p.amount ≠ 0) (h : c.seen.contains p.nonce = true) :
    (step c (.request p)).st = St.aborted := by
  simp only [step, hidle]
  rw [if_neg hpos, if_pos h]

end PaymentModel
