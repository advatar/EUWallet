/-
  W2wModel — Tier-2 formal model of the wallet-to-wallet RECEIVER machine.

  The SAME machine that `crates/w2w` implements in Rust. When a wallet receives a credential handed
  to it by a peer, the security decision is: accept it ONLY IF its issuer signature validated AND
  it was bound to THIS receiver. We prove:

    1. (validate-before-accept) a credential is accepted only if the issuer signature was valid;
    2. (peer binding)           a credential is accepted only if the transfer was bound to this
                                receiver — no accepting a forged or misdirected/replayed transfer.

  Same discipline as the other Tier-2 models; no `mathlib`.
-/

namespace W2wModel

inductive Ev where
  | createOffer
  | transferReceived (issuerValid peerBound : Bool)
  deriving Repr

inductive St where
  | idle
  | awaitingTransfer
  | accepted          -- accepting/terminal
  | rejected
  deriving DecidableEq, Repr

structure Ctx where
  st          : St
  issuerValid : Bool
  peerBound   : Bool
  deriving Repr

def init : Ctx := { st := .idle, issuerValid := false, peerBound := false }

def step (c : Ctx) : Ev → Ctx
  | .createOffer =>
      match c.st with
      | .idle => { c with st := .awaitingTransfer }
      | _ => c
  | .transferReceived iv pb =>
      match c.st with
      | .awaitingTransfer =>
          if !iv then { c with st := .rejected }                       -- guard: IssuerInvalid
          else if !pb then { c with st := .rejected }                  -- guard: PeerMismatch
          else { c with st := .accepted, issuerValid := true, peerBound := true }
      | .idle => { c with st := .rejected }                            -- guard: OutOfOrder
      | _ => c

def run (evs : List Ev) : Ctx := evs.foldl step init

def Inv (c : Ctx) : Prop :=
  c.st = St.accepted → c.issuerValid = true ∧ c.peerBound = true

theorem step_preserves_inv (c : Ctx) (e : Ev) (h : Inv c) : Inv (step c e) := by
  unfold Inv at h ⊢
  intro hst
  cases e with
  | createOffer =>
      simp only [step] at hst ⊢; split at hst <;> simp_all
  | transferReceived iv pb =>
      simp only [step] at hst ⊢
      split at hst
      · -- awaitingTransfer: nested guards on iv/pb
        split at hst
        · simp_all
        · split at hst <;> simp_all
      · simp_all
      · simp_all

theorem inv_foldl (evs : List Ev) (c : Ctx) (h : Inv c) : Inv (evs.foldl step c) := by
  induction evs generalizing c with
  | nil => simpa using h
  | cons e rest ih => simpa [List.foldl_cons] using ih (step c e) (step_preserves_inv c e h)

theorem inv_run (evs : List Ev) : Inv (run evs) :=
  inv_foldl evs init (by intro h; simp [init] at h)

/-- **Theorem (validate-before-accept).** A credential is accepted only if its issuer was valid. -/
theorem accepted_requires_valid_issuer (evs : List Ev) :
    (run evs).st = St.accepted → (run evs).issuerValid = true :=
  fun h => (inv_run evs h).1

/-- **Theorem (peer binding).** A credential is accepted only if the transfer was bound to this
    receiver — no forged or misdirected/replayed transfer is accepted. -/
theorem accepted_requires_peer_binding (evs : List Ev) :
    (run evs).st = St.accepted → (run evs).peerBound = true :=
  fun h => (inv_run evs h).2

end W2wModel
