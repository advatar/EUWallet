/-
  IssuanceModel — Tier-2 formal model of the OID4VCI issuance state machine.

  The SAME machine that `crates/oid4vci` implements in Rust: a credential offer whose issuer trust
  is decided IN-CORE against the trusted list, a sender-bound token, and a device proof-of-
  possession whose key must be attested (the Wallet Unit Attestation must verify AND bind the
  device key at High assurance — never a shell boolean). We prove:

    1. (issuer trust)      no credential is accepted unless the issuer was trusted in-core;
    2. (token binding)     no credential is accepted over a token that was not sender-bound;
    3. (key attestation)   no credential is accepted unless the proof key was attested (WUA High).

  Same style as the other Tier-2 models; no `mathlib`.
-/

namespace IssuanceModel

inductive Ev where
  | offer (issuerTrusted : Bool)
  | approveOffer
  | token (bound attested : Bool)   -- sender-bound token + proof-key attested (WUA High)
  | proof                           -- device proof-of-possession assembled
  | credential (valid portraitProfileValid : Bool)
  deriving Repr

/-- Machine states (mirror of the security-relevant subset of `oid4vci::State`). -/
inductive St where
  | idle
  | reviewingOffer
  | offerParsed
  | provingPossession
  | requestingCredential
  | credentialIssued        -- accepting/terminal
  | aborted
  deriving DecidableEq, Repr

/-- Holder-visible issuance journey derived from the security state. Native shells render this
    projection; they do not independently decide whether an offer is approved or a document is
    ready. -/
inductive Ui where
  | hidden
  | review
  | preparing
  | ready
  | recovery
  deriving DecidableEq, Repr

def uiFor : St → Ui
  | .idle => .hidden
  | .reviewingOffer => .review
  | .offerParsed | .provingPossession | .requestingCredential => .preparing
  | .credentialIssued => .ready
  | .aborted => .recovery

structure Ctx where
  st              : St
  issuerTrusted   : Bool
  tokenBound      : Bool
  proofKeyAttested : Bool
  portraitProfileValid : Bool
  holderApproved : Bool
  deriving Repr

def init : Ctx :=
  { st := .idle, issuerTrusted := false, tokenBound := false, proofKeyAttested := false,
    portraitProfileValid := false, holderApproved := false }

def step (c : Ctx) : Ev → Ctx
  | .offer trusted =>
      match c.st with
      | .idle =>
          if trusted then { c with st := .reviewingOffer, issuerTrusted := true }
          else { c with st := .aborted }                              -- guard: IssuerNotTrusted
      | _ => c
  | .approveOffer =>
      match c.st with
      | .reviewingOffer => { c with st := .offerParsed, holderApproved := true }
      | _ => c
  | .token bound attested =>
      match c.st with
      | .offerParsed =>
          if !bound then { c with st := .aborted }                    -- guard: TokenNotBound
          else if !attested then { c with st := .aborted }            -- guard: ProofKeyNotAttested
          else { c with st := .provingPossession, tokenBound := true, proofKeyAttested := true }
      | _ => c
  | .proof =>
      match c.st with
      | .provingPossession => { c with st := .requestingCredential }
      | _ => c
  | .credential valid portraitValid =>
      match c.st with
      | .requestingCredential =>
          if valid && portraitValid then
            { c with st := .credentialIssued, portraitProfileValid := true }
          else { c with st := .aborted }                              -- guard: CredentialInvalid
      | _ => c

def run (evs : List Ev) : Ctx := evs.foldl step init

/-! ## Inductive invariant carrying the three security facts to the accepting state. -/

def Inv (c : Ctx) : Prop :=
  (c.st = St.reviewingOffer → c.issuerTrusted = true) ∧
  (c.st = St.offerParsed → c.issuerTrusted = true ∧ c.holderApproved = true) ∧
  (c.st = St.provingPossession →
      c.issuerTrusted = true ∧ c.tokenBound = true ∧ c.proofKeyAttested = true ∧
        c.holderApproved = true) ∧
  (c.st = St.requestingCredential →
      c.issuerTrusted = true ∧ c.tokenBound = true ∧ c.proofKeyAttested = true ∧
        c.holderApproved = true) ∧
  (c.st = St.credentialIssued →
      c.issuerTrusted = true ∧ c.tokenBound = true ∧ c.proofKeyAttested = true ∧
        c.portraitProfileValid = true ∧ c.holderApproved = true)

theorem step_preserves_inv (c : Ctx) (e : Ev) (h : Inv c) : Inv (step c e) := by
  obtain ⟨h1, h2, h3, h4, h5⟩ := h
  cases e with
  | offer trusted =>
      simp only [step]; split
      · split
        · refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intro hst <;> simp_all
        · refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intro hst <;> simp_all
      · exact ⟨h1, h2, h3, h4, h5⟩
  | approveOffer =>
      simp only [step]; split
      · rename_i hst; refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intro hnew <;> simp_all [h1 hst]
      · exact ⟨h1, h2, h3, h4, h5⟩
  | token bound attested =>
      simp only [step]; split
      · rename_i hst
        split
        · refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intro hnew <;> simp_all
        · split
          · refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intro hnew <;> simp_all
          · refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intro hnew <;> simp_all [h2 hst]
      · exact ⟨h1, h2, h3, h4, h5⟩
  | proof =>
      simp only [step]; split
      · rename_i hst; refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intro hnew <;> simp_all [h3 hst]
      · exact ⟨h1, h2, h3, h4, h5⟩
  | credential valid portraitValid =>
      simp only [step]; split
      · rename_i hst
        split
        · refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intro hnew <;> simp_all [h4 hst]
        · refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intro hnew <;> simp_all
      · exact ⟨h1, h2, h3, h4, h5⟩

theorem inv_foldl (evs : List Ev) (c : Ctx) (h : Inv c) : Inv (evs.foldl step c) := by
  induction evs generalizing c with
  | nil => simpa using h
  | cons e rest ih => simpa [List.foldl_cons] using ih (step c e) (step_preserves_inv c e h)

theorem inv_run (evs : List Ev) : Inv (run evs) :=
  inv_foldl evs init (by refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intro h <;> simp [init] at h)

/-- **Theorem (issuer trust).** A credential is accepted only if the issuer was trusted in-core. -/
theorem issued_requires_issuer_trust (evs : List Ev) :
    (run evs).st = St.credentialIssued → (run evs).issuerTrusted = true :=
  fun h => ((inv_run evs).2.2.2.2 h).1

/-- **Theorem (token binding).** A credential is accepted only over a sender-bound token. -/
theorem issued_requires_bound_token (evs : List Ev) :
    (run evs).st = St.credentialIssued → (run evs).tokenBound = true :=
  fun h => ((inv_run evs).2.2.2.2 h).2.1

/-- **Theorem (key attestation).** A credential is accepted only if the proof key was attested
    (the WUA verified and bound the device key at High assurance). -/
theorem issued_requires_attested_key (evs : List Ev) :
    (run evs).st = St.credentialIssued → (run evs).proofKeyAttested = true :=
  fun h => ((inv_run evs).2.2.2.2 h).2.2.1

/-- **Theorem (PID portrait profile).** An issued PID passed the mandatory portrait gate. -/
theorem issued_requires_valid_portrait_profile (evs : List Ev) :
    (run evs).st = St.credentialIssued → (run evs).portraitProfileValid = true :=
  fun h => ((inv_run evs).2.2.2.2 h).2.2.2.1

/-- An issued credential always follows explicit holder approval of the reviewed offer. -/
theorem issued_requires_holder_approval (evs : List Ev) :
    (run evs).st = St.credentialIssued → (run evs).holderApproved = true :=
  fun h => ((inv_run evs).2.2.2.2 h).2.2.2.2

/-- The consumer completion screen is reachable exactly from the accepting protocol state. -/
theorem issued_renders_ready (evs : List Ev) :
    (run evs).st = St.credentialIssued → uiFor (run evs).st = Ui.ready := by
  intro h
  simp [uiFor, h]

/-- A preparing screen after offer parsing is always backed by explicit holder approval. -/
theorem offer_parsed_preparing_requires_approval (evs : List Ev) :
    (run evs).st = St.offerParsed →
      uiFor (run evs).st = Ui.preparing ∧ (run evs).holderApproved = true := by
  intro h
  exact ⟨by simp [uiFor, h], ((inv_run evs).2.1 h).2⟩

/-- **Theorem (issuer-trust gate).** An offer from an untrusted issuer is rejected. -/
theorem untrusted_issuer_is_rejected (c : Ctx) (h : c.st = St.idle) :
    (step c (.offer false)).st = St.aborted := by
  simp [step, h]

end IssuanceModel
