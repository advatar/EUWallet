/-
  HybridPqModel — Tier-2 formal model of the experimental hybrid-PQ verifier
  (plan Section 15, issue #92). Companion to the Tier-3
  `hybrid_pq_and_verification.spthy`.

  The SAME fail-closed decision structure that `crates/hybrid-pq` implements in
  Rust: a hybrid result is accepted ONLY IF both component signatures validated,
  both keys belong to one hybrid identity and generation, the profile and
  purpose match the negotiated session, and — when the session negotiated
  hybrid-required policy — no classical-only completion is possible. We prove:

    1. (AND verification)      acceptance requires BOTH components valid — one
                               valid component is insufficient, and removal or
                               substitution of a component cannot produce
                               acceptance;
    2. (single identity)       acceptance requires identity AND generation
                               match — mixed identities/generations cannot be
                               combined;
    3. (profile/purpose bind)  acceptance requires the negotiated profile and
                               exact purpose — cross-purpose replay is
                               rejected;
    4. (downgrade resistance)  a hybrid-required session can never end in
                               classical-only acceptance, and partial
                               completion never accepts.

  Same discipline as the other Tier-2 models; no `mathlib`.
-/

namespace HybridPqModel

inductive Ev where
  | negotiate (hybridRequired : Bool)
  | componentResult (classicalValid pqValid identityMatch generationMatch
      profileMatch purposeMatch : Bool)
  | classicalFallback
  deriving Repr

inductive St where
  | idle
  | negotiated
  | accepted            -- hybrid AND acceptance/terminal
  | acceptedClassical   -- classical-only completion (lawful only without hybrid-required)
  | rejected
  deriving DecidableEq, Repr

structure Ctx where
  st              : St
  hybridRequired  : Bool
  classicalValid  : Bool
  pqValid         : Bool
  identityMatch   : Bool
  generationMatch : Bool
  profileMatch    : Bool
  purposeMatch    : Bool
  deriving Repr

def init : Ctx :=
  { st := .idle, hybridRequired := false, classicalValid := false, pqValid := false,
    identityMatch := false, generationMatch := false, profileMatch := false,
    purposeMatch := false }

def step (c : Ctx) : Ev → Ctx
  | .negotiate hr =>
      match c.st with
      | .idle => { c with st := .negotiated, hybridRequired := hr }
      | _ => c
  | .componentResult cv qv im gm pm pu =>
      match c.st with
      | .negotiated =>
          -- AND verification: every check must pass or the whole result rejects.
          if cv && qv && im && gm && pm && pu then
            { c with st := .accepted, classicalValid := true, pqValid := true,
                     identityMatch := true, generationMatch := true,
                     profileMatch := true, purposeMatch := true }
          else
            { c with st := .rejected }
      | _ => c
  | .classicalFallback =>
      match c.st with
      | .negotiated =>
          -- Hybrid-required policy makes downgrade a hard rejection, never silent.
          if c.hybridRequired then { c with st := .rejected }
          else { c with st := .acceptedClassical }
      | _ => c

def run (evs : List Ev) : Ctx := evs.foldl step init

def Inv (c : Ctx) : Prop :=
  (c.st = St.accepted →
    c.classicalValid = true ∧ c.pqValid = true ∧ c.identityMatch = true ∧
    c.generationMatch = true ∧ c.profileMatch = true ∧ c.purposeMatch = true)
  ∧ (c.st = St.acceptedClassical → c.hybridRequired = false)

theorem step_preserves_inv (c : Ctx) (e : Ev) (h : Inv c) : Inv (step c e) := by
  obtain ⟨h1, h2⟩ := h
  constructor
  · intro hst
    cases e with
    | negotiate hr =>
        simp only [step] at hst ⊢
        split at hst <;> simp_all
    | componentResult cv qv im gm pm pu =>
        simp only [step] at hst ⊢
        split at hst
        · split at hst <;> simp_all
        · simp_all
    | classicalFallback =>
        simp only [step] at hst ⊢
        split at hst
        · split at hst <;> simp_all
        · simp_all
  · intro hst
    cases e with
    | negotiate hr =>
        simp only [step] at hst ⊢
        split at hst <;> simp_all
    | componentResult cv qv im gm pm pu =>
        simp only [step] at hst ⊢
        split at hst
        · split at hst <;> simp_all
        · simp_all
    | classicalFallback =>
        simp only [step] at hst ⊢
        split at hst
        · split at hst <;> simp_all
        · simp_all

theorem inv_foldl (evs : List Ev) (c : Ctx) (h : Inv c) : Inv (evs.foldl step c) := by
  induction evs generalizing c with
  | nil => simpa using h
  | cons e rest ih => simpa [List.foldl_cons] using ih (step c e) (step_preserves_inv c e h)

theorem inv_run (evs : List Ev) : Inv (run evs) := by
  refine inv_foldl evs init ⟨?_, ?_⟩ <;> intro h <;> simp [init] at h

/-- **Theorem (AND verification).** A hybrid result is accepted only if BOTH the
    classical and the post-quantum component validated. One valid component is
    formally insufficient; removing a component cannot produce acceptance. -/
theorem accepted_requires_both_components (evs : List Ev) :
    (run evs).st = St.accepted →
    (run evs).classicalValid = true ∧ (run evs).pqValid = true :=
  fun h => ⟨((inv_run evs).1 h).1, ((inv_run evs).1 h).2.1⟩

/-- **Theorem (single hybrid identity).** Acceptance requires both keys to
    belong to one hybrid identity AND one generation — mixed identities or
    generations cannot be combined. -/
theorem accepted_requires_one_identity_and_generation (evs : List Ev) :
    (run evs).st = St.accepted →
    (run evs).identityMatch = true ∧ (run evs).generationMatch = true :=
  fun h => ⟨((inv_run evs).1 h).2.2.1, ((inv_run evs).1 h).2.2.2.1⟩

/-- **Theorem (profile and purpose binding).** Acceptance requires the session's
    negotiated profile and the exact domain-separated purpose — a component
    substituted from another profile or replayed across purposes rejects. -/
theorem accepted_requires_negotiated_profile_and_purpose (evs : List Ev) :
    (run evs).st = St.accepted →
    (run evs).profileMatch = true ∧ (run evs).purposeMatch = true :=
  fun h => ⟨((inv_run evs).1 h).2.2.2.2.1, ((inv_run evs).1 h).2.2.2.2.2⟩

/-- **Theorem (downgrade resistance).** A session that negotiated
    hybrid-required policy can never end in classical-only acceptance. -/
theorem hybrid_required_never_downgrades (evs : List Ev) :
    (run evs).st = St.acceptedClassical → (run evs).hybridRequired = false :=
  fun h => (inv_run evs).2 h

end HybridPqModel
