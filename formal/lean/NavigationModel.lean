/-
  NavigationModel — Tier-2 formal model of the iOS app-shell navigation statechart.

  The SAME machine that `ios/Sources/WalletShell/Navigation.swift` (`NavigationMachine`) implements
  in Swift. This machine is deliberately **outside the certification core**: it routes screen
  *containment* (onboarding vs. home vs. the modal hosting a flow vs. settings/history/…), while the
  Rust core decides screen *content* and enforces every security invariant. So the properties here
  are about UX-flow safety and defense-in-depth, NOT security — the model intentionally carries no
  security state, exactly like the Swift machine it mirrors.

  We prove:

    1. (no dead-end)        `home` is reachable from EVERY state in one event — the user is never
                            trapped (`cancelled` always returns home);
    2. (cancel/complete)    `cancelled` and `presentationCompleted` return home from any state;
    3. (flow entry pinned)  the flow-hosting `presenting` state is entered ONLY via a deep link or a
                            consent-render milestone (`deepLinkArrived` / `startPresentation`);
    4. (onboarding is once) no event ever routes INTO `onboarding` from another state — once left,
                            it never recurs mid-session.

  The Swift side is bound to this exact transition table by an EXHAUSTIVE (state × event)
  conformance test (`ios/Tests/WalletShellTests/NavigationTests.swift`), so the proven properties
  transfer to the shipped code — the same model↔code discipline the core uses (plan Section 10).
  No `mathlib`.
-/

namespace NavigationModel

/-- The app-shell containers. Mirrors `NavigationMachine.State`. -/
inductive St where
  | onboarding
  | home
  | presenting
  | issuing
  | scanning
  | settings
  | history
  | catalogue
  deriving DecidableEq, Repr

/-- The coarse milestone events the shell derives from what the core rendered.
    Mirrors `NavigationMachine.Event`. -/
inductive Ev where
  | finishedOnboarding
  | startPresentation
  | startIssuance
  | openScanner
  | openSettings
  | openHistory
  | openCatalogue
  | presentationCompleted
  | cancelled
  | deepLinkArrived
  deriving DecidableEq, Repr

/-- The transition function — behaviourally identical to Swift's `send`. The two "from any state"
    events (`deepLinkArrived`/`startPresentation` → presenting, `presentationCompleted`/`cancelled`
    → home) are matched on the event alone; every other event advances only from `home` (or, for
    `finishedOnboarding`, only from `onboarding`), and is otherwise ignored (the state is kept). -/
def step (s : St) : Ev → St
  | .deepLinkArrived => .presenting
  | .startPresentation => .presenting
  | .presentationCompleted => .home
  | .cancelled => .home
  | .finishedOnboarding => match s with | .onboarding => .home | _ => s
  | .startIssuance => match s with | .home => .issuing | _ => s
  | .openScanner => match s with | .home => .scanning | _ => s
  | .openSettings => match s with | .home => .settings | _ => s
  | .openHistory => match s with | .home => .history | _ => s
  | .openCatalogue => match s with | .home => .catalogue | _ => s

def run (evs : List Ev) : St → St := fun s => evs.foldl step s

/-- **Theorem (cancel returns home).** `cancelled` returns to home from ANY state. -/
theorem cancel_returns_home (s : St) : step s .cancelled = .home := rfl

/-- **Theorem (completion returns home).** A finished flow returns to home from any state. -/
theorem complete_returns_home (s : St) : step s .presentationCompleted = .home := rfl

/-- **Theorem (flow entry via deep link).** A deep link presents from any state. -/
theorem deeplink_presents (s : St) : step s .deepLinkArrived = .presenting := rfl

/-- **Theorem (flow entry via consent).** A consent-render milestone presents from any state. -/
theorem consent_presents (s : St) : step s .startPresentation = .presenting := rfl

/-- **Theorem (no dead-end).** `home` is reachable from EVERY state in a single event — the user is
    never trapped in any screen. -/
theorem home_reachable (s : St) : ∃ e, step s e = .home :=
  ⟨.cancelled, cancel_returns_home s⟩

/-- **Theorem (flow entry is pinned).** You never ENTER the flow-hosting `presenting` state from a
    different state except via a deep link or a consent-render milestone. (Being already in
    `presenting` and ignoring an unrelated event trivially keeps you there — hence the `s =
    presenting` disjunct; the point is that no *other* state routes in by any other event.) -/
theorem presenting_entered_only_via_flow_entry (s : St) (e : Ev) :
    step s e = .presenting →
      s = .presenting ∨ e = .deepLinkArrived ∨ e = .startPresentation := by
  cases e <;> cases s <;> simp_all [step]

/-- **Theorem (onboarding is entered at most once).** No event routes INTO `onboarding` from a
    different state — once onboarding is left it never recurs mid-session. -/
theorem onboarding_not_reentered (s : St) (e : Ev) :
    step s e = .onboarding → s = .onboarding := by
  cases e <;> cases s <;> simp_all [step]

end NavigationModel
