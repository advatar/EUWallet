/-
  Traces — the executable ORACLE (plan Section 10).

  Enumerates a curated set of event traces, runs each through the *proven* model, and
  prints them as JSON on stdout. The Rust conformance test (crates/oid4vp) loads this JSON
  and replays each trace through `oid4vp::step`, asserting the Rust core's behaviour matches
  the model exactly. Because the core is sans-IO, this is deterministic.

  Run:  lake exe traces > ../../crates/oid4vp/tests/model_traces.json
-/
import WalletModel

open WalletModel

/-- Quote a string for JSON. -/
def q (s : String) : String := "\"" ++ s ++ "\""

/-- Serialise an event as a compact JSON object the Rust side can parse. -/
def evJson : Ev → String
  | .request n   => "{" ++ q "kind" ++ ":" ++ q "request" ++ "," ++ q "nonce" ++ ":" ++ toString n ++ "}"
  | .validateSig => "{" ++ q "kind" ++ ":" ++ q "validateSig" ++ "}"
  | .consent     => "{" ++ q "kind" ++ ":" ++ q "consent" ++ "}"
  | .disclose    => "{" ++ q "kind" ++ ":" ++ q "disclose" ++ "}"

/-- Serialise a state as a JSON string value. -/
def stJson : St → String
  | .idle            => "idle"
  | .requested       => "requested"
  | .validated       => "validated"
  | .awaitingConsent => "awaitingConsent"
  | .presenting      => "presenting"
  | .aborted         => "aborted"

def boolJson (b : Bool) : String := if b then "true" else "false"

/-- Serialise one (trace, expected-outcome) pair. -/
def traceJson (evs : List Ev) : String :=
  let c := run evs
  let events := String.intercalate "," (evs.map evJson)
  let expect :=
    "{" ++ q "state" ++ ":" ++ q (stJson c.st) ++ "," ++
          q "disclosed" ++ ":" ++ boolJson c.disclosed ++ "," ++
          q "sigValidated" ++ ":" ++ boolJson c.sigValidated ++ "," ++
          q "consented" ++ ":" ++ boolJson c.consented ++ "}"
  "{" ++ q "events" ++ ":[" ++ events ++ "]," ++ q "expect" ++ ":" ++ expect ++ "}"

/-- The curated conformance suite: happy path + each failure path the invariants cover. -/
def suite : List (List Ev) :=
  [ -- happy path: request → validate → consent → disclose ⇒ presenting
    [.request 1, .validateSig, .consent, .disclose],
    -- disclose attempted before consent ⇒ aborted (invariant 2)
    [.request 2, .validateSig, .disclose],
    -- disclose attempted before signature validation ⇒ aborted (invariant 1)
    [.request 3, .consent, .disclose],
    -- replayed nonce ⇒ aborted (invariant 3)
    [.request 4, .validateSig, .consent, .disclose, .request 4],
    -- nothing disclosed
    [.request 5, .validateSig]
  ]

def main : IO Unit := do
  let body := String.intercalate ",\n  " (suite.map traceJson)
  IO.println ("[\n  " ++ body ++ "\n]")
