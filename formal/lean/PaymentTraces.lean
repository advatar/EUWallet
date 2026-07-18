/-
  PaymentTraces — executable ORACLE for the payment SCA model (plan Section 10).

  Enumerates curated traces, runs them through the *proven* `PaymentModel`, and prints them as
  JSON. The Rust conformance test (crates/payment) replays each through `payment::model::step` and
  asserts the mirror matches the proven model exactly.

  Run:  lake exe payment_traces > ../../crates/payment/tests/model_traces.json
-/
import PaymentModel

open PaymentModel

def q (s : String) : String := "\"" ++ s ++ "\""
def boolJson (b : Bool) : String := if b then "true" else "false"

/-- Serialise a payment as JSON fields (embedded in a request event). -/
def payJson (p : Payment) : String :=
  q "payee" ++ ":" ++ q p.payee ++ "," ++
  q "amount" ++ ":" ++ toString p.amount ++ "," ++
  q "nonce" ++ ":" ++ toString p.nonce

def evJson : Ev → String
  | .request p => "{" ++ q "kind" ++ ":" ++ q "request" ++ "," ++ payJson p ++ "}"
  | .approve   => "{" ++ q "kind" ++ ":" ++ q "approve" ++ "}"
  | .decline   => "{" ++ q "kind" ++ ":" ++ q "decline" ++ "}"
  | .sign      => "{" ++ q "kind" ++ ":" ++ q "sign" ++ "}"

def stJson : St → String
  | .idle => "idle"
  | .awaitingConfirmation _ => "awaitingConfirmation"
  | .awaitingSca _ => "awaitingSca"
  | .authorized _ => "authorized"
  | .aborted => "aborted"

/-- Dynamic-linking flag: in the accepting state, is the auth code bound to the confirmed payment? -/
def boundFlag (c : Ctx) : Bool :=
  match c.st, c.confirmed with
  | .authorized p, some qy => decide (p = qy)
  | _, _ => false

def traceJson (evs : List Ev) : String :=
  let c := run evs
  let events := String.intercalate "," (evs.map evJson)
  let expect :=
    "{" ++ q "state" ++ ":" ++ q (stJson c.st) ++ "," ++
          q "approved" ++ ":" ++ boolJson c.approved ++ "," ++
          q "bound" ++ ":" ++ boolJson (boundFlag c) ++ "}"
  "{" ++ q "events" ++ ":[" ++ events ++ "]," ++ q "expect" ++ ":" ++ expect ++ "}"

def p1 : Payment := { payee := "Acme Store", amount := 1299, nonce := 7 }
def pZero : Payment := { payee := "Acme Store", amount := 0, nonce := 8 }

/-- Curated suite: happy path + each guard/branch the invariants cover. -/
def suite : List (List Ev) :=
  [ -- happy path: request → approve → sign ⇒ authorized, approved, dynamically linked
    [.request p1, .approve, .sign],
    -- user declines ⇒ aborted, never approved
    [.request p1, .decline],
    -- sign attempted before approval ⇒ no-op (stuck at confirmation), no auth code
    [.request p1, .sign],
    -- zero amount ⇒ aborted (guard: InvalidAmount)
    [.request pZero],
    -- just the confirmation, nothing authorised
    [.request p1]
  ]

def main : IO Unit := do
  let body := String.intercalate ",\n  " (suite.map traceJson)
  IO.println ("[\n  " ++ body ++ "\n]")
