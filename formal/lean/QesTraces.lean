/-
  QesTraces — executable ORACLE for the QES authorization model (plan Section 10).

  Run:  lake exe qes_traces > ../../crates/qes/tests/model_traces.json
-/
import QesModel

open QesModel

def q (s : String) : String := "\"" ++ s ++ "\""
def boolJson (b : Bool) : String := if b then "true" else "false"

def docJson (d : Doc) : String :=
  q "docId" ++ ":" ++ toString d.docId ++ "," ++ q "nonce" ++ ":" ++ toString d.nonce

def evJson : Ev → String
  | .request d => "{" ++ q "kind" ++ ":" ++ q "request" ++ "," ++ docJson d ++ "}"
  | .authorize => "{" ++ q "kind" ++ ":" ++ q "authorize" ++ "}"
  | .decline   => "{" ++ q "kind" ++ ":" ++ q "decline" ++ "}"
  | .sign      => "{" ++ q "kind" ++ ":" ++ q "sign" ++ "}"

def stJson : St → String
  | .idle => "idle"
  | .awaitingAuthorization _ => "awaitingAuthorization"
  | .awaitingSca _ => "awaitingSca"
  | .signed _ => "signed"
  | .aborted => "aborted"

/-- WYSIWYS flag: in the accepting state, is the signature bound to the confirmed document? -/
def boundFlag (c : Ctx) : Bool :=
  match c.st, c.confirmed with
  | .signed d, some e => decide (d = e)
  | _, _ => false

def traceJson (evs : List Ev) : String :=
  let c := run evs
  let events := String.intercalate "," (evs.map evJson)
  let expect :=
    "{" ++ q "state" ++ ":" ++ q (stJson c.st) ++ "," ++
          q "authorized" ++ ":" ++ boolJson c.authorized ++ "," ++
          q "bound" ++ ":" ++ boolJson (boundFlag c) ++ "}"
  "{" ++ q "events" ++ ":[" ++ events ++ "]," ++ q "expect" ++ ":" ++ expect ++ "}"

def d1 : Doc := { docId := 42, nonce := 3 }
def dMissing : Doc := { docId := 0, nonce := 4 }

def suite : List (List Ev) :=
  [ [.request d1, .authorize, .sign],       -- happy: signed, authorized, bound
    [.request d1, .decline],                -- declined ⇒ aborted
    [.request d1, .sign],                   -- sign before authorize ⇒ no-op (stuck)
    [.request dMissing],                    -- missing document hash ⇒ aborted
    [.request d1] ]                         -- confirmation only

def main : IO Unit := do
  let body := String.intercalate ",\n  " (suite.map traceJson)
  IO.println ("[\n  " ++ body ++ "\n]")
