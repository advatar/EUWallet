/-
  W2wTraces — executable ORACLE for the wallet-to-wallet receiver model (plan Section 10).

  Run:  lake exe w2w_traces > ../../crates/w2w/tests/model_traces.json
-/
import W2wModel

open W2wModel

def q (s : String) : String := "\"" ++ s ++ "\""
def boolJson (b : Bool) : String := if b then "true" else "false"

def evJson : Ev → String
  | .createOffer => "{" ++ q "kind" ++ ":" ++ q "createOffer" ++ "}"
  | .transferReceived iv pb =>
      "{" ++ q "kind" ++ ":" ++ q "transferReceived" ++ "," ++
        q "issuerValid" ++ ":" ++ boolJson iv ++ "," ++ q "peerBound" ++ ":" ++ boolJson pb ++ "}"

def stJson : St → String
  | .idle => "idle"
  | .awaitingTransfer => "awaitingTransfer"
  | .accepted => "accepted"
  | .rejected => "rejected"

def traceJson (evs : List Ev) : String :=
  let c := run evs
  let events := String.intercalate "," (evs.map evJson)
  let expect :=
    "{" ++ q "state" ++ ":" ++ q (stJson c.st) ++ "," ++
          q "issuerValid" ++ ":" ++ boolJson c.issuerValid ++ "," ++
          q "peerBound" ++ ":" ++ boolJson c.peerBound ++ "}"
  "{" ++ q "events" ++ ":[" ++ events ++ "]," ++ q "expect" ++ ":" ++ expect ++ "}"

def suite : List (List Ev) :=
  [ [.createOffer, .transferReceived true true],    -- accepted
    [.createOffer, .transferReceived false true],   -- rejected: issuer invalid
    [.createOffer, .transferReceived true false],   -- rejected: peer mismatch
    [.transferReceived true true],                  -- rejected: out of order (no offer)
    [.createOffer] ]                                -- awaiting, nothing accepted

def main : IO Unit := do
  let body := String.intercalate ",\n  " (suite.map traceJson)
  IO.println ("[\n  " ++ body ++ "\n]")
