/-
  ProximityTraces — executable ORACLE for the ISO 18013-5 proximity model (plan Section 10).

  Run:  lake exe proximity_traces > ../../crates/iso18013-5/tests/model_traces.json
-/
import ProximityModel

open ProximityModel

def q (s : String) : String := "\"" ++ s ++ "\""
def boolJson (b : Bool) : String := if b then "true" else "false"

def evJson : Ev → String
  | .startEngagement    => "{" ++ q "kind" ++ ":" ++ q "startEngagement" ++ "}"
  | .readerEstablish v  => "{" ++ q "kind" ++ ":" ++ q "readerEstablish" ++ "," ++ q "valid" ++ ":" ++ boolJson v ++ "}"
  | .consentGrant       => "{" ++ q "kind" ++ ":" ++ q "consentGrant" ++ "}"
  | .consentDecline     => "{" ++ q "kind" ++ ":" ++ q "consentDecline" ++ "}"
  | .deviceSign         => "{" ++ q "kind" ++ ":" ++ q "deviceSign" ++ "}"
  | .terminate          => "{" ++ q "kind" ++ ":" ++ q "terminate" ++ "}"

def stJson : St → String
  | .idle => "idle"
  | .engaged => "engaged"
  | .sessionEstablished => "sessionEstablished"
  | .signingResponse => "signingResponse"
  | .responded => "responded"
  | .aborted => "aborted"
  | .terminated => "terminated"

def traceJson (evs : List Ev) : String :=
  let c := run evs
  let events := String.intercalate "," (evs.map evJson)
  let expect :=
    "{" ++ q "state" ++ ":" ++ q (stJson c.st) ++ "," ++
          q "sessionBound" ++ ":" ++ boolJson c.sessionBound ++ "," ++
          q "consented" ++ ":" ++ boolJson c.consented ++ "}"
  "{" ++ q "events" ++ ":[" ++ events ++ "]," ++ q "expect" ++ ":" ++ expect ++ "}"

/-- Curated suite covering the happy path and each guard. -/
def suite : List (List Ev) :=
  [ -- happy path: engage → establish(valid) → consent → sign ⇒ responded
    [.startEngagement, .readerEstablish true, .consentGrant, .deviceSign],
    -- reader/transcript invalid ⇒ aborted, never a bound session
    [.startEngagement, .readerEstablish false],
    -- consent declined ⇒ aborted
    [.startEngagement, .readerEstablish true, .consentDecline],
    -- consent BEFORE session established ⇒ aborted (ordering)
    [.startEngagement, .consentGrant],
    -- reader terminates ⇒ terminated
    [.startEngagement, .readerEstablish true, .terminate],
    -- session established but no consent/response yet
    [.startEngagement, .readerEstablish true]
  ]

def main : IO Unit := do
  let body := String.intercalate ",\n  " (suite.map traceJson)
  IO.println ("[\n  " ++ body ++ "\n]")
