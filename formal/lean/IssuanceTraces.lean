/-
  IssuanceTraces — executable ORACLE for the OID4VCI issuance model (plan Section 10).

  Run:  lake exe issuance_traces > ../../crates/oid4vci/tests/model_traces.json
-/
import IssuanceModel

open IssuanceModel

def q (s : String) : String := "\"" ++ s ++ "\""
def boolJson (b : Bool) : String := if b then "true" else "false"

def evJson : Ev → String
  | .offer t        => "{" ++ q "kind" ++ ":" ++ q "offer" ++ "," ++ q "issuerTrusted" ++ ":" ++ boolJson t ++ "}"
  | .approveOffer   => "{" ++ q "kind" ++ ":" ++ q "approveOffer" ++ "}"
  | .token b a      => "{" ++ q "kind" ++ ":" ++ q "token" ++ "," ++ q "bound" ++ ":" ++ boolJson b ++ "," ++ q "attested" ++ ":" ++ boolJson a ++ "}"
  | .proof          => "{" ++ q "kind" ++ ":" ++ q "proof" ++ "}"
  | .credential v p => "{" ++ q "kind" ++ ":" ++ q "credential" ++ "," ++ q "valid" ++ ":" ++ boolJson v ++ "," ++ q "portraitProfileValid" ++ ":" ++ boolJson p ++ "}"

def stJson : St → String
  | .idle => "idle"
  | .reviewingOffer => "reviewingOffer"
  | .offerParsed => "offerParsed"
  | .provingPossession => "provingPossession"
  | .requestingCredential => "requestingCredential"
  | .credentialIssued => "credentialIssued"
  | .aborted => "aborted"

def traceJson (evs : List Ev) : String :=
  let c := run evs
  let events := String.intercalate "," (evs.map evJson)
  let expect :=
    "{" ++ q "state" ++ ":" ++ q (stJson c.st) ++ "," ++
          q "issuerTrusted" ++ ":" ++ boolJson c.issuerTrusted ++ "," ++
          q "tokenBound" ++ ":" ++ boolJson c.tokenBound ++ "," ++
          q "proofKeyAttested" ++ ":" ++ boolJson c.proofKeyAttested ++ "," ++
          q "portraitProfileValid" ++ ":" ++ boolJson c.portraitProfileValid ++ "," ++
          q "holderApproved" ++ ":" ++ boolJson c.holderApproved ++ "}"
  "{" ++ q "events" ++ ":[" ++ events ++ "]," ++ q "expect" ++ ":" ++ expect ++ "}"

/-- Curated suite covering the happy path and each security guard. -/
def suite : List (List Ev) :=
  [ -- happy path: trusted offer → bound+attested token → proof → valid credential ⇒ issued
    [.offer true, .approveOffer, .token true true, .proof, .credential true true],
    -- no protocol work is admitted until the holder approves the reviewed offer
    [.offer true, .token true true, .proof, .credential true true],
    -- untrusted issuer ⇒ aborted immediately
    [.offer false],
    -- token not sender-bound ⇒ aborted (guard: TokenNotBound)
    [.offer true, .approveOffer, .token false true],
    -- proof key not attested (WUA) ⇒ aborted (guard: ProofKeyNotAttested)
    [.offer true, .approveOffer, .token true false],
    -- invalid credential ⇒ aborted
    [.offer true, .approveOffer, .token true true, .proof, .credential false true],
    -- missing or malformed mandatory portrait ⇒ aborted
    [.offer true, .approveOffer, .token true true, .proof, .credential true false],
    -- proof-of-possession stage reached, not yet issued
    [.offer true, .approveOffer, .token true true, .proof]
  ]

def main : IO Unit := do
  let body := String.intercalate ",\n  " (suite.map traceJson)
  IO.println ("[\n  " ++ body ++ "\n]")
