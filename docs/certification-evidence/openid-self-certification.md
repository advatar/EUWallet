# OpenID Foundation self-certification

Status: **not submitted**. This file is a launch gate and must not be read as a
conformance or certification claim.

## Required scope

The release candidate must run the OpenID Foundation Conformance Suite against
the exact production profiles we ship:

- OpenID4VP 1.0, including HAIP 1.0 SD-JWT VC and ISO mdoc profiles;
- OpenID4VCI 1.0, including the HAIP issuance profiles we expose; and
- every enabled client-authentication, redirect, response-mode, and credential
  format variant.

The profile matrix is version-pinned in `docs/normative-baselines.md`. A green
local unit or integration test is not a substitute for the Foundation suite.

## Evidence required for submission

For each submitted profile, retain an immutable evidence bundle under
`docs/certification-evidence/oidf/<release>/` (or in the controlled release
evidence store) containing:

1. the suite commit/release, test-plan identifier, and normative-profile hashes;
2. the conformance configuration with secrets, tokens, and personal data
   removed;
3. the complete machine result, including negative tests and any permitted
   exclusions with written justification;
4. the wallet build identifier, source revision, platform/OS, feature flags,
   endpoints, certificates, and trust-list snapshot used; and
5. the submitted self-certification URL/identifier, reviewer, date, and
   expiry or re-run trigger.

Results must be signed or checksummed and retained with the release SBOM. Never
commit live credentials or user data. A failed or partial run remains evidence
of an open gate; it must not be converted into a pass by editing the report.

## Renewal and change control

Re-run before launch and whenever a normative profile, conformance-suite
version, OpenID client behavior, cryptographic algorithm, redirect/transport
boundary, credential format, or platform shell changes. Security fixes that
change wire behavior require a new result. The release checklist must block
promotion when the result does not match the shipped commit and configuration.

## Current gap

`tools/interop/probe.sh` only checks reference-environment reachability and
metadata shape. It explicitly does **not** run the OIDF suite. The production
OpenID4VCI adapter, real issuance/presentation round trips, pinned trust
anchors, and the external Foundation submission remain outstanding.
