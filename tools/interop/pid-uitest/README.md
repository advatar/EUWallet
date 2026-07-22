# Live PID issuance — headless UI test (EU reference issuer)

Answers the question "can the eID/authorization step be automated instead of done by a human?"
**For the EU *reference* issuer (`issuer.eudiw.dev`): yes.** Its authentication is a plain web form
("Test Credentials Provider" → *FormEU* → a PID data form → a "Review & Send" **Authorize** page),
not a hardware eID/NFC flow. This Playwright test drives that form end to end, headless, with
**synthetic** test data, and captures the OpenID4VCI authorization `code` from the redirect.

> The German **production** path (AusweisApp + a real eID card over NFC) is different and genuinely
> needs hardware/a human — this harness is for the reference/sandbox issuer only.

## Run

```sh
npm ci
npm run check
npx playwright install chromium
ATTEMPTS=6 node issue-pid.js      # prints {"code":...,"verifier":...,...} on success
```

## What it does (all machine-driven)

1. PKCE S256 + Pushed Authorization Request as a **public client** (`scope=eu.europa.ec.eudi.pid_vc_sd_jwt`).
2. Opens the authorization URL; follows the issuer's self-submitting redirect forms.
3. Selects **FormEU** on the country page.
4. Fills the mandatory PID attributes (family/given name, birthdate, nationality, place of birth).
5. Confirms → reaches the issuer's **Review & Send** page → clicks **Authorize**.
6. Captures `?code=…&state=…` from the `https://example.com/cb` redirect.

The captured `code` + PKCE `verifier` feed the token + credential legs (DPoP, ES256 proof), which
are owned by the Rust core's OID4VCI/HAIP transport — not reimplemented here.

## Status / caveat (honest)

Verified live that the harness reaches the issuer's **Authorize** consent page with the real PID
preview rendered. Capturing the final `code` depends on the reference issuer's `/dynamic/form`
endpoint, which currently returns intermittent **HTTP 500s** (a server-side reliability issue on
`eudiw.dev`, not this wallet). The script retries with backoff; rerun when the service is healthy.
No conformance or certification pass is implied.
