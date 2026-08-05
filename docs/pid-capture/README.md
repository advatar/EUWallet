# Cross-Wallet PID Issuance via App Clip — technical overview

`pid-capture-appclip-flow.pdf` explains how any wallet obtains a PID by launching the
**PID Capture** companion (app or App Clip): iProov liveness → eMRTD chip read over the
`service-nfc` relay → issuer validation → PID minted back into the requesting wallet.

## Regenerate

Source: `pid-capture-appclip-flow.html` (mermaid diagrams + a live-rendered QR + the real
Test Wallet screenshot in `assets/`; the device-only screens are labelled representative mockups).

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless=new --disable-gpu --no-pdf-header-footer \
  --virtual-time-budget=25000 --run-all-compositor-stages-before-draw \
  --print-to-pdf=pid-capture-appclip-flow.pdf \
  file://$PWD/pid-capture-appclip-flow.html
```

The device screens (MRZ scan, iProov liveness, NFC read, issued) are mockups because PID Capture
runs only on a physical device (iProov + CoreNFC are unavailable in the Simulator). Swap in real
screenshots under `assets/` and re-render for a production version.
