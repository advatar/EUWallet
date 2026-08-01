# Experimental hybrid-PQ physical-device evidence

This record covers the non-interactive portion of the issue #95 hardware closure run. The profile
remains experimental, disabled by default, and outside certified EUDI paths.

## Run identity

- Timestamp: 2026-08-01 19:24 CEST
- Device: iPhone 15 Pro (`iPhone16,1` / `D83AP`)
- OS: iOS 26.5.2 (`23F84`)
- Xcode destination: physical iPhone; simulator paths are rejected by the test harness
- Result bundle: `euwallet-pq-95-physical-v2.xcresult`
- Archived result SHA-256: `5643f642c114cb728eb797e61d2b3483a89d0f7f48a5c23fe489473c7413e30f`

The raw result bundle is retained with the qualification workspace rather than committed because it
contains physical-device identifiers. The digest above is the integrity anchor for the archive.

## Results

`PhysicalHybridPqEvidenceTests` executed four tests: three passed and the explicitly interactive
biometric test skipped because no `EUWALLET_PQ_BIOMETRIC_ACTION` was supplied.

- Real ML-DSA backend correctness and resource measurement passed.
- Four concurrent real-backend operations completed in 2 ms, below the 100 ms hard bound.
- Secure Enclave/Keychain custody generation and rotation passed; the public-key hash changed.
- Only encrypted seed material was persisted and it was excluded from backup.
- Missing wrapping-key and stale-generation rollback attempts failed closed.

The five measured backend samples averaged 0.001 seconds monotonic time, 0.001 seconds CPU time,
3,013.990 kcycles, and 19,815.754 kB peak physical memory. These are XCTest measurements of the
bounded backend operation, not a claim about whole-app energy use.

## Remaining interactive gates

This run does not close biometric approval, biometric cancellation, locked-device access, or the
documented battery/thermal observation. Run the test twice with
`EUWALLET_PQ_BIOMETRIC_ACTION=approve` and `EUWALLET_PQ_BIOMETRIC_ACTION=cancel`, then execute the
locked-device and battery/thermal matrix before marking the hardware closure gate complete.
