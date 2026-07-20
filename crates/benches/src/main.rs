//! Performance benchmarks for the wallet's hot paths — dependency-free (std only), so the
//! minimal-dependency budget and `cargo deny` are unaffected. Each row reports mean latency and
//! throughput over an auto-sized sample against the REAL aws-lc-rs backend (no mock crypto).
//!
//! Run: `cargo run -p benches --release`   (release is required for meaningful numbers)

use std::hint::black_box;
use std::time::Instant;

use cose::cbor::Value;
use crypto_backend::{AwsLc, SoftwareSigner};
use crypto_traits::{Alg, Digest, KeyRef, Signer, Verifier};

/// Warm up, then run batches until ~`budget_ms` have elapsed; report mean ns/op and ops/sec.
fn bench<R>(name: &str, f: impl Fn() -> R) {
    let budget_ms = 350u128;
    for _ in 0..2_000 {
        black_box(f());
    }
    let mut iters: u64 = 0;
    let start = Instant::now();
    while start.elapsed().as_millis() < budget_ms {
        for _ in 0..500 {
            black_box(f());
        }
        iters += 500;
    }
    let ns = start.elapsed().as_nanos() as f64 / iters as f64;
    let per_sec = 1e9 / ns;
    let latency = if ns >= 1000.0 {
        format!("{:.2} µs", ns / 1000.0)
    } else {
        format!("{ns:.0} ns")
    };
    println!("| {name} | {latency} | {per_sec:.0} |");
}

fn main() {
    let profile = if cfg!(debug_assertions) {
        "debug (NOT representative — use --release)"
    } else {
        "release"
    };
    println!("# Wallet performance benchmarks\n");
    println!("Backend: aws-lc-rs (real crypto). Build profile: {profile}.");
    println!("Sample: auto-sized (~350 ms/bench after 2000-iter warmup). Single-threaded.\n");
    println!("| Operation | Mean latency | Throughput (ops/sec) |");
    println!("|---|---|---|");

    let aws = AwsLc;

    // --- Hashing ---
    let msg32 = [0x5au8; 32];
    let msg1k = vec![0x5au8; 1024];
    bench("SHA-256 (32 B)", || aws.sha256(black_box(&msg32)));
    bench("SHA-256 (1 KiB)", || aws.sha256(black_box(&msg1k)));

    // --- Signatures (P-256 / ES256) ---
    let signer = SoftwareSigner::generate_p256().expect("keygen");
    let key = KeyRef("bench-key".into());
    let payload = b"DeviceAuthenticationBytes-representative-signing-input-0123456789".to_vec();
    bench("ES256 sign (P-256)", || {
        signer
            .sign(&key, Alg::Es256, black_box(&payload))
            .expect("sign")
    });
    let sig = signer.sign(&key, Alg::Es256, &payload).expect("sign");
    let pk = signer.public_key_raw().to_vec();
    bench("ES256 verify (P-256)", || {
        aws.verify(Alg::Es256, &pk, black_box(&payload), &sig)
            .is_ok()
    });

    // --- Canonical CBOR (the mdoc/COSE codec hot path) ---
    let item = Value::Map(vec![
        (Value::Text("digestID".into()), Value::Uint(3)),
        (Value::Text("random".into()), Value::Bytes(vec![0x11u8; 16])),
        (
            Value::Text("elementIdentifier".into()),
            Value::Text("family_name".into()),
        ),
        (
            Value::Text("elementValue".into()),
            Value::Text("Andersson".into()),
        ),
    ]);
    bench(
        "Canonical CBOR encode (IssuerSignedItem-shaped map)",
        || black_box(&item).to_canonical(),
    );

    // --- SD-JWT VC structural parse (combined serialization split + shape checks) ---
    let compact = format!(
        "{}.{}.{}~{}~{}~",
        "e".repeat(40),
        "e".repeat(320),
        "e".repeat(86),
        "e".repeat(64),
        "e".repeat(64),
    );
    bench("SD-JWT VC parse (2 disclosures)", || {
        sdjwt::SdJwtVc::parse(black_box(&compact)).expect("parse")
    });

    println!(
        "\nNote: these are core-operation micro-benchmarks. End-to-end flow latency is dominated"
    );
    println!(
        "by the ES256 operations above plus a single TLS round-trip (platform), not by parsing."
    );
}
