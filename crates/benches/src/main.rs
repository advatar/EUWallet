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

    #[cfg(feature = "experimental-pq")]
    bench_experimental_pq();

    println!(
        "\nNote: these are core-operation micro-benchmarks. End-to-end flow latency is dominated"
    );
    println!(
        "by the ES256 operations above plus a single TLS round-trip (platform), not by parsing."
    );
}

/// Experimental hybrid-PQ primitive and codec budgets (plan section 16, issue #93). Uses the
/// REAL RustCrypto ml-dsa/ml-kem backends behind `experimental-pq-primitives`; wire sizes are
/// printed so the documented message-size budgets stay tied to measurements.
#[cfg(feature = "experimental-pq")]
fn bench_experimental_pq() {
    use crypto_backend::experimental_pq::{
        encapsulate_ml_kem_768, verify_ml_dsa_65, MlDsa65SecretKey, MlKem768SecretKey,
    };
    use hybrid_pq::envelope::{decode_signature, encode_signature, HybridSignatureEnvelope};
    use hybrid_pq::tbs::HybridPurpose;
    use hybrid_pq::{HybridSignature, HybridSignatureProfile};

    println!("\n## Experimental hybrid-PQ (feature experimental-pq)\n");
    println!("| Operation | Mean latency | Throughput (ops/sec) |");
    println!("|---|---|---|");

    bench("ML-DSA-65 keygen", || {
        MlDsa65SecretKey::generate().expect("keygen")
    });
    let dsa = MlDsa65SecretKey::generate().expect("keygen");
    let dsa_pk = dsa.public_key();
    let message = [0x5au8; 64];
    bench("ML-DSA-65 sign (64 B)", || {
        dsa.sign(black_box(&message)).expect("sign")
    });
    let dsa_sig = dsa.sign(&message).expect("sign");
    bench("ML-DSA-65 verify (64 B)", || {
        verify_ml_dsa_65(&dsa_pk, black_box(&message), &dsa_sig).expect("verify")
    });

    bench("ML-KEM-768 keygen", || {
        MlKem768SecretKey::generate().expect("keygen")
    });
    let kem = MlKem768SecretKey::generate().expect("keygen");
    let kem_pk = kem.public_key();
    bench("ML-KEM-768 encapsulate", || {
        encapsulate_ml_kem_768(black_box(&kem_pk)).expect("encapsulate")
    });
    let (kem_ct, _shared) = encapsulate_ml_kem_768(&kem_pk).expect("encapsulate");
    bench("ML-KEM-768 decapsulate", || {
        kem.decapsulate(black_box(&kem_ct)).expect("decapsulate")
    });

    let hybrid_signature = HybridSignature::try_new(
        HybridSignatureProfile::Es256MlDsa65V1,
        vec![0x11; hybrid_pq::ES256_SIGNATURE_BYTES],
        dsa_sig.clone(),
    )
    .expect("hybrid signature components");
    let envelope =
        HybridSignatureEnvelope::new(HybridPurpose::TestSdJwtWrapperV1, hybrid_signature);
    let encoded = encode_signature(&envelope);
    bench("Hybrid signature envelope encode", || {
        encode_signature(black_box(&envelope))
    });
    bench("Hybrid signature envelope decode", || {
        decode_signature(black_box(&encoded)).expect("decode")
    });

    println!("\n### Wire sizes (message-size budget inputs)\n");
    println!("| Artifact | Bytes |");
    println!("|---|---|");
    println!("| ML-DSA-65 public key | {} |", dsa_pk.len());
    println!("| ML-DSA-65 signature | {} |", dsa_sig.len());
    println!("| ML-KEM-768 encapsulation key | {} |", kem_pk.len());
    println!("| ML-KEM-768 ciphertext | {} |", kem_ct.len());
    println!("| Hybrid signature envelope | {} |", encoded.len());
    println!(
        "| Envelope hard cap (MAX_ENVELOPE_BYTES) | {} |",
        hybrid_pq::envelope::MAX_ENVELOPE_BYTES
    );
}

#[cfg(test)]
mod budget_tests {
    use hybrid_pq::envelope::{encode_signature, HybridSignatureEnvelope, MAX_ENVELOPE_BYTES};
    use hybrid_pq::tbs::HybridPurpose;
    use hybrid_pq::{HybridSignature, HybridSignatureProfile};

    /// Storage/message budget (docs/experimental-pq-performance-budgets.md): the maximal
    /// signature envelope stays within the 8 KiB hard cap and its wire size stays pinned, so a
    /// codec change that silently grows stored or transported hybrid artifacts fails here.
    #[test]
    fn maximal_signature_envelope_respects_the_storage_budget() {
        let signature = HybridSignature::try_new(
            HybridSignatureProfile::Es256MlDsa65V1,
            vec![0x11; hybrid_pq::ES256_SIGNATURE_BYTES],
            vec![0x22; hybrid_pq::ML_DSA_65_SIGNATURE_BYTES],
        )
        .expect("fixed-size components");
        let mut max_wire = 0;
        for purpose in [
            HybridPurpose::WalletExportV1,
            HybridPurpose::WalletRecoveryV1,
            HybridPurpose::PrivateProviderMessageV1,
            HybridPurpose::TestSdJwtWrapperV1,
            HybridPurpose::TestMdocWrapperV1,
        ] {
            let encoded =
                encode_signature(&HybridSignatureEnvelope::new(purpose, signature.clone()));
            assert!(encoded.len() <= MAX_ENVELOPE_BYTES);
            max_wire = max_wire.max(encoded.len());
        }
        assert_eq!(max_wire, 3_473);
    }
}
