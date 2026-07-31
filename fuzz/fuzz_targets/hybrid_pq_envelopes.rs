#![no_main]

use hybrid_pq::envelope::{decode_public_key, decode_signature};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_public_key(data);
    let _ = decode_signature(data);
});
