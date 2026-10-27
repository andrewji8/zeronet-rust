//! Sign a content.json with the Rust engine and print the full document so a
//! ZeroNet Python `sslcrypto` reference can recover the address from it.
use content::compat::{sign_content_json, ZeronetKey};
use content::secp::recover_address;

fn main() {
    let wif = std::env::args()
        .nth(1)
        .unwrap_or("5K9S6dVpufGnroRgFrT6wsKiz2mJRYsC73eWDmajaHserAp3F1C".to_string());
    let key = ZeronetKey::from_wif(&wif).expect("bad wif");

    let content = serde_json::json!({
        "modified": 1700000000.123,
        "files": {
            "index.html": {"sha512": "ab".repeat(32), "size": 1234, "optional": false},
            "style.css":  {"sha512": "cd".repeat(32), "size": 67,   "optional": true}
        },
        "files_optional": {},
        "includes": {},
        "signers": []
    });

    let sc = sign_content_json(&content);
    let sig = key.sign(&sc).expect("sign failed");

    // Self-check: recover the address from the signature we just produced.
    let self_rec = recover_address(&sc, &sig).expect("self-recovery failed");
    assert_eq!(
        self_rec,
        key.address(),
        "Rust self-recovery must equal signing address"
    );

    let signed = key.sign_content(&content).expect("sign_content failed");
    println!("address: {}", key.address());
    println!("sign_content_len: {}", sc.len());
    println!("sign_content: {}", sc);
    println!("sig_b64: {}", sig);
    println!("signed_doc:\n{}", signed);

    // Also write files for the Python cross-language verifier.
    std::fs::write(
        r"C:\Users\chen\.agnes\temporary\2026-10-26\20261026_1\work\rust_sign_content.txt",
        sc.as_bytes(),
    )
    .unwrap();
    std::fs::write(
        r"C:\Users\chen\.agnes\temporary\2026-10-26\20261026_1\work\rust_signed.json",
        signed.as_bytes(),
    )
    .unwrap();
}
