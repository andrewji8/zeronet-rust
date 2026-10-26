//! Secp256k1 (ZeroNet) signing + verification: ECRECOVER, ECDRECOVER, address
//! derivation, and ZeroNet's exact message framing.
//!
//! - WIF:            `base58check(0x80 + privkey[:32] [+ 0x01])`
//! - Public key:     uncompressed 65 bytes by default (WIF without 0x01 suffix)
//! - Address:        `base58check(0x00 + RIPEMD160(SHA256(pubkey)))`
//! - Message digest: `sha256(sha256("\x18Bitcoin Signed Message:\n" + varint + msg))`
//! - Electrum sig:   65 bytes `[v][r:32][s:32]`, v = recid + 27 (+4 if compressed),
//!   base64 encoded and stored under `signs[address]`.
//!
//! `sha2` uses digest 0.10; `ripemd160` uses digest 0.9 — the two same-named
//! `Digest` traits are imported under distinct aliases so the concrete types
//! resolve their associated `digest()` unambiguously.

use base58::{FromBase58, ToBase58};
use base64::Engine;
use ripemd160::Ripemd160;
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, PublicKey, Secp256k1};
use sha2::Sha256;

use digest::Digest as _Sha2Digest;
use ripemd160::digest::Digest as _RmdDigest;

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn ripemd160_hash(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(data).into()
}

/// Decode a base58check string, verifying the trailing 4-byte checksum.
fn base58_check_decode(s: &str) -> Result<Vec<u8>, String> {
    let full = s.from_base58().map_err(|_| "invalid base58".to_string())?;
    if full.len() < 5 {
        return Err("checksum too short".into());
    }
    let (payload, checksum) = full.split_at(full.len() - 4);
    let h1 = sha256_hash(payload);
    let h2 = sha256_hash(&h1);
    if &h2[..4] != checksum {
        return Err("bad checksum".into());
    }
    Ok(payload.to_vec())
}

fn base58_check_encode(payload: &[u8]) -> String {
    let mut full = payload.to_vec();
    let h1 = sha256_hash(&full);
    let h2 = sha256_hash(&h1);
    full.extend_from_slice(&h2[..4]);
    full.to_base58()
}

/// `0x00 + RIPEMD160(SHA256(pubkey))` -> base58check address.
pub fn public_key_to_address(pubkey: &PublicKey, compressed: bool) -> String {
    let der = if compressed {
        pubkey.serialize().to_vec()
    } else {
        pubkey.serialize_uncompressed().to_vec()
    };
    let sha = sha256_hash(&der);
    let hash160 = ripemd160_hash(&sha);
    let mut payload = Vec::with_capacity(21);
    payload.push(0x00u8);
    payload.extend_from_slice(&hash160);
    base58_check_encode(&payload)
}

/// Parse a base58check address into its 20-byte `RIPEMD160(SHA256(pubkey))`.
pub fn address_to_hash160(address: &str) -> Result<[u8; 20], String> {
    let payload = base58_check_decode(address)?;
    if payload.len() != 21 || payload[0] != 0x00 {
        return Err("not a public (version 0x00) address".into());
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&payload[1..21]);
    Ok(out)
}

/// Extract the 32-byte private key from a WIF string.
pub fn wif_to_private(wif: &str) -> Result<[u8; 32], String> {
    let payload = base58_check_decode(wif)?;
    if payload.first() != Some(&0x80u8) || (payload.len() != 33 && payload.len() != 34) {
        return Err("bad WIF".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&payload[1..33]);
    Ok(out)
}

/// Derive the (uncompressed) ZeroNet address for a WIF private key.
pub fn wif_to_address(wif: &str) -> Result<String, String> {
    let sk_bytes = wif_to_private(wif)?;
    let secp = Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&sk_bytes).map_err(|e| e.to_string())?;
    let pk = PublicKey::from_secret_key(&secp, &sk);
    Ok(public_key_to_address(&pk, false))
}

/// Bitcoin "Signed Message" framing, then double SHA256.
pub fn bitcoin_double_sha256(message: &str) -> [u8; 32] {
    let framed = bitcoin_message_frame(message);
    let once = sha256_hash(&framed);
    sha256_hash(&once)
}

/// `"\x18Bitcoin Signed Message:\n" + varint(len) + message`
pub fn bitcoin_message_frame(message: &str) -> Vec<u8> {
    let msg = message.as_bytes();
    let mut framed = Vec::new();
    framed.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
    framed.extend_from_slice(&encode_varint(msg.len() as u64));
    framed.extend_from_slice(msg);
    framed
}

/// ZeroNet's `Electrum.insane_int` length prefix.
///
/// For `len >= 253` the value follows the marker byte. `Electrum.encode(x,256,n)[::-1]`
/// produces a **little-endian** value after the marker (verified against the
/// golden framing `fd 56 01` for a 342-byte message), hence `to_le_bytes()`.
fn encode_varint(len: u64) -> Vec<u8> {
    if len < 0xfd {
        vec![len as u8]
    } else if len <= 0xffff {
        let mut v = vec![0xfd_u8];
        v.extend_from_slice(&(len as u16).to_le_bytes());
        v
    } else if len <= 0xffff_ffff {
        let mut v = vec![0xfe_u8];
        v.extend_from_slice(&len.to_le_bytes());
        v
    } else {
        let mut v = vec![0xff_u8];
        v.extend_from_slice(&len.to_le_bytes());
        v
    }
}

/// Recover the signer's address from a ZeroNet/Electrum base64 signature.
pub fn recover_address(data: &str, sign_b64: &str) -> Option<String> {
    let (compact, v) = parse_electrum_signature(sign_b64)?;
    let compressed = (v - 27) & 4 != 0;
    let recid = (v - 27) & 3;

    let digest_bytes = bitcoin_double_sha256(data);
    let message = Message::from_digest_slice(&digest_bytes).ok()?;
    let sig = RecoverableSignature::from_compact(
        &compact,
        RecoveryId::from_i32(recid as i32).ok()?,
    )
    .ok()?;

    let secp = Secp256k1::verification_only();
    let pk = secp.recover_ecdsa(&message, &sig).ok()?;
    Some(public_key_to_address(&pk, compressed))
}

fn parse_electrum_signature(sig_b64: &str) -> Option<([u8; 64], u8)> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(sig_b64).ok()?;
    if bytes.len() != 65 {
        return None;
    }
    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(&bytes[1..33]);
    compact[32..].copy_from_slice(&bytes[33..65]);
    Some((compact, bytes[0]))
}

// ---- Signing (ZeroNet publish) ----

/// Sign a message string into a ZeroNet/Electrum base64 65-byte recoverable
/// signature.
///
/// The private key is a 32-byte seed wrapped in a `SecretKey`. The message is
/// framed exactly as ZeroNet signs it (Bitcoin "signed message" magic, then
/// double-SHA256). The output is base64 of `[v][r:32][s:32]` where
/// `v = 27 + recid (+4 when compressed)`, matching `libsecp256k1message` so
/// that ZeroNet's `CryptBitcoin.verify` / `recover_address` accepts it.
///
/// NOTE: ZeroNet uses a deterministic per-key nonce for signing; this crate
/// uses the secp256k1 crate's RFC6979-style recovery, so the **byte** values
/// will differ from ZeroNet's for the same key+message, but both are valid
/// ECDSA-recoverable signatures over the identical message digest and recover
/// to the identical address. That is what interoperability requires.
pub fn sign_electrum(
    sk: &secp256k1::SecretKey,
    data: &str,
    compressed: bool,
) -> Result<String, String> {
    let digest_bytes = bitcoin_double_sha256(data);
    let message = Message::from_digest_slice(&digest_bytes).map_err(|e| e.to_string())?;

    let secp = Secp256k1::signing_only();
    let rec_sig = secp.sign_ecdsa_recoverable(&message, sk);
    let (rec_id, compact) = rec_sig.serialize_compact();

    let recid = rec_id.to_i32() as u8;
    let v: u8 = 27 + recid + (if compressed { 4 } else { 0 });
    let mut out = [0u8; 65];
    out[0] = v;
    out[1..33].copy_from_slice(&compact[0..32]);
    out[33..65].copy_from_slice(&compact[32..64]);

    Ok(base64::engine::general_purpose::STANDARD.encode(&out))
}

/// A ZeroNet signing identity: a WIF private key plus its derived address.
pub struct ZeronetKey {
    sk: secp256k1::SecretKey,
    address: String,
}

impl ZeronetKey {
    /// Build from a WIF private key, validating its checksum and deriving the
    /// (uncompressed) ZeroNet address.
    pub fn from_wif(wif: &str) -> Result<Self, String> {
        let sk_bytes = wif_to_private(wif)?;
        let sk =
            secp256k1::SecretKey::from_slice(&sk_bytes).map_err(|e| e.to_string())?;
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let address = public_key_to_address(&pk, false);
        Ok(Self { sk, address })
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    /// Sign a string into a ZeroNet/Electrum base64 signature (uncompressed).
    pub fn sign(&self, data: &str) -> Result<String, String> {
        sign_electrum(&self.sk, data, false)
    }

    /// Sign and attach as `signs[address] = sig` on a ZeroNet `content.json`
    /// object, returning the full signed document.
    ///
    /// Mirrors `ContentManager.sign`: the signed content is the document with
    /// `signs`/`sign` removed (via `sign_content_json`), then re-serialized
    /// with the `signs` map populated under this key's address.
    pub fn sign_content(&self, content: &serde_json::Value) -> Result<String, String> {
        let sign_content = crate::compat::sign_content_json(content);
        let sig = self.sign(&sign_content)?;
        let sig_b64 = sig;

        let mut doc = content.clone();
        if let Some(obj) = doc.as_object_mut() {
            obj.remove("sign");
            obj.remove("signers_sign");
            obj.insert(
                "signs".to_string(),
                serde_json::json!({ self.address.clone(): sig_b64 }),
            );
        }
        Ok(serde_json::to_string(&doc).map_err(|e| e.to_string())?)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Golden data from ZeroNet's own `Test/TestCryptBitcoin.py::testVerify`
    /// (a real cert-verify data + signature pair circulating in the network).
    const DATA: &str = "1NQUem2M4cAqWua6BVFBADtcSP55P4QobM#web/gitcenter";
    const SIGN_UNCOMPRESSED: &str = "G6YkcFTuwKMVMHI2yycGQIFGbCZVNsZEZvSlOhKpHUt/BlADY94egmDAWdlrbbFrP9wH4aKcEfbLO8sa6f63VU0=";
    const SIGN_COMPRESSED: &str = "H6YkcFTuwKMVMHI2yycGQIFGbCZVNsZEZvSlOhKpHUt/BlADY94egmDAWdlrbbFrP9wH4aKcEfbLO8sa6f63VU0=";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn zeronet_official_recover_uncompressed() {
        assert_eq!(
            recover_address(DATA, SIGN_UNCOMPRESSED).as_deref(),
            Some("19Bir5zRm1yo4pw9uuxQL8xwf9b7jqMpR")
        );
    }

    #[test]
    fn zeronet_official_recover_compressed() {
        assert_eq!(
            recover_address(DATA, SIGN_COMPRESSED).as_deref(),
            Some("1KH5BdNnqxh2KRWMMT8wUXzUgz4vVQ4S8p")
        );
    }

    #[test]
    fn zeronet_official_wif_to_address() {
        assert_eq!(
            wif_to_address("5K9S6dVpufGnroRgFrT6wsKiz2mJRYsC73eWDmajaHserAp3F1C").as_deref(),
            Ok("1MpDMxFeDUkiHohxx9tbGLeEGEuR4ZNsJz")
        );
    }

    #[test]
    fn wif_to_private_rejects_garbage() {
        assert!(wif_to_private("bogus").is_err());
    }

    #[test]
    fn sign_recover_roundtrip() {
        // Sign a message with the WIF key, then recover the address from the
        // signature. Must round-trip to the same address (proves the sign and
        // recover paths agree on framing + recid + address derivation).
        let key = ZeronetKey::from_wif("5K9S6dVpufGnroRgFrT6wsKiz2mJRYsC73eWDmajaHserAp3F1C").unwrap();
        let msg = "1NQUem2M4cAqWua6BVFBADtcSP55P4QobM#web/gitcenter";
        let sig = key.sign(msg).unwrap();
        assert_eq!(recover_address(msg, &sig).as_deref(), Some(key.address()));
    }

    #[test]
    fn sign_content_roundtrip_via_verify() {
        // sign_content() emits a ZeroNet content.json; verify_zeronet_content()
        // must accept it (self-consistency of the publish+verify path).
        let key = ZeronetKey::from_wif("5K9S6dVpufGnroRgFrT6wsKiz2mJRYsC73eWDmajaHserAp3F1C").unwrap();
        let content = serde_json::json!({
            "modified": 1700000000.123,
            "files": {"index.html": {"sha512": "ab".repeat(32), "size": 1234, "optional": false}},
            "files_optional": {},
            "includes": {},
            "signers": []
        });
        let signed = key.sign_content(&content).unwrap();
        let ok = crate::compat::verify_zeronet_content(signed.as_bytes()).unwrap();
        assert_eq!(ok, vec![key.address().to_string()]);
    }

    #[test]
    fn double_sha256_matches_python_golden() {
        // Goldens generated with pure-Python hashlib (independent reference).
        assert_eq!(
            hex(&bitcoin_double_sha256("hello")),
            "cf0447ec85f0ce7150a257db32ebfcb7523dae17c36dbd1be598779fec0484f4"
        );
        assert_eq!(
            hex(&bitcoin_double_sha256(DATA)),
            "661342f73c7564b090dbf26ff7bf05d5333f7e3af35f3829112302d2c4f26ee3"
        );
    }
}

#[cfg(test)]
mod dbl_golden {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    /// Build the authoritative 342-char long sign string byte-exactly the way
    /// CPython's `json.dumps(content, sort_keys=True)` does, using programmatic
    /// repeats to avoid any hand-typed length error.
    fn long_sign_str() -> String {
        let sha_a = "ab".repeat(32); // 64 hex chars
        let sha_c = "cd".repeat(32);
        crate::compat::sign_content_json(&serde_json::json!({
            "modified": 1700000000.123,
            "files": {
                "index.html": {"sha512": sha_a, "size": 1234, "optional": false},
                "style.css":  {"sha512": sha_c, "size": 67,   "optional": true}
            },
            "files_optional": {},
            "includes": {},
            "signers": []
        }))
    }

    /// Byte-exact cross-check against ZeroNet's `util/Electrum.dbl_format`.
    /// 342 bytes => exercises the varint `>=253` branch (`fd` marker form).
    #[test]
    fn long_message_dbl_matches_zenet_electrum() {
        let sc = long_sign_str();
        assert_eq!(sc.len(), 342, "sign string must match Python's 342-byte golden");
        assert_eq!(
            hex(&bitcoin_double_sha256(&sc)),
            "2b3554887a3cb31897b7bdee97b0508643f8c37809c650240419a2f145682c0e"
        );
    }

    #[test]
    fn short_message_dbl_matches_zenet_electrum() {
        let sc = crate::compat::sign_content_json(&serde_json::json!({
            "modified": 5.0,
            "files": {"i.html": {"sha512": "aa", "size": 9}}
        }));
        assert_eq!(
            hex(&bitcoin_double_sha256(&sc)),
            "0ae793a309e40941c00837f073320a40018433b8c86db74f6914bd1ed87224a8"
        );
    }
}
