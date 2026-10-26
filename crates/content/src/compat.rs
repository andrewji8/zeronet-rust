//! ZeroNet compatibility layer.
//!
//! 1. **ZeroNet `content.json` format** - parse/convert between ZeroNet's
//!    `content.json` (Secp256k1 + sha512) and the native BLAKE3/Ed25519 manifest.
//! 2. **Secp256k1 verification** - full verification of ZeroNet-signed content:
//!    Python-JSON-exact serialization, Bitcoin "signed message" framing,
//!    double-SHA256, secp256k1 ECRECOVER, and base58check address derivation.

use serde_json::Value;

// ---- Part 1: ZeroNet content.json parsing ----

/// Parsed shape of a ZeroNet `content.json`.
#[derive(Debug, serde::Deserialize)]
pub struct ZeronetContent {
    pub files: std::collections::HashMap<String, ZeronetFile>,
    #[serde(default)]
    pub files_optional: std::collections::HashMap<String, ZeronetFile>,
    #[serde(default)]
    pub includes: std::collections::HashMap<String, Value>,
    #[serde(default)]
    pub modified: f64,
    #[serde(default)]
    pub size: f64,
}

#[derive(Debug, serde::Deserialize)]
pub struct ZeronetFile {
    #[serde(default)]
    pub sha512: Option<String>,
    #[serde(default)]
    pub sha1: Option<String>,
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub optional: bool,
}

/// Parse ZeroNet `content.json` bytes.
pub fn parse_zeronet_content(bytes: &[u8]) -> Result<ZeronetContent, CompatError> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| CompatError::Parse(e.to_string()))?;
    let c: ZeronetContent = serde_json::from_value(v).map_err(|e| CompatError::Parse(e.to_string()))?;
    Ok(c)
}

/// Verify a ZeroNet `content.json` document's signature(s).
///
/// Returns the list of signer addresses whose signatures check out.
pub fn verify_zeronet_content(json_bytes: &[u8]) -> Result<Vec<String>, CompatError> {
    let mut v: Value =
        serde_json::from_slice(json_bytes).map_err(|e| CompatError::Parse(e.to_string()))?;

    let signs: std::collections::BTreeMap<String, String> = v
        .get("signs")
        .and_then(|s| s.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    if let Some(obj) = v.as_object_mut() {
        obj.remove("signs");
        obj.remove("sign");
    }

    let sign_content = python_json_dump(&v);
    let mut ok: Vec<String> = Vec::new();
    for (address, sig) in &signs {
        if let Some(recovered) = crate::secp::recover_address(&sign_content, sig) {
            if recovered == *address {
                ok.push(address.clone());
            }
        }
    }
    if ok.is_empty() {
        Err(CompatError::BadSignature)
    } else {
        Ok(ok)
    }
}

// ---- Part 2: Python-JSON-exact serialization ----

/// Serialize a JSON value the way `json.dumps(value, sort_keys=True)` does in
/// CPython 3: keys sorted by codepoint, separators `", "` / `": "`,
/// `ensure_ascii=True`, CPython float repr. Must match byte-for-byte.
pub fn python_json_dump(v: &Value) -> String {
    let mut out = String::new();
    dump_into(v, &mut out);
    out
}

fn dump_into(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(f) = n.as_f64() {
                out.push_str(&python_float_repr(f));
            }
        }
        Value::String(s) => escape_string(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                dump_into(item, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                escape_string(k, out);
                out.push_str(": ");
                dump_into(&m[*k], out);
            }
            out.push('}');
        }
    }
}

/// `ensure_ascii=True` string escaping, matching CPython's json module.
fn escape_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        let cp = c as u32;
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            _ if cp < 0x20 => {
                out.push_str(&format!("\\u{:04x}", cp));
            }
            _ if cp >= 0x7F => {
                if cp > 0xFFFF {
                    let hi = 0xD800u32 + ((cp - 0x10000) >> 10);
                    let lo = 0xDC00u32 + ((cp - 0x10000) & 0x3FF);
                    out.push_str(&format!("\\u{:04x}\\u{:04x}", hi, lo));
                } else {
                    out.push_str(&format!("\\u{:04x}", cp));
                }
            }
            _ => out.push(c),
        }
    }
    out.push('"');
}

/// CPython `repr(float)` compatible formatting (shortest round-trip with
/// scientific-notation thresholds `abs < 1e-4` or `abs >= 1e16`).
fn python_float_repr(x: f64) -> String {
    if x.is_nan() {
        return "NaN".to_string();
    }
    if x.is_infinite() {
        return if x > 0.0 {
            "Infinity".to_string()
        } else {
            "-Infinity".to_string()
        };
    }
    let neg = x < 0.0 || (x == 0.0 && x.is_sign_negative());
    let a = x.abs();
    let s = format!("{}", a);
    let (int_part, frac_part) = s.split_once('.').unwrap_or((s.as_str(), ""));

    let all_digits: String = format!("{}{}", int_part, frac_part);
    let n_frac = frac_part.len() as i32;
    let p = all_digits.len() as i32 - n_frac; // decimal point position
    // Index of first non-zero significant digit.
    let i: i32 = all_digits
        .char_indices()
        .find(|&(_, c)| c != '0')
        .map(|(idx, _)| idx as i32)
        .unwrap_or(all_digits.len() as i32);
    let exp = p - 1 - i; // value = d_0.d_1... x 10^exp
    let mut sig: String = all_digits[i.max(0) as usize..]
        .trim_end_matches('0')
        .to_string();
    if sig.is_empty() {
        sig = "0".to_string();
    }

    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if exp <= -5 || exp >= 16 {
        // Scientific notation: Python always uses signed, >=2-digit exponent.
        if sig.len() == 1 {
            out.push_str(&sig);
        } else {
            out.push_str(&sig[..1]);
            out.push('.');
            out.push_str(&sig[1..]);
        }
        out.push('e');
        out.push_str(if exp >= 0 { "+" } else { "-" });
        out.push_str(&format!("{:02}", exp.abs()));
    } else if exp >= 0 {
        let n_int = (exp + 1) as usize;
        if sig.len() <= n_int {
            out.push_str(&sig);
            for _ in sig.len()..n_int {
                out.push('0');
            }
            out.push_str(".0");
        } else {
            out.push_str(&sig[..n_int]);
            out.push('.');
            out.push_str(&sig[n_int..]);
        }
    } else {
        out.push_str("0.");
        for _ in 0..((-exp) - 1) {
            out.push('0');
        }
        out.push_str(&sig);
    }
    out
}

/// Python `json.dumps` of the site content as ZeroNet signs it
/// (the `signs`/`sign` keys are excluded, `signers_sign` is kept).
pub fn sign_content_json(content: &Value) -> String {
    let mut v = content.clone();
    if let Some(obj) = v.as_object_mut() {
        obj.remove("signs");
        obj.remove("sign");
    }
    python_json_dump(&v)
}

/// Errors from the compatibility layer.
#[derive(Debug, thiserror::Error)]
pub enum CompatError {
    #[error("failed to parse ZeroNet content.json: {0}")]
    Parse(String),
    #[error("no valid signature found in content.json")]
    BadSignature,
}

// ---- Secp256k1 verification entry points (re-exported) ----
pub use crate::secp::{
    address_to_hash160, bitcoin_double_sha256, public_key_to_address, recover_address,
    sign_electrum, wif_to_address, wif_to_private, ZeronetKey,
};




#[cfg(test)]
mod tests {
    use super::*;

    /// Authoritative content.json signed by ZeroNet's own sslcrypto secp256k1
    /// engine (342-byte sign string => varint long branch). Built
    /// programmatically so the sha512 fields are exactly 64 hex chars.
    fn long_signed_doc() -> String {
        let sha_a = "ab".repeat(32);
        let sha_c = "cd".repeat(32);
        serde_json::json!({
            "modified": 1700000000.123,
            "files": {
                "index.html": {"sha512": sha_a, "size": 1234, "optional": false},
                "style.css":  {"sha512": sha_c, "size": 67,   "optional": true}
            },
            "files_optional": {},
            "includes": {},
            "signers": [],
            "signs": {
                "1JfiBT8GTi14zao4rDc5Vxn5JSGaQSUW1Q": "HFR8Zb3f+nJWZtrvwGaSOV9A7r60jsXWtlLJv2W5xN7qTS+sN/fJV5J59aeEPKivQjpK3Z8NzQlxnEkhlok3KCc="
            }
        })
        .to_string()
    }

    #[test]
    fn python_json_dump_matches_cpython_golden_1() {
        let v: Value = serde_json::from_str(
            r#"{"files": {"b": {"sha1": null, "size": 1}, "index.html": {"optional": false, "sha512": "ab", "size": 1234}}, "flags": ["x", 1, null, true], "includes": {}, "modified": 1700000000.5, "signers": ["1abc"]}"#,
        )
        .unwrap();
        assert_eq!(
            python_json_dump(&v),
            r#"{"files": {"b": {"sha1": null, "size": 1}, "index.html": {"optional": false, "sha512": "ab", "size": 1234}}, "flags": ["x", 1, null, true], "includes": {}, "modified": 1700000000.5, "signers": ["1abc"]}"#
        );
    }

    #[test]
    fn python_json_dump_floats_match_cpython_repr() {
        let v: Value = serde_json::from_str(
            r#"{"a": 0.1, "b": 1e-05, "c": 1e+20, "d": 3.0, "e": 0.00025, "f": 0.0, "g": 123.456789012345, "h": 0.0001, "i": 1e-05, "j": -2.5, "k": 12345678901}"#,
        )
        .unwrap();
        assert_eq!(
            python_json_dump(&v),
            r#"{"a": 0.1, "b": 1e-05, "c": 1e+20, "d": 3.0, "e": 0.00025, "f": 0.0, "g": 123.456789012345, "h": 0.0001, "i": 1e-05, "j": -2.5, "k": 12345678901}"#
        );
    }

    #[test]
    fn python_json_dump_ensure_ascii_unicode() {
        let v: Value =
            serde_json::from_str(r#"{"nested": {"a": false, "z": [1, "two", [3]]}, "u": "caf\u00e9 \u2764"}"#).unwrap();
        assert_eq!(
            python_json_dump(&v),
            r#"{"nested": {"a": false, "z": [1, "two", [3]]}, "u": "caf\u00e9 \u2764"}"#
        );
    }

    #[test]
    fn verify_sslcrypto_signed_long_content() {
        // Signed by ZeroNet's sslcrypto engine; 342-byte sign string.
        let doc = long_signed_doc();
        let ok = verify_zeronet_content(doc.as_bytes()).unwrap();
        assert_eq!(ok, vec!["1JfiBT8GTi14zao4rDc5Vxn5JSGaQSUW1Q".to_string()]);
    }

    #[test]
    fn verify_sslcrypto_signed_short_content() {
        let doc = r#"{"modified": 5.0, "files": {"i.html": {"sha512": "aa", "size": 9}}, "signs": {"1JfiBT8GTi14zao4rDc5Vxn5JSGaQSUW1Q": "HI5ydY/Vyg1wI2bjUKQxivnx2GgYEybqxrPutMpdy+dLBTHaPuYE0VRMD6he3zHn2L8CJBvuDF/ZM8cGM6BRRAc="}}"#;
        let ok = verify_zeronet_content(doc.as_bytes()).unwrap();
        assert_eq!(ok, vec!["1JfiBT8GTi14zao4rDc5Vxn5JSGaQSUW1Q".to_string()]);
    }

    #[test]
    fn verify_rejects_tampered_content() {
        // Same signature, but a file size was changed after signing.
        let doc = long_signed_doc();
        let mut m: Value = serde_json::from_str(&doc).unwrap();
        if let Some(files) = m.get_mut("files").and_then(|f| f.as_object_mut()) {
            if let Some(e) = files.get_mut("index.html") {
                e["size"] = serde_json::json!(9999);
            }
        }
        assert!(matches!(
            verify_zeronet_content(m.to_string().as_bytes()),
            Err(CompatError::BadSignature)
        ));
    }

    #[test]
    fn parse_zeronet_content_shape() {
        let doc = r#"{"modified": 5.0, "files": {"i.html": {"sha512": "aa", "size": 9, "optional": false}}}"#;
        let c = parse_zeronet_content(doc.as_bytes()).unwrap();
        assert_eq!(c.files.len(), 1);
        assert_eq!(c.files.get("i.html").unwrap().size, 9);
    }
}


