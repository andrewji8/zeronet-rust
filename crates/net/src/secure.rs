//! Noise-XX encrypted transport (X25519 + HKDF(HMAC-SHA256) + ChaCha20-Poly1305).
//!
//! This replaces ZeroNet's `fakedomains` SNI anti-DPI hack with a real,
//! forward-secret P2P encryption layer. Both parties run the Noise `XX`
//! handshake (mutual static-key authentication; a fresh ephemeral key per
//! session gives forward secrecy), and afterwards every application frame is
//! carried inside a length-prefixed ChaCha20-Poly1305 ciphertext over the
//! underlying socket.
//!
//! Design reference:
//! - The Noise Protocol Framework (revision 34), section 7.5 (XX pattern):
//!
//!   ```text
//!   c -> e
//!   c <- e, ee, s, se
//!   c -> s, se
//!   ```
//!   `ee`/`se` are X25519 Diffie-Hellman reductions mixed into the chaining
//!   key (HKDF-HMAC-SHA256); `s` public keys are AEAD-encrypted under the
//!   current chaining key with the current handshake hash as associated data.
//!
//! This module is additive: the existing plaintext `peer` / `server` / `dht`
//! paths are unchanged, so the wire protocol stays compatible and the prior
//! tests remain green.

use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Digest;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{x25519 as x25519_dh, X25519_BASEPOINT_BYTES};

type HmacSha256 = Hmac<Sha256>;

/// Protocol name mixed into the initial handshake hash. Must be byte-identical
/// on both ends; it does not need to match other Noise implementations.
const PROTOCOL_NAME: &[u8] = b"Noise_XX_25519_ChaChaPoly_SHA256";

/// Errors in the secure tunnel.
#[derive(Debug, thiserror::Error)]
pub enum SecErr {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("aead/auth failure: {0}")]
    Aead(String),
    #[error("handshake: {0}")]
    Handshake(String),
    #[error("frame too large: {0} bytes")]
    OversizedFrame(usize),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// A persistent P2P identity: a long-lived X25519 key pair. The public key is
/// the peer's on-wire identity; the secret is what authenticates its side of
/// the handshake.
#[derive(Clone)]
pub struct NoiseIdentity {
    sk: [u8; 32],
    pk: [u8; 32],
}

impl NoiseIdentity {
    /// Generate a fresh random identity.
    pub fn new() -> Self {
        let sk = random_scalar();
        let pk = pub_from_secret(&sk);
        Self { sk, pk }
    }

    pub fn sk(&self) -> &[u8; 32] {
        &self.sk
    }

    pub fn pk(&self) -> &[u8; 32] {
        &self.pk
    }

    /// Hex of the public key (a stable peer identifier).
    pub fn pk_hex(&self) -> String {
        hex_of(&self.pk)
    }

    /// Persist the secret key as a raw 32-byte file.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        std::fs::write(path, self.sk)
    }

    /// Load a 32-byte secret key.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let b = std::fs::read(path)?;
        if b.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "noise identity must be 32 bytes",
            ));
        }
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&b);
        let pk = pub_from_secret(&sk);
        Ok(Self { sk, pk })
    }

    /// Load an identity from `path`, or generate and save a new one if absent.
    pub fn load_or_new(path: &Path) -> Result<Self, std::io::Error> {
        match Self::load(path) {
            Ok(id) => Ok(id),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let id = Self::new();
                id.save(path)?;
                Ok(id)
            }
            Err(e) => Err(e),
        }
    }
}

impl Default for NoiseIdentity {
    fn default() -> Self {
        Self::new()
    }
}

/// The peer identity learned from a completed handshake.
pub struct NoiseRemoteId {
    pk: [u8; 32],
    hex: String,
}

impl NoiseRemoteId {
    pub fn pk(&self) -> &[u8; 32] {
        &self.pk
    }

    pub fn hex(&self) -> &str {
        &self.hex
    }
}

/// A post-handshake encrypted channel over an underlying stream.
///
/// Each frame is a length-prefixed ChaCha20-Poly1305 ciphertext; the 4-byte
/// big-endian length prefix is the same framing the plaintext path uses, but
/// it now bounds the *ciphertext* instead of the JSON body.
pub struct SecureConn<S> {
    stream: S,
    tx: [u8; 32],
    rx: [u8; 32],
    n_tx: u64,
    n_rx: u64,
}

impl<S: AsyncRead + AsyncWrite + Unpin> SecureConn<S> {
    /// Encrypt `payload`, length-prefix the ciphertext, and write it.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), SecErr> {
        let ct = aead_enc(&self.tx, self.n_tx, b"", payload)?;
        self.n_tx = bump(self.n_tx)?;
        let len = (ct.len() as u32).to_be_bytes();
        self.stream.write_all(&len).await?;
        self.stream.write_all(&ct).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Read one length-prefixed ciphertext and decrypt it.
    pub async fn recv(&mut self) -> Result<Vec<u8>, SecErr> {
        let mut lb = [0u8; 4];
        self.stream.read_exact(&mut lb).await?;
        let len = u32::from_be_bytes(lb) as usize;
        if len > crate::frame::MAX_FRAME_SIZE {
            return Err(SecErr::OversizedFrame(len));
        }
        let mut ct = vec![0u8; len];
        self.stream.read_exact(&mut ct).await?;
        let pt = aead_dec(&self.rx, self.n_rx, b"", &ct)?;
        self.n_rx = bump(self.n_rx)?;
        Ok(pt)
    }
}

// ---------------------------------------------------------------------------
// primitives
// ---------------------------------------------------------------------------

fn bump(n: u64) -> Result<u64, SecErr> {
    n.checked_add(1)
        .ok_or_else(|| SecErr::Handshake("nonce exhausted".into()))
}

fn random_scalar() -> [u8; 32] {
    let mut sk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sk);
    sk
}

/// X25519 public key from a secret scalar: `sk * G`.
fn pub_from_secret(sk: &[u8; 32]) -> [u8; 32] {
    x25519_dh(*sk, X25519_BASEPOINT_BYTES)
}

/// X25519 Diffie-Hellman: `sk * pk` -> 32-byte shared secret.
fn dh(sk: [u8; 32], pk: [u8; 32]) -> [u8; 32] {
    x25519_dh(sk, pk)
}

fn hex_of(pk: &[u8; 32]) -> String {
    pk.iter().map(|b| format!("{:02x}", b)).collect()
}

/// SHA-256 -> 32 bytes.
fn sha256_32(data: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d[..]);
    out
}

/// `h = H(h || data)`.
fn mix_hash(h: [u8; 32], data: &[u8]) -> [u8; 32] {
    let mut inb = Vec::with_capacity(32 + data.len());
    inb.extend_from_slice(&h);
    inb.extend_from_slice(data);
    sha256_32(&inb)
}

/// `HMAC(key, data)` (SHA-256) -> 32 bytes.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key length");
    mac.update(data);
    let r = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

/// `MixKey`: `(ck, k) = HKDF(ck, input, 2)` (RFC 5869, zero-length info).
fn mix_key(ck: [u8; 32], input: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac_sha256(&ck, &input);
    let out1 = hmac_sha256(&temp, &[0x01]);
    let mut in2 = Vec::with_capacity(33);
    in2.extend_from_slice(&out1);
    in2.push(0x02);
    let out2 = hmac_sha256(&temp, &in2);
    (out1, out2)
}

/// `Split()` derivation: transport keys = HKDF(ck, b"", 2).
fn split_keys(ck: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac_sha256(&ck, b"");
    let out1 = hmac_sha256(&temp, &[0x01]);
    let mut in2 = Vec::with_capacity(33);
    in2.extend_from_slice(&out1);
    in2.push(0x02);
    let out2 = hmac_sha256(&temp, &in2);
    (out1, out2)
}

/// 96-bit ChaCha20-Poly1305 nonce: 32 zero bits + little-endian 64-bit counter.
fn nonce96(n: u64) -> [u8; 12] {
    let mut a = [0u8; 12];
    a[4..12].copy_from_slice(&n.to_le_bytes());
    a
}

fn aead_enc(k: &[u8; 32], n: u64, ad: &[u8], pt: &[u8]) -> Result<Vec<u8>, SecErr> {
    let c = ChaCha20Poly1305::new_from_slice(&k[..]).map_err(|e| SecErr::Aead(e.to_string()))?;
    c.encrypt(&Nonce::from(nonce96(n)), Payload { msg: pt, aad: ad })
        .map_err(|e| SecErr::Aead(e.to_string()))
}

fn aead_dec(k: &[u8; 32], n: u64, ad: &[u8], ct: &[u8]) -> Result<Vec<u8>, SecErr> {
    let c = ChaCha20Poly1305::new_from_slice(&k[..]).map_err(|e| SecErr::Aead(e.to_string()))?;
    c.decrypt(&Nonce::from(nonce96(n)), Payload { msg: ct, aad: ad })
        .map_err(|e| SecErr::Aead(e.to_string()))
}

/// Run the `XX` handshake as the **initiator** (the side that opens the
/// connection). Returns the secured channel and the peer's identity.
pub async fn initiator_handshake<S>(
    mut stream: S,
    identity: &NoiseIdentity,
) -> Result<(SecureConn<S>, NoiseRemoteId), SecErr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Symmetric init: h0 = H(PN); ck = h0; k empty.
    let h0 = sha256_32(PROTOCOL_NAME);
    let mut h = h0;
    let ck = h0;

    // m1: send ephemeral e.
    let ei_sk = random_scalar();
    let ei_pk = pub_from_secret(&ei_sk);
    stream.write_all(&ei_pk).await?;
    stream.flush().await?;
    h = mix_hash(h, &ei_pk);

    // read m2: er (32) + ct_s (48) = 80 bytes.
    let mut m2 = [0u8; 80];
    stream.read_exact(&mut m2).await?;
    let er_pk: [u8; 32] = m2[0..32]
        .try_into()
        .map_err(|_| SecErr::Handshake("m2 short".into()))?;
    let ct_s = &m2[32..80];
    // token e
    h = mix_hash(h, &er_pk);
    // token ee: DH(e_i, e_r)
    let shared_ee = dh(ei_sk, er_pk);
    let (ck, k_ee) = mix_key(ck, shared_ee);
    // token s: decrypt remote static public key (ct_s under k_ee, ad = h)
    let sr_bytes = aead_dec(&k_ee, 0, &h, ct_s)?;
    if sr_bytes.len() != 32 {
        return Err(SecErr::Handshake("remote static key wrong length".into()));
    }
    let mut sr_pk = [0u8; 32];
    sr_pk.copy_from_slice(&sr_bytes);
    h = mix_hash(h, ct_s);
    // token se: DH(e_i, s_r)
    let shared_se1 = dh(ei_sk, sr_pk);
    let (ck, k_se1) = mix_key(ck, shared_se1);

    // m3: s (my static public, encrypted under k_se1, ad = h) + se.
    let ct_s2 = aead_enc(&k_se1, 0, &h, &identity.pk)?;
    let _h = mix_hash(h, &ct_s2);
    // token se: DH(s_i, e_r)
    let shared_se2 = dh(*identity.sk(), er_pk);
    let (ck, _) = mix_key(ck, shared_se2);
    stream.write_all(&ct_s2).await?;
    stream.flush().await?;

    // Split transport keys: out1 = initiator->responder, out2 = responder->initiator.
    let (i_tx, i_rx) = split_keys(ck);
    let remote = NoiseRemoteId {
        hex: hex_of(&sr_pk),
        pk: sr_pk,
    };
    Ok((
        SecureConn {
            stream,
            tx: i_tx,
            rx: i_rx,
            n_tx: 0,
            n_rx: 0,
        },
        remote,
    ))
}

/// Run the `XX` handshake as the **responder** (the listening side).
pub async fn responder_handshake<S>(
    mut stream: S,
    identity: &NoiseIdentity,
) -> Result<(SecureConn<S>, NoiseRemoteId), SecErr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let h0 = sha256_32(PROTOCOL_NAME);
    let mut h = h0;
    let ck = h0;

    // read m1: e.
    let mut m1 = [0u8; 32];
    stream.read_exact(&mut m1).await?;
    let ei_pk: [u8; 32] = m1;
    h = mix_hash(h, &ei_pk);

    // m2: e, ee, s, se.
    let er_sk = random_scalar();
    let er_pk = pub_from_secret(&er_sk);
    h = mix_hash(h, &er_pk);
    // token ee: DH(e_r, e_i)
    let shared_ee = dh(er_sk, ei_pk);
    let (ck, k_ee) = mix_key(ck, shared_ee);
    // token s: my static public key (ct_s under k_ee, ad = h)
    let ct_s = aead_enc(&k_ee, 0, &h, &identity.pk)?;
    h = mix_hash(h, &ct_s);
    // token se: DH(s_r, e_i)
    let shared_se1 = dh(*identity.sk(), ei_pk);
    let (ck, k_se1) = mix_key(ck, shared_se1);
    let mut m2 = Vec::with_capacity(32 + ct_s.len());
    m2.extend_from_slice(&er_pk);
    m2.extend_from_slice(&ct_s);
    stream.write_all(&m2).await?;
    stream.flush().await?;

    // read m3: ct_s2 (48 bytes) = s (encrypted) + se.
    let mut m3 = [0u8; 48];
    stream.read_exact(&mut m3).await?;
    let si_bytes = aead_dec(&k_se1, 0, &h, &m3)?;
    if si_bytes.len() != 32 {
        return Err(SecErr::Handshake("remote static key wrong length".into()));
    }
    let mut si_pk = [0u8; 32];
    si_pk.copy_from_slice(&si_bytes);
    let _h = mix_hash(h, &m3);
    // token se: DH(e_r, s_i)
    let shared_se2 = dh(er_sk, si_pk);
    let (ck, _) = mix_key(ck, shared_se2);

    // Split transport keys: out1 = initiator->responder (R receives), out2 = R sends.
    let (r_rx, r_tx) = split_keys(ck);
    let remote = NoiseRemoteId {
        hex: hex_of(&si_pk),
        pk: si_pk,
    };
    Ok((
        SecureConn {
            stream,
            tx: r_tx,
            rx: r_rx,
            n_tx: 0,
            n_rx: 0,
        },
        remote,
    ))
}

/// Like `peer::get_file`, but the RPC travels inside a Noise-XX-secured
/// channel: connect, handshake, then one encrypted `GetFile` round-trip.
pub async fn sec_get_file(
    addr: std::net::SocketAddr,
    identity: &NoiseIdentity,
    site: &str,
    path: &str,
) -> Result<Vec<u8>, SecErr> {
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let (mut conn, _remote) = initiator_handshake(stream, identity).await?;
    let req = serde_json::to_vec(&crate::rpc::Rpc::GetFile {
        site: site.to_string(),
        path: path.to_string(),
    })?;
    conn.send(&req).await?;
    let resp = conn.recv().await?;
    let f: crate::rpc::FileResponse = serde_json::from_slice(&resp)?;
    if !f.ok {
        return Err(SecErr::Handshake(
            f.error.unwrap_or_else(|| "peer refused".into()),
        ));
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(&f.data_b64)
        .map_err(|e| SecErr::Handshake(format!("bad base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-consistency: encrypt with one key/nonce, confirm the matching
    /// key/nonce recovers it, and any tamper or wrong key is rejected.
    #[test]
    fn aead_roundtrip_and_tamper_rejection() {
        let k = [0x5au8; 32];
        let pt = b"hello noise xx";
        let ct = aead_enc(&k, 0, b"", pt).expect("enc");
        assert_ne!(ct, pt.to_vec(), "ciphertext must differ from plaintext");
        let back = aead_dec(&k, 0, b"", &ct).expect("dec");
        assert_eq!(back, pt);

        // tamper the ciphertext -> auth must fail
        let mut bad = ct.clone();
        bad[0] ^= 0x01;
        assert!(
            aead_dec(&k, 0, b"", &bad).is_err(),
            "tamper must be rejected"
        );

        // wrong key -> auth must fail
        let wrong = [0x5bu8; 32];
        assert!(aead_dec(&wrong, 0, b"", &ct).is_err());

        // wrong nonce -> auth must fail
        assert!(aead_dec(&k, 1, b"", &ct).is_err());
    }

    /// The X25519 DH is symmetric: DH(a_sk, b_pk) == DH(b_sk, a_pk).
    #[test]
    fn dh_is_symmetric() {
        let a = random_scalar();
        let b = random_scalar();
        let ap = pub_from_secret(&a);
        let bp = pub_from_secret(&b);
        assert_eq!(dh(a, bp), dh(b, ap));
    }

    #[test]
    fn identity_save_load_roundtrip() {
        let id = NoiseIdentity::new();
        let p = std::env::temp_dir().join(format!("zrs_noise_id_{}.bin", std::process::id()));
        std::fs::remove_file(&p).ok();
        id.save(&p).unwrap();
        let loaded = NoiseIdentity::load(&p).unwrap();
        assert_eq!(loaded.pk(), id.pk());
        assert_eq!(loaded.pk_hex(), id.pk_hex());
        std::fs::remove_file(&p).ok();
    }
}
