//! Ed25519 keypair helpers.

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;

/// A freshly generated ed25519 identity.
pub struct Identity {
    pub verifying_key: VerifyingKey,
    pub signing_key: SigningKey,
}

impl Identity {
    /// Generate a new random identity.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        Self { verifying_key, signing_key }
    }

    /// Load from existing secret bytes (32).
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        let verifying_key = signing_key.verifying_key();
        Self { verifying_key, signing_key }
    }

    /// Public key as raw 32 bytes (used as the site address).
    pub fn site_key(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::with_capacity(64);
        for b in self.site_key() {
            s.push_str(&format!("{:02x}", b));
        }
        write!(f, "Identity(site={})", &s[..16])
    }
}
