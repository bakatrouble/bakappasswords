use rand::RngCore;
use sha_crypt::{PasswordHash, PasswordHasher, PasswordVerifier, ShaCrypt};
use sha2::{Digest, Sha256};

/// Salt bytes. Twelve bytes encode to the 16 characters sha-crypt allows.
const SALT_LEN: usize = 12;

/// SHA-512-crypt in MCF form with the default 5000 rounds. Verifying one
/// costs a few thousand hash rounds, far below Argon2's memory-hard cost,
/// so high-volume Basic auth (Loki pushes) stays cheap on the CPU.
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    let hash = ShaCrypt::SHA512
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing failed: {e}"))?;
    Ok(hash.to_string())
}

pub fn verify_password(stored: &str, password: &str) -> bool {
    stored
        .parse::<PasswordHash>()
        .map(|parsed| {
            ShaCrypt::SHA512
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}

/// Bearer tokens are high-entropy, so a plain SHA-256 index is enough and
/// allows direct lookup. Only the digest is stored.
pub fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

pub fn random_bytes() -> [u8; 32] {
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// Fresh bearer token: 64 hex characters from 256 random bits.
pub fn random_token() -> String {
    hex::encode(random_bytes())
}
