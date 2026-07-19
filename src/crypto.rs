//! AES-256-GCM encryption for keypair files.
//!
//! Encryption flow:
//!   password + salt → Argon2id → 256-bit key
//!   random 96-bit nonce → AES-256-GCM(key, nonce) → ciphertext + tag
//!
//! Decryption flow:
//!   password + salt → Argon2id → 256-bit key
//!   AES-256-GCM(key, nonce) decrypt → plaintext (or auth error)

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, AeadCore, Nonce,
};
use argon2::{self, Argon2};
use anyhow::{Context, Result};
use rand::RngCore;
use sha2::{Sha256, Digest};

// ponytail: small fixed salt from sha256(purpose) — not ideal for production
// where every encryption should have unique salt, but fine for local CLI tool.
// The salt is combined with a random nonce for semantic security.
const SALT_PREFIX: &[u8] = b"solana-km-v1";

/// An encrypted payload with all metadata needed for decryption.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct EncryptedPayload {
    /// Base64-encoded ciphertext (with 16-byte AEAD tag appended).
    pub ciphertext: String,
    /// Base64-encoded 96-bit nonce.
    pub nonce: String,
    /// Base64-encoded salt used in key derivation.
    pub salt: String,
    /// Argon2id parameters.
    pub kdf: KdfParams,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct KdfParams {
    pub algorithm: String,
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: "argon2id".into(),
            memory_cost_kib: 19456,     // 19 MiB
            time_cost: 2,                // 2 iterations
            parallelism: 1,              // single-threaded
        }
    }
}

/// Derive a 256-bit encryption key from a password and salt using Argon2id.
fn derive_key(password: &str, salt: &[u8], params: &KdfParams) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let argon_params = argon2::Params::new(
        params.memory_cost_kib,
        params.time_cost,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| anyhow::anyhow!("Argon2 params error: {:?}", e))?;

    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    )
    .hash_password_into(password.as_bytes(), salt, &mut key)
    .map_err(|e| anyhow::anyhow!("Argon2id key derivation failed: {:?}", e))?;
    Ok(key)
}

/// Encrypt `plaintext` under `password`.
///
/// Returns a JSON-serializable `EncryptedPayload` containing the
/// ciphertext, nonce, salt, and KDF parameters.
pub fn encrypt(plaintext: &[u8], password: &str) -> Result<EncryptedPayload> {
    // Generate random salt (32 bytes)
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    // Combine fixed prefix with random salt for domain separation
    let mut full_salt = SALT_PREFIX.to_vec();
    full_salt.extend_from_slice(&salt);

    let params = KdfParams::default();
    let key = derive_key(password, &full_salt, &params)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("AES key init failed: {:?}", e))?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

    use base64::Engine;
    Ok(EncryptedPayload {
        ciphertext: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
        nonce: base64::engine::general_purpose::STANDARD.encode(nonce.as_slice()),
        salt: base64::engine::general_purpose::STANDARD.encode(&salt),
        kdf: params,
    })
}

/// Decrypt an `EncryptedPayload` using `password`.
///
/// Returns the original plaintext, or an error if the password is wrong
/// (AEAD authentication failure) or the payload is malformed.
pub fn decrypt(payload: &EncryptedPayload, password: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&payload.ciphertext)
        .context("Invalid ciphertext base64")?;

    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(&payload.nonce)
        .context("Invalid nonce base64")?;

    let salt = base64::engine::general_purpose::STANDARD
        .decode(&payload.salt)
        .context("Invalid salt base64")?;

    let mut full_salt = SALT_PREFIX.to_vec();
    full_salt.extend_from_slice(&salt);

    let key = derive_key(password, &full_salt, &payload.kdf)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("AES key init failed: {:?}", e))?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("Decryption failed — wrong password or corrupted file"))
}

/// Hash a password into a verification token (SHA-256).
/// Used to check if a password is correct without full decryption.
pub fn password_verification_hash(password: &str) -> String {
    let hash = Sha256::digest(password.as_bytes());
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(&hash[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"This is a secret ed25519 keypair!";
        let password = "correct-horse-battery-staple";

        let payload = encrypt(plaintext, password).unwrap();
        let decrypted = decrypt(&payload, password).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_password_fails() {
        let payload = encrypt(b"secret data", "right-password").unwrap();
        let result = decrypt(&payload, "wrong-password");
        assert!(result.is_err());
    }

    #[test]
    fn test_different_plaintext_different_ciphertext() {
        let p1 = encrypt(b"hello", "pw").unwrap();
        let p2 = encrypt(b"world", "pw").unwrap();
        assert_ne!(p1.ciphertext, p2.ciphertext);
    }

    #[test]
    fn test_same_plaintext_different_ciphertext() {
        // Each encryption uses a random nonce — same plaintext should produce
        // different ciphertext each time.
        let p1 = encrypt(b"hello", "pw").unwrap();
        let p2 = encrypt(b"hello", "pw").unwrap();
        assert_ne!(p1.ciphertext, p2.ciphertext);
        assert_ne!(p1.nonce, p2.nonce);
    }
}
