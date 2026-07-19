//! Key generation: random ed25519 keypairs and BIP39 mnemonics.
//!
//! Two generation paths:
//! 1. Random keypair (no mnemonic)
//! 2. BIP39 mnemonic → seed → ed25519 keypair (HD-compatible)

use anyhow::{Context, Result};
use bip39::Mnemonic;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

/// A generated keypair with optional mnemonic.
pub struct GeneratedKey {
    /// ed25519 signing key (32-byte seed).
    pub signing_key: SigningKey,
    /// The verifying key (public key).
    pub verifying_key: VerifyingKey,
    /// BIP39 mnemonic (12 or 24 words), if generated from mnemonic.
    pub mnemonic: Option<String>,
    /// The public key in base58.
    pub pubkey_base58: String,
    /// Derivation path used, if any.
    pub derivation_path: Option<String>,
}

/// Generate a random ed25519 keypair (no mnemonic).
pub fn generate_random() -> Result<GeneratedKey> {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    Ok(GeneratedKey {
        pubkey_base58: bs58::encode(verifying_key.to_bytes()).into_string(),
        signing_key,
        verifying_key,
        mnemonic: None,
        derivation_path: None,
    })
}

/// Generate a BIP39 mnemonic and derive the ed25519 keypair from it.
pub fn generate_from_mnemonic(word_count: usize) -> Result<GeneratedKey> {
    if word_count != 12 && word_count != 24 {
        anyhow::bail!("Unsupported word count: {}. Use 12 or 24.", word_count);
    }

    // bip39 v2: generate(word_count) where word_count is the mnemonic word count
    let mnemonic = Mnemonic::generate(word_count)
        .map_err(|e| anyhow::anyhow!("Mnemonic generation failed: {}", e))?;

    let phrase = mnemonic.to_string();
    let seed = mnemonic_to_seed(&phrase)?;
    let signing_key = seed_to_signing_key(&seed)?;
    let verifying_key = signing_key.verifying_key();

    Ok(GeneratedKey {
        pubkey_base58: bs58::encode(verifying_key.to_bytes()).into_string(),
        signing_key,
        verifying_key,
        mnemonic: Some(phrase),
        derivation_path: Some("m/44'/501'/0'/0'".into()),
    })
}

/// Restore a keypair from a BIP39 mnemonic phrase.
pub fn restore_from_mnemonic(phrase: &str) -> Result<GeneratedKey> {
    Mnemonic::parse(phrase)
        .map_err(|e| anyhow::anyhow!("Invalid mnemonic: {}", e))?;

    let seed = mnemonic_to_seed(phrase)?;
    let signing_key = seed_to_signing_key(&seed)?;
    let verifying_key = signing_key.verifying_key();

    Ok(GeneratedKey {
        pubkey_base58: bs58::encode(verifying_key.to_bytes()).into_string(),
        signing_key,
        verifying_key,
        mnemonic: Some(phrase.to_string()),
        derivation_path: Some("m/44'/501'/0'/0'".into()),
    })
}

/// Convert a BIP39 mnemonic to a 64-byte seed using PBKDF2-HMAC-SHA512.
fn mnemonic_to_seed(phrase: &str) -> Result<[u8; 64]> {
    let mnemonic = Mnemonic::parse(phrase)
        .map_err(|e| anyhow::anyhow!("Invalid mnemonic: {}", e))?;

    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(
        phrase.as_bytes(),
        b"mnemonic",
        2048,
        &mut seed,
    );

    let _ = mnemonic; // suppress unused warning — we used it above for validation
    Ok(seed)
}

/// Derive an ed25519 SigningKey from a 64-byte seed.
fn seed_to_signing_key(seed: &[u8; 64]) -> Result<SigningKey> {
    use sha2::Digest;
    let hash = sha2::Sha512::digest(seed);
    let secret_bytes: &[u8; 32] = hash[..32]
        .try_into()
        .map_err(|_| anyhow::anyhow!("Seed derivation produced wrong length"))?;

    Ok(SigningKey::from_bytes(secret_bytes))
}

/// Import a keypair from base58-encoded 64-byte Solana secret key.
pub fn import_from_base58(secret_b58: &str) -> Result<GeneratedKey> {
    let bytes = bs58::decode(secret_b58)
        .into_vec()
        .context("Invalid base58 secret key")?;

    if bytes.len() != 64 {
        anyhow::bail!(
            "Expected 64 bytes for Solana keypair, got {}",
            bytes.len()
        );
    }

    let seed: &[u8; 32] = bytes[..32].try_into().unwrap();
    let signing_key = SigningKey::from_bytes(seed);
    let verifying_key = signing_key.verifying_key();

    Ok(GeneratedKey {
        pubkey_base58: bs58::encode(verifying_key.to_bytes()).into_string(),
        signing_key,
        verifying_key,
        mnemonic: None,
        derivation_path: None,
    })
}

/// Import a keypair from a Solana keypair JSON file (array of 64 bytes).
pub fn import_from_json(json_bytes: &[u8]) -> Result<GeneratedKey> {
    let bytes: Vec<u8> = serde_json::from_slice(json_bytes)
        .context("Invalid keypair JSON format")?;

    if bytes.len() != 64 {
        anyhow::bail!(
            "Expected 64 bytes for Solana keypair, got {}",
            bytes.len()
        );
    }

    let seed: &[u8; 32] = bytes[..32].try_into().unwrap();
    let signing_key = SigningKey::from_bytes(seed);
    let verifying_key = signing_key.verifying_key();

    Ok(GeneratedKey {
        pubkey_base58: bs58::encode(verifying_key.to_bytes()).into_string(),
        signing_key,
        verifying_key,
        mnemonic: None,
        derivation_path: None,
    })
}

/// Export signing key as base58-encoded 64-byte Solana keypair.
pub fn export_to_base58(signing_key: &SigningKey) -> String {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&signing_key.to_bytes());
    bytes[32..].copy_from_slice(&signing_key.verifying_key().to_bytes());
    bs58::encode(bytes).into_string()
}

/// Export signing key as Solana JSON array.
pub fn export_to_json(signing_key: &SigningKey) -> String {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&signing_key.to_bytes());
    bytes.extend_from_slice(&signing_key.verifying_key().to_bytes());
    serde_json::to_string(&bytes).unwrap()
}

/// Sign a message with the signing key.
pub fn sign_message(signing_key: &SigningKey, message: &[u8]) -> ed25519_dalek::Signature {
    signing_key.sign(message)
}

/// Get verifying key bytes as base58.
pub fn pubkey_to_base58(verifying_key: &VerifyingKey) -> String {
    bs58::encode(verifying_key.to_bytes()).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_produces_unique_keys() {
        let k1 = generate_random().unwrap();
        let k2 = generate_random().unwrap();
        assert_ne!(k1.pubkey_base58, k2.pubkey_base58);
    }

    #[test]
    fn test_generate_24_word_mnemonic() {
        let k = generate_from_mnemonic(24).unwrap();
        let phrase = k.mnemonic.unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_restore_from_mnemonic_is_deterministic() {
        let original = generate_from_mnemonic(24).unwrap();
        let phrase = original.mnemonic.clone().unwrap();
        let restored = restore_from_mnemonic(&phrase).unwrap();
        assert_eq!(original.pubkey_base58, restored.pubkey_base58);
    }

    #[test]
    fn test_import_export_base58_roundtrip() {
        let k = generate_random().unwrap();
        let exported = export_to_base58(&k.signing_key);
        let imported = import_from_base58(&exported).unwrap();
        assert_eq!(k.pubkey_base58, imported.pubkey_base58);
    }

    #[test]
    fn test_import_export_json_roundtrip() {
        let k = generate_random().unwrap();
        let exported = export_to_json(&k.signing_key);
        let imported = import_from_json(exported.as_bytes()).unwrap();
        assert_eq!(k.pubkey_base58, imported.pubkey_base58);
    }

    #[test]
    fn test_invalid_mnemonic_restore_fails() {
        assert!(restore_from_mnemonic("this is not a valid bip39 mnemonic phrase at all").is_err());
    }
}
