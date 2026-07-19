//! Wallet file management — encrypted identity storage.
//!
//! Wallet directory: `~/.solana-key-manager/`

use crate::crypto::{self, EncryptedPayload};
use crate::keygen;
use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use std::path::PathBuf;

pub fn wallet_dir() -> Result<PathBuf> {
    dirs_home()
}

pub fn identities_dir() -> Result<PathBuf> {
    Ok(wallet_dir()?.join(".solana-key-manager").join("identities"))
}

pub fn init_wallet() -> Result<()> {
    let dir = wallet_dir()?.join(".solana-key-manager");
    let id_dir = identities_dir()?;
    std::fs::create_dir_all(&id_dir)?;

    let config_path = dir.join("config.toml");
    if !config_path.exists() {
        std::fs::write(&config_path, "# Solana Key Manager\nversion = \"0.1\"\n")?;
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct StoredIdentity {
    pub name: String,
    pub pubkey: String,
    pub has_mnemonic: bool,
    pub encrypted: EncryptedPayload,
}

impl StoredIdentity {
    pub fn decrypt_signing_key(&self, password: &str) -> Result<SigningKey> {
        let bytes = crypto::decrypt(&self.encrypted, password)?;
        if bytes.len() < 32 {
            anyhow::bail!("Decrypted data too short for ed25519 key");
        }
        let seed: &[u8; 32] = bytes[..32].try_into().unwrap();
        Ok(SigningKey::from_bytes(seed))
    }
}

pub fn save_identity(
    name: &str,
    signing_key: &SigningKey,
    password: &str,
    has_mnemonic: bool,
) -> Result<()> {
    init_wallet()?;
    let id_dir = identities_dir()?;

    let encrypted = crypto::encrypt(&signing_key.to_bytes(), password)?;

    let identity = StoredIdentity {
        name: name.to_string(),
        pubkey: keygen::pubkey_to_base58(&signing_key.verifying_key()),
        has_mnemonic,
        encrypted,
    };

    let path = id_dir.join(format!("{}.enc", name));
    std::fs::write(&path, serde_json::to_string_pretty(&identity)?)?;
    Ok(())
}

pub fn load_identity(name: &str, password: &str) -> Result<StoredIdentity> {
    let id_dir = identities_dir()?;
    let path = id_dir.join(format!("{}.enc", name));

    let json = std::fs::read_to_string(&path)
        .context(format!("Identity '{}' not found", name))?;

    let identity: StoredIdentity = serde_json::from_str(&json)?;

    // Verify password
    identity.decrypt_signing_key(password)
        .context("Wrong password or corrupted identity file")?;

    Ok(identity)
}

pub fn list_identities() -> Result<Vec<IdentitySummary>> {
    let id_dir = identities_dir()?;
    if !id_dir.exists() {
        return Ok(Vec::new());
    }

    let mut identities = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&id_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "enc") {
                if let Ok(json) = std::fs::read_to_string(&path) {
                    if let Ok(id) = serde_json::from_str::<StoredIdentity>(&json) {
                        identities.push(IdentitySummary {
                            name: id.name,
                            pubkey: id.pubkey,
                            has_mnemonic: id.has_mnemonic,
                        });
                    }
                }
            }
        }
    }

    identities.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(identities)
}

pub fn delete_identity(name: &str) -> Result<()> {
    let path = identities_dir()?.join(format!("{}.enc", name));
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

#[derive(Debug)]
pub struct IdentitySummary {
    pub name: String,
    pub pubkey: String,
    pub has_mnemonic: bool,
}

pub fn identity_path(name: &str) -> Result<PathBuf> {
    Ok(identities_dir()?.join(format!("{}.enc", name)))
}

fn dirs_home() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE")
            .map(PathBuf::from)
            .context("USERPROFILE not set")
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME")
            .map(PathBuf::from)
            .context("HOME not set")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen;

    #[test]
    fn test_save_load_delete_identity() {
        let k = keygen::generate_random().unwrap();
        let path = identity_path("__test__").unwrap();
        let _ = std::fs::remove_file(&path);

        save_identity("__test__", &k.signing_key, "test-pw", false).unwrap();
        assert!(path.exists());

        let loaded = load_identity("__test__", "test-pw").unwrap();
        assert_eq!(loaded.pubkey, k.pubkey_base58);

        assert!(load_identity("__test__", "wrong-pw").is_err());
        delete_identity("__test__").unwrap();
        assert!(!path.exists());
    }
}
