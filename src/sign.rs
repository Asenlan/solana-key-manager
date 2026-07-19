//! Message signing and signature verification with ed25519-dalek.

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer};

/// Sign an arbitrary message.
pub fn sign_message(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

/// Sign a UTF-8 string message.
pub fn sign_string(signing_key: &SigningKey, message: &str) -> String {
    let sig = sign_message(signing_key, message.as_bytes());
    bs58::encode(sig.to_bytes()).into_string()
}

/// Verify a signature against a verifying key and message.
pub fn verify_signature(verifying_key: &VerifyingKey, message: &[u8], signature_b58: &str) -> Result<bool> {
    let sig_bytes = bs58::decode(signature_b58)
        .into_vec()
        .context("Invalid signature base58 encoding")?;

    if sig_bytes.len() != 64 {
        anyhow::bail!("Invalid signature: expected 64 bytes, got {}", sig_bytes.len());
    }

    let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
    let signature = Signature::from_bytes(&sig_arr);
    Ok(verifying_key.verify_strict(message, &signature).is_ok())
}

/// Verify a signature for a UTF-8 string message.
pub fn verify_string(verifying_key: &VerifyingKey, message: &str, signature_b58: &str) -> Result<bool> {
    verify_signature(verifying_key, message.as_bytes(), signature_b58)
}

/// Format a message the way Solana wallets do for off-chain signing.
fn format_solana_offchain_message(message: &str) -> String {
    format!("\x13Solana Signed Message:\n{}{}", message.len(), message)
}

/// Sign in Solana off-chain message format.
pub fn sign_solana_message(signing_key: &SigningKey, message: &str) -> String {
    let formatted = format_solana_offchain_message(message);
    let sig = sign_message(signing_key, formatted.as_bytes());
    bs58::encode(sig.to_bytes()).into_string()
}

/// Verify a Solana off-chain signed message.
pub fn verify_solana_message(verifying_key: &VerifyingKey, message: &str, signature_b58: &str) -> Result<bool> {
    let formatted = format_solana_offchain_message(message);
    verify_signature(verifying_key, formatted.as_bytes(), signature_b58)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen;

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let k = keygen::generate_random().unwrap();
        let sig = sign_string(&k.signing_key, "hello world");
        assert!(verify_string(&k.verifying_key, "hello world", &sig).unwrap());
    }

    #[test]
    fn test_wrong_message_fails() {
        let k = keygen::generate_random().unwrap();
        let sig = sign_string(&k.signing_key, "original");
        assert!(!verify_string(&k.verifying_key, "tampered", &sig).unwrap());
    }

    #[test]
    fn test_wrong_key_fails() {
        let k1 = keygen::generate_random().unwrap();
        let k2 = keygen::generate_random().unwrap();
        let sig = sign_string(&k1.signing_key, "test");
        assert!(!verify_string(&k2.verifying_key, "test", &sig).unwrap());
    }

    #[test]
    fn test_solana_message_format() {
        let k = keygen::generate_random().unwrap();
        let sig = sign_solana_message(&k.signing_key, "Login to dApp");
        assert!(verify_solana_message(&k.verifying_key, "Login to dApp", &sig).unwrap());
    }
}
