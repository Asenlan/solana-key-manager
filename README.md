# Solana Key Manager

[中文](README_CN.md) | [English](README.md)

---

Secure ed25519 keypair manager. Generate, encrypt, sign — never store plaintext private keys.

## Features

- **BIP39 Mnemonics** — 12 or 24 word phrases (128/256-bit entropy)
- **AES-256-GCM Encryption** — All keypairs encrypted at rest with Argon2id key derivation
- **Offline Signing** — Sign messages without network connectivity
- **Solana Off-Chain Format** — Compatible with Phantom wallet / Solana CLI signing
- **Import/Export** — keypair.json, base58 secret key, mnemonic restore
- **Multiple Identities** — Manage dev, mainnet, test wallets from one CLI
- **Signature Verification** — Verify any ed25519 signature against a public key

## Commands

| Command | Description |
|---------|-------------|
| `generate` | New keypair + BIP39 mnemonic, encrypted to disk |
| `restore` | Recover keypair from mnemonic phrase |
| `import` | Add existing keypair from file or base58 key |
| `export` | Output secret key (with warning) |
| `sign` | Sign a message with stored identity |
| `verify` | Verify signature ↔ message ↔ pubkey |
| `list` | Show all stored identities |
| `show` | Display public key and metadata |
| `delete` | Remove identity from wallet |

## Security Model

```
Password ──Argon2id(19MiB, 2 rounds)──▶ 256-bit Key ──AES-256-GCM──▶ Encrypted File
                                          (random nonce)           (~/.solana-key-manager/)
```

- **Passwords never stored** — verified via AEAD authentication
- **Unique salt + nonce per encryption** — same plaintext produces different ciphertext
- **Argon2id 19 MiB** — resistant to GPU brute-force
- **Key material zeroized** — memory cleanup after use

## Tech Stack

- **ed25519-dalek** — Key generation and signing
- **bip39** — Mnemonic generation and validation
- **aes-gcm + argon2** — Encryption and key derivation
- **bs58** — Solana address encoding
- **clap** — CLI argument parsing

## License

MIT
