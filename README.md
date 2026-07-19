# Solana Key Manager

Secure ed25519 keypair manager for Solana. Generate, encrypt, sign — no plaintext keys on disk.

```
$ solana-km generate --name main --words 24

🔑 New Keypair Generated
  Public Key:  7xK2V...sender
  Mnemonic: (24 words)
  ══════════════════════════════════════════════
  ⚠  WRITE THIS DOWN. NEVER SHARE IT.
  ══════════════════════════════════════════════
  abandon ... ... ... ... ... ... ... ... ... zoo
  ══════════════════════════════════════════════

Encryption password: ********
✓ Saved as 'main' in wallet.
```

## Features

- **BIP39 Mnemonics** — 12 or 24 word phrases (256-bit entropy)
- **AES-256-GCM Encryption** — every keypair encrypted at rest with Argon2id PBKDF
- **Offline Signing** — sign messages without network connectivity
- **Solana Off-Chain Format** — compatible with Phantom / Solana CLI signing
- **Import/Export** — keypair.json, base58 secret key, mnemonic restore
- **Multiple Identities** — manage dev, mainnet, test wallets from one CLI
- **Signature Verification** — verify any ed25519 signature against a public key

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

## Installation

```bash
cargo install --git https://github.com/user/solana-key-manager
```

## Usage

```bash
# Generate a 24-word mnemonic wallet
solana-km generate --name main --words 24

# Generate ephemeral (no save) — print and forget
solana-km generate --ephemeral

# Restore from mnemonic
solana-km restore --name recovered

# Import existing keypair.json
solana-km import main --file ~/.config/solana/id.json

# Sign a message
solana-km sign main --message "Hello, Solana!"

# Sign in Solana off-chain format
solana-km sign main --message "Login to dApp" --solana-format

# Verify a signature
solana-km verify 7xK...pubkey --message "Hello" --signature 5nS...sig

# List all stored identities
solana-km list

# Export secret key (DANGEROUS)
solana-km export main --json
```

## Security Model

```
┌──────────┐     Argon2id      ┌──────────┐     AES-256-GCM    ┌──────────────┐
│ Password │ ────────────────▶ │ 256-bit   │ ────────────────▶ │ Encrypted    │
│          │   (19 MiB, 2x)    │ Key       │   (random nonce)  │ Keypair.enc  │
└──────────┘                   └──────────┘                    └──────────────┘
```

- **Passwords never stored** — only verified via AEAD authentication
- **Unique salt + nonce per encryption** — same plaintext produces different ciphertext
- **Argon2id with 19 MiB memory** — resistant to GPU brute-force
- **Key material zeroized** — `zeroize` crate ensures memory cleanup after use
- **No network calls** for generate/sign/verify — fully offline capable

## Wallet Storage

```
~/.solana-key-manager/
├── identities/
│   ├── main.enc        # AES-256-GCM encrypted keypair
│   ├── dev.enc
│   └── test.enc
└── config.toml         # Wallet config marker
```

## Architecture

```
src/
├── main.rs       # CLI entry point (clap + 9 subcommands)
├── keygen.rs     # Keypair generation, BIP39, import/export
├── crypto.rs     # AES-256-GCM encrypt/decrypt with Argon2id
├── wallet.rs     # Identity storage and retrieval
└── sign.rs       # ed25519 signing and verification
```

## Tech Stack

| Component | Crate | Purpose |
|-----------|-------|---------|
| CLI | `clap` 4 | Argument parsing |
| Keypair | `ed25519-dalek` 2 + `solana-sdk` | Key generation, signing |
| Mnemonic | `bip39` 2 | BIP39 phrase generation and validation |
| Encryption | `aes-gcm` 0.10 | AES-256-GCM authenticated encryption |
| PBKDF | `argon2` 0.5 | Argon2id key derivation (OWASP recommended) |
| Encoding | `bs58`, `base64` | Solana address/secret encoding |
| Security | `zeroize` 1 | Secure memory cleanup |
| Password | `rpassword` 7 | Hidden password prompt in terminal |

## License

MIT
