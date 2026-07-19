//! `solana-km` — Solana Key Manager CLI.

mod crypto;
mod keygen;
mod sign;
mod wallet;

use anyhow::Context;
use clap::{Parser, Subcommand};
use colored::*;
use ed25519_dalek::VerifyingKey;

#[derive(Parser)]
#[command(name = "solana-km", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Generate {
        #[arg(long, default_value = "12")]
        words: usize,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        ephemeral: bool,
    },
    Restore {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        password: Option<String>,
    },
    Import {
        #[arg(long)]
        file: Option<String>,
        #[arg(long)]
        secret: Option<String>,
        name: String,
        #[arg(long)]
        password: String,
    },
    Export {
        name: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        json: bool,
    },
    Sign {
        name: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        message: Option<String>,
        #[arg(long)]
        solana_format: bool,
    },
    Verify {
        public_key: String,
        #[arg(long)]
        message: String,
        #[arg(long)]
        signature: String,
    },
    List,
    Show {
        name: String,
        #[arg(long)]
        reveal_secret: bool,
    },
    Delete { name: String },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate { words, name, password, ephemeral } => handle_generate(words, name, password, ephemeral),
        Command::Restore { name, password } => handle_restore(name, password),
        Command::Import { file, secret, name, password } => handle_import(file, secret, &name, &password),
        Command::Export { name, password, json } => handle_export(&name, &password, json),
        Command::Sign { name, password, message, solana_format } => handle_sign(&name, &password, message, solana_format),
        Command::Verify { public_key, message, signature } => handle_verify(&public_key, &message, &signature),
        Command::List => handle_list(),
        Command::Show { name, reveal_secret } => handle_show(&name, reveal_secret),
        Command::Delete { name } => handle_delete(&name),
    }
}

fn handle_generate(words: usize, name: Option<String>, password: Option<String>, ephemeral: bool) -> anyhow::Result<()> {
    let generated = keygen::generate_from_mnemonic(words)?;

    println!();
    println!("{}", "New Keypair Generated".green().bold());
    println!("  {}  {}", "Public Key:".dimmed(), generated.pubkey_base58.yellow());
    println!();
    println!("{} ({} words)", "Mnemonic:".dimmed(), generated.mnemonic.as_ref().map(|m| m.split_whitespace().count()).unwrap_or(0));
    println!("  {}", "══════════════════════════════════════════════".bright_yellow());
    println!("  {}", "WRITE THIS DOWN. NEVER SHARE IT.".bright_yellow());
    println!("  {}", "══════════════════════════════════════════════".bright_yellow());
    println!("  {}", generated.mnemonic.as_deref().unwrap_or("N/A").bright_white());
    println!("  {}", "══════════════════════════════════════════════".bright_yellow());
    println!();

    if ephemeral {
        println!("{}", "Ephemeral mode — key NOT saved.".bright_yellow());
        return Ok(());
    }

    let identity_name = name.unwrap_or_else(|| format!("wallet-{}", &generated.pubkey_base58[..8]));
    let pw = password.unwrap_or_else(|| rpassword::prompt_password("Encryption password: ").unwrap());

    wallet::save_identity(&identity_name, &generated.signing_key, &pw, true)?;
    println!("{}", format!("Saved as '{}'.", identity_name).green());
    Ok(())
}

fn handle_restore(name: Option<String>, password: Option<String>) -> anyhow::Result<()> {
    let mnemonic = rpassword::prompt_password("Enter BIP39 mnemonic: ")?;
    let generated = keygen::restore_from_mnemonic(&mnemonic)?;

    println!();
    println!("{}", "Keypair Restored".green().bold());
    println!("  {}  {}", "Public Key:".dimmed(), generated.pubkey_base58.yellow());

    let identity_name = name.unwrap_or_else(|| format!("wallet-{}", &generated.pubkey_base58[..8]));
    let pw = password.unwrap_or_else(|| rpassword::prompt_password("Encryption password: ").unwrap());

    wallet::save_identity(&identity_name, &generated.signing_key, &pw, true)?;
    println!("{}", format!("Saved as '{}'.", identity_name).green());
    Ok(())
}

fn handle_import(file: Option<String>, secret: Option<String>, name: &str, password: &str) -> anyhow::Result<()> {
    let generated = if let Some(path) = file {
        keygen::import_from_json(&std::fs::read(&path)?)?
    } else if let Some(s) = secret {
        keygen::import_from_base58(&s)?
    } else {
        anyhow::bail!("Provide --file or --secret.");
    };
    wallet::save_identity(name, &generated.signing_key, password, false)?;
    println!();
    println!("{}", "Keypair Imported".green().bold());
    println!("  {}  {}", "Name:".dimmed(), name);
    println!("  {}  {}", "Public Key:".dimmed(), generated.pubkey_base58.yellow());
    Ok(())
}

fn handle_export(name: &str, password: &str, as_json: bool) -> anyhow::Result<()> {
    let identity = wallet::load_identity(name, password)?;
    let signing_key = identity.decrypt_signing_key(password)?;

    if as_json {
        println!("{}", keygen::export_to_json(&signing_key));
    } else {
        println!("{}", keygen::export_to_base58(&signing_key));
    }
    println!("{}", "Secret key printed. Clear your terminal after use.".bright_yellow());
    Ok(())
}

fn handle_sign(name: &str, password: &str, message: Option<String>, solana_format: bool) -> anyhow::Result<()> {
    let identity = wallet::load_identity(name, password)?;
    let signing_key = identity.decrypt_signing_key(password)?;

    let msg = message.unwrap_or_else(|| rpassword::prompt_password("Message to sign: ").unwrap());

    let signature = if solana_format {
        sign::sign_solana_message(&signing_key, &msg)
    } else {
        sign::sign_string(&signing_key, &msg)
    };

    println!();
    println!("{}", "Message Signed".green().bold());
    println!("  {}  {}", "Signer:".dimmed(), identity.pubkey.yellow());
    println!("  {}      {}", "Signature:".dimmed(), signature.bright_white());
    Ok(())
}

fn handle_verify(public_key: &str, message: &str, signature: &str) -> anyhow::Result<()> {
    let pk_bytes = bs58::decode(public_key).into_vec().context("Invalid public key")?;
    if pk_bytes.len() != 32 {
        anyhow::bail!("Expected 32-byte public key, got {}", pk_bytes.len());
    }
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes.try_into().unwrap())?;

    let valid = sign::verify_string(&verifying_key, message, signature)?;
    println!();
    if valid {
        println!("{}", "Signature Valid".green().bold());
    } else {
        println!("{}", "Signature INVALID".red().bold());
    }
    Ok(())
}

fn handle_list() -> anyhow::Result<()> {
    let identities = wallet::list_identities()?;
    println!();
    if identities.is_empty() {
        println!("{}", "No identities stored.".dimmed());
        return Ok(());
    }
    println!("{}", "Stored Identities".green().bold());
    println!();
    for id in &identities {
        let kind = if id.has_mnemonic { "mnemonic" } else { "imported" };
        println!("  {:<20} {:<48} {}", id.name.cyan(), id.pubkey.dimmed(), kind.dimmed());
    }
    println!();
    println!("{}", format!("{} identities.", identities.len()).dimmed());
    Ok(())
}

fn handle_show(name: &str, reveal_secret: bool) -> anyhow::Result<()> {
    let password = rpassword::prompt_password("Password: ")?;
    let identity = wallet::load_identity(name, &password)?;

    println!();
    println!("{}", format!("{}", name).green().bold());
    println!("  {}  {}", "Public Key:".dimmed(), identity.pubkey.yellow());

    if reveal_secret {
        let signing_key = identity.decrypt_signing_key(&password)?;
        println!();
        println!("{}", "SECRET KEY — Never share!".bright_yellow().bold());
        println!("  {}", keygen::export_to_base58(&signing_key).bright_white());
    }
    Ok(())
}

fn handle_delete(name: &str) -> anyhow::Result<()> {
    wallet::delete_identity(name)?;
    println!("{}", format!("Deleted '{}'.", name).green());
    Ok(())
}
