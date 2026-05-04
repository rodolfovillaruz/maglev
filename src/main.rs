use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct ServiceAccountCredentials {
    #[serde(rename = "type")]
    credential_type: String,
    private_key: String,
    client_email: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn prompt_yes_no(question: &str) -> bool {
    print!("{question} [y/N]: ");
    io::stdout().flush().expect("Failed to flush stdout");

    let stdin = io::stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .expect("Failed to read input");

    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

fn generate_rsa_private_key_pem() -> Result<String, Box<dyn std::error::Error>> {
    use rand::rngs::OsRng;
    use rsa::{
        pkcs8::{EncodePrivateKey, LineEnding},
        RsaPrivateKey,
    };

    println!("  Generating RSA-2048 private key (this may take a moment)...");

    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let pem = private_key.to_pkcs8_pem(LineEnding::LF)?;

    Ok(pem.to_string())
}

// ---------------------------------------------------------------------------
// Step 1 — GOOGLE_APPLICATION_CREDENTIALS
// ---------------------------------------------------------------------------

/// Returns:
///   `Some(Ok((private_key, client_email)))` – env var was set and file parsed
///   `Some(Err(...))` – env var was set but something went wrong
///   `None`           – env var is not set; caller should fall through to step 2
fn step1_google_application_credentials(
) -> Option<Result<(String, String), Box<dyn std::error::Error>>> {
    let path = env::var("GOOGLE_APPLICATION_CREDENTIALS").ok()?;

    println!("[Step 1] GOOGLE_APPLICATION_CREDENTIALS = {path}");

    let result = (|| {
        let content =
            fs::read_to_string(&path).map_err(|e| format!("Cannot read '{path}': {e}"))?;

        let json: Value = serde_json::from_str(&content)
            .map_err(|e| format!("Cannot parse JSON from '{path}': {e}"))?;

        let private_key = json["private_key"]
            .as_str()
            .ok_or("Missing 'private_key' field in credentials file")?
            .to_string();

        let client_email = json["client_email"]
            .as_str()
            .ok_or("Missing 'client_email' field in credentials file")?
            .to_string();

        Ok((private_key, client_email))
    })();

    Some(result)
}

// ---------------------------------------------------------------------------
// Step 2 — MAGLEV_PRIVATE_KEY
// ---------------------------------------------------------------------------

fn step2_maglev_private_key() -> Result<(String, String), Box<dyn std::error::Error>> {
    let key_path = env::var("MAGLEV_PRIVATE_KEY")
        .map_err(|_| "MAGLEV_PRIVATE_KEY environment variable is not set")?;

    println!("[Step 2] MAGLEV_PRIVATE_KEY = {key_path}");

    let private_key = if Path::new(&key_path).exists() {
        println!("  Key file found — reading...");

        fs::read_to_string(&key_path).map_err(|e| format!("Cannot read '{key_path}': {e}"))?
    } else {
        println!("  Key file does not exist at: {key_path}");

        if !prompt_yes_no("  Would you like to generate and save a new RSA-2048 private key?") {
            eprintln!("  Aborted by user.");
            std::process::exit(1);
        }

        let pem = generate_rsa_private_key_pem()?;

        // Ensure parent directories exist
        if let Some(parent) = Path::new(&key_path).parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Cannot create parent directories: {e}"))?;
            }
        }

        fs::write(&key_path, &pem)
            .map_err(|e| format!("Cannot write private key to '{key_path}': {e}"))?;

        println!("  Private key saved to: {key_path}");
        pem
    };

    // client_email must be supplied separately when using a raw key file
    let client_email = env::var("MAGLEV_CLIENT_EMAIL").map_err(|_| {
        "MAGLEV_CLIENT_EMAIL environment variable is not set \
         (required when using MAGLEV_PRIVATE_KEY)"
    })?;

    Ok((private_key, client_email))
}

// ---------------------------------------------------------------------------
// Step 3 — Build in-memory service account JSON
// ---------------------------------------------------------------------------

fn step3_build_credentials(private_key: String, client_email: String) -> ServiceAccountCredentials {
    ServiceAccountCredentials {
        credential_type: "service_account".to_string(),
        private_key,
        client_email,
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Credential Builder ===\n");

    // ── Step 1 ──────────────────────────────────────────────────────────────
    let (private_key, client_email) = match step1_google_application_credentials() {
        Some(Ok(pair)) => {
            println!("  Using credentials from GOOGLE_APPLICATION_CREDENTIALS.\n");
            pair
        }
        Some(Err(e)) => {
            return Err(e);
        }
        None => {
            println!("  GOOGLE_APPLICATION_CREDENTIALS not set — falling through.\n");

            // ── Step 2 ──────────────────────────────────────────────────────
            step2_maglev_private_key()?
        }
    };

    // ── Step 3 ──────────────────────────────────────────────────────────────
    println!("\n[Step 3] Building in-memory service account credentials...");

    let credentials = step3_build_credentials(private_key, client_email);
    let json = serde_json::to_string_pretty(&credentials)?;

    println!("  Done.\n");
    println!("{json}");

    Ok(())
}
