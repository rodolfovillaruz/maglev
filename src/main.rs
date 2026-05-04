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

fn prompt_client_email() -> Result<String, Box<dyn std::error::Error>> {
    print!("  Enter client email: ");
    io::stdout()
        .flush()
        .map_err(|e| format!("Failed to flush stdout: {e}"))?;

    let stdin = io::stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("Failed to read from stdin: {e}"))?;

    let email = line.trim().to_string();

    if email.is_empty() {
        Err("Client email cannot be empty. Aborted.".into())
    } else {
        Ok(email)
    }
}

fn generate_rsa_private_key_pem() -> Result<String, Box<dyn std::error::Error>> {
    use rsa::{
        RsaPrivateKey,
        pkcs8::{EncodePrivateKey, LineEnding},
    };

    println!("  Generating RSA-2048 private key (this may take a moment)...");

    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let pem = private_key.to_pkcs8_pem(LineEnding::LF)?;

    Ok(pem.to_string())
}

// ---------------------------------------------------------------------------
// Build a self-signed X.509 certificate from the RSA private key.
//
// Google Cloud's "Upload public key" expects an RSA_X509_PEM, i.e. a
// PEM-encoded X.509 certificate (NOT a bare SPKI public key).
// ---------------------------------------------------------------------------

fn public_key_info(
    private_key_pem: &str,
    client_email: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    use sha2::{Digest, Sha256};
    use time::{Duration, OffsetDateTime};

    // rcgen detects RSA from the PKCS#8 PEM and signs the cert with it.
    let key_pair = KeyPair::from_pem(private_key_pem)?;

    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, client_email);
    params.distinguished_name = dn;

    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::minutes(5);
    params.not_after = now + Duration::days(365 * 10);

    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem();
    let cert_der = cert.der();

    // Google displays the SHA-256 of the certificate DER as the key id
    // for uploaded user-managed keys. Render it as colon-separated hex.
    let digest = Sha256::digest(cert_der.as_ref());
    let fingerprint = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");

    Ok((cert_pem, fingerprint))
}

// ---------------------------------------------------------------------------
// Load credentials from GOOGLE_APPLICATION_CREDENTIALS
// ---------------------------------------------------------------------------

fn load_google_application_credentials()
-> Option<Result<(String, String), Box<dyn std::error::Error>>> {
    let path = env::var("GOOGLE_APPLICATION_CREDENTIALS").ok()?;

    println!("GOOGLE_APPLICATION_CREDENTIALS = {path}");

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
// Load or generate credentials from MAGLEV_PRIVATE_KEY
// ---------------------------------------------------------------------------

fn load_maglev_private_key() -> Result<(String, String), Box<dyn std::error::Error>> {
    let key_path = env::var("MAGLEV_PRIVATE_KEY")
        .map_err(|_| "MAGLEV_PRIVATE_KEY environment variable is not set")?;

    println!("MAGLEV_PRIVATE_KEY = {key_path}");

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

    let client_email = env::var("MAGLEV_CLIENT_EMAIL").or_else(|_| {
        println!("  MAGLEV_CLIENT_EMAIL not set.");
        prompt_client_email()
    })?;

    Ok((private_key, client_email))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Credential Builder ===\n");

    let (private_key, client_email) = match load_google_application_credentials() {
        Some(Ok(pair)) => {
            println!("  Using credentials from GOOGLE_APPLICATION_CREDENTIALS.\n");
            pair
        }
        Some(Err(e)) => return Err(e),
        None => {
            println!("  GOOGLE_APPLICATION_CREDENTIALS not set — falling through.\n");
            load_maglev_private_key()?
        }
    };

    // ── Public key & fingerprint ─────────────────────────────────────────────

    let (public_cert_pem, _) = public_key_info(&private_key, &client_email)?;

    println!("\n── Public certificate (RSA_X509_PEM) ──────────────────────────────────\n");
    println!("{public_cert_pem}");
    println!("Upload steps:");
    println!("  • IAM & Admin → Service Accounts → {client_email} → Keys");
    println!("    → Add Key → Upload public key, and paste the certificate above.");
    println!("  • Or via CLI:");
    println!("      gcloud iam service-accounts keys upload cert.pem \\");
    println!("        --iam-account={client_email}");
    println!("  • Verify locally with:");
    println!("      openssl x509 -in cert.pem -noout -fingerprint -sha256");

    // ── Credentials JSON ─────────────────────────────────────────────────────

    println!("── Credentials ─────────────────────────────────────────────────────────\n");

    let credentials = ServiceAccountCredentials {
        credential_type: "service_account".to_string(),
        private_key,
        client_email,
    };

    println!("{}", serde_json::to_string_pretty(&credentials)?);

    Ok(())
}
