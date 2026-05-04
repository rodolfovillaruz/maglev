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
// Generic prompt helpers
// ---------------------------------------------------------------------------

/// Ask a yes/no question. Returns `true` only for "y" or "yes".
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

/// Prompt for a required field. Returns an error if the user submits an empty
/// string and no default is available.
///
/// * `label`    – displayed to the user.
/// * `env_var`  – if `Some("VAR")`, the current value of that env var is shown
///                as a default and accepted on empty input.
fn prompt_field(label: &str, env_var: Option<&str>) -> Result<String, Box<dyn std::error::Error>> {
    let default = env_var.and_then(|var| env::var(var).ok());

    match &default {
        Some(val) => {
            print!("  {label} [{val}]: ");
            io::stdout()
                .flush()
                .map_err(|e| format!("Failed to flush stdout: {e}"))?;

            let mut line = String::new();
            io::stdin()
                .lock()
                .read_line(&mut line)
                .map_err(|e| format!("Failed to read from stdin: {e}"))?;

            let input = line.trim().to_string();
            Ok(if input.is_empty() { val.clone() } else { input })
        }
        None => {
            print!("  {label}: ");
            io::stdout()
                .flush()
                .map_err(|e| format!("Failed to flush stdout: {e}"))?;

            let mut line = String::new();
            io::stdin()
                .lock()
                .read_line(&mut line)
                .map_err(|e| format!("Failed to read from stdin: {e}"))?;

            let input = line.trim().to_string();
            if input.is_empty() {
                Err(format!("'{label}' cannot be empty").into())
            } else {
                Ok(input)
            }
        }
    }
}

/// Like `prompt_field`, but falls back to `hardcoded_default` when neither the
/// env var nor user input provides a value.
fn prompt_field_with_default(
    label: &str,
    env_var: Option<&str>,
    hardcoded_default: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let default = env_var
        .and_then(|var| env::var(var).ok())
        .unwrap_or_else(|| hardcoded_default.to_string());

    print!("  {label} [{default}]: ");
    io::stdout()
        .flush()
        .map_err(|e| format!("Failed to flush stdout: {e}"))?;

    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("Failed to read from stdin: {e}"))?;

    let input = line.trim().to_string();
    Ok(if input.is_empty() { default } else { input })
}

// ---------------------------------------------------------------------------
// Credential-builder–specific helpers (kept from original)
// ---------------------------------------------------------------------------

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

fn public_key_info(
    private_key_pem: &str,
    client_email: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    use sha2::{Digest, Sha256};
    use time::{Duration, OffsetDateTime};

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
// `generate` subcommand
// ---------------------------------------------------------------------------

/// Render aligned key-value pairs inside a block.
///
/// The `=` sign is aligned to one column past the longest key so that the
/// output matches the style shown in the spec:
///
/// ```text
/// kubernetes_instance = {
///   name    = "my-k8s-cluster"
///
///   maglev = {
///     client_email  = "…"
///     instance_name = "…"
///     …
///   }
/// }
/// ```
fn format_config(
    name: &str,
    client_email: &str,
    instance_name: &str,
    machine_type: &str,
    private_key: &str,
    project_id: &str,
    zone: &str,
) -> String {
    let maglev_fields: &[(&str, &str)] = &[
        ("client_email", client_email),
        ("instance_name", instance_name),
        ("machine_type", machine_type),
        ("private_key", private_key),
        ("project_id", project_id),
        ("zone", zone),
    ];

    // Align `=` one space past the longest key in the inner block.
    let max_key = maglev_fields
        .iter()
        .map(|(k, _)| k.len())
        .max()
        .unwrap_or(0);

    let maglev_body: String = maglev_fields
        .iter()
        .map(|(key, value)| {
            let pad = " ".repeat(max_key - key.len() + 1);
            format!("    {key}{pad}= \"{value}\"\n")
        })
        .collect();

    // The outer block currently has only `name`; pad it to 8 chars (matching
    // the spec's `name    =`) so future outer keys can align naturally.
    format!(
        "kubernetes_instance = {{\n  name    = \"{name}\"\n\n  maglev = {{\n{maglev_body}  }}\n}}\n"
    )
}

fn run_generate() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Config Generator ===\n");

    // ── Outer block ──────────────────────────────────────────────────────────

    println!("Kubernetes instance settings:");
    let name = prompt_field("name", None)?;

    // ── Maglev block ─────────────────────────────────────────────────────────

    println!("\nMaglev settings (press Enter to accept the shown default):");

    let client_email = prompt_field("client_email", Some("MAGLEV_CLIENT_EMAIL"))?;

    // Derive a sensible default instance name from the outer `name`.
    let instance_name_default = format!("maglev-vm-{name}");
    let instance_name = prompt_field_with_default(
        "instance_name",
        Some("MAGLEV_INSTANCE_NAME"),
        &instance_name_default,
    )?;

    let machine_type =
        prompt_field_with_default("machine_type", Some("MAGLEV_MACHINE_TYPE"), "e2-micro")?;

    let private_key = prompt_field_with_default(
        "private_key",
        Some("MAGLEV_PRIVATE_KEY"),
        ".keys/private_key.pem",
    )?;

    // Derive project ID from `<account>@<project>.iam.gserviceaccount.com`
    // when MAGLEV_PROJECT_ID is not set.
    let derived_project = client_email
        .split('@')
        .nth(1)
        .and_then(|domain| domain.split('.').next())
        .unwrap_or("my-project")
        .to_string();

    let project_id =
        prompt_field_with_default("project_id", Some("MAGLEV_PROJECT_ID"), &derived_project)?;

    let zone = prompt_field_with_default("zone", Some("MAGLEV_ZONE"), "us-central1-a")?;

    // ── Render ───────────────────────────────────────────────────────────────

    let config = format_config(
        &name,
        &client_email,
        &instance_name,
        &machine_type,
        &private_key,
        &project_id,
        &zone,
    );

    println!("\n── Generated config ────────────────────────────────────────────────────\n");
    println!("{config}");

    // ── Optionally save ──────────────────────────────────────────────────────

    if prompt_yes_no("Save config to file?") {
        let filename = format!("{name}.maglev");
        fs::write(&filename, &config)
            .map_err(|e| format!("Cannot write config to '{filename}': {e}"))?;
        println!("✓ Config saved to: {filename}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Original credential-builder flow (was `main`)
// ---------------------------------------------------------------------------

fn run_credential_builder() -> Result<(), Box<dyn std::error::Error>> {
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

    println!("\n── Credentials ─────────────────────────────────────────────────────────\n");

    let credentials = ServiceAccountCredentials {
        credential_type: "service_account".to_string(),
        private_key: private_key.clone(),
        client_email: client_email.clone(),
    };

    let json_str = serde_json::to_string_pretty(&credentials)?;
    println!("{json_str}");

    // ── Save credentials ─────────────────────────────────────────────────────

    if prompt_yes_no("\nSave credentials to file?") {
        let filename = format!(
            "maglev-credentials-{}.json",
            client_email.split('@').next().unwrap_or("account")
        );

        let json_str = serde_json::to_string_pretty(&credentials)?;
        fs::write(&filename, json_str).map_err(|e| format!("Cannot write credentials: {e}"))?;

        println!("✓ Credentials saved to: {filename}");
        println!("⚠ Keep this file secure!");
    }

    // ── Create a VM instance ─────────────────────────────────────────────────

    if prompt_yes_no("\nCreate a VM instance now?") {
        let project_id = if let Ok(p) = env::var("MAGLEV_PROJECT_ID") {
            p
        } else {
            client_email
                .split('@')
                .nth(1)
                .and_then(|domain| domain.split('.').next())
                .map(|s| s.to_string())
                .ok_or("Cannot derive project ID from client_email; set MAGLEV_PROJECT_ID")?
        };

        let zone = env::var("MAGLEV_ZONE").unwrap_or_else(|_| "us-central1-a".to_string());
        let machine_type =
            env::var("MAGLEV_MACHINE_TYPE").unwrap_or_else(|_| "e2-micro".to_string());
        let instance_name = env::var("MAGLEV_INSTANCE_NAME").unwrap_or_else(|_| {
            format!(
                "maglev-vm-{}",
                time::OffsetDateTime::now_utc().unix_timestamp()
            )
        });

        println!("\n── Creating VM instance ────────────────────────────────────────────────");
        println!("  Project:      {project_id}");
        println!("  Zone:         {zone}");
        println!("  Machine type: {machine_type}");
        println!("  Name:         {instance_name}");

        println!("  Signing JWT with RSA-SHA256 (PEM-native)...");
        let jwt = create_jwt(
            &private_key,
            &client_email,
            "https://www.googleapis.com/auth/compute",
        )?;

        println!("  Exchanging JWT for OAuth2 access token...");
        let access_token = get_access_token(&jwt)?;

        println!("  Calling Compute Engine API...");
        let response = create_vm(
            &access_token,
            &project_id,
            &zone,
            &instance_name,
            &machine_type,
        )?;

        println!("\n✓ VM creation requested. Operation response:\n");
        println!("{}", serde_json::to_string_pretty(&response)?);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point — subcommand dispatch
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    match env::args().nth(1).as_deref() {
        Some("generate") => run_generate(),
        Some(unknown) => {
            eprintln!("error: unknown subcommand '{unknown}'");
            eprintln!();
            eprintln!("USAGE:");
            eprintln!("    maglev [SUBCOMMAND]");
            eprintln!();
            eprintln!("SUBCOMMANDS:");
            eprintln!("    generate    Interactively generate a .maglev config file");
            eprintln!("    (none)      Run the credential builder (default)");
            std::process::exit(1);
        }
        None => run_credential_builder(),
    }
}

// ---------------------------------------------------------------------------
// JWT (RS256)
// ---------------------------------------------------------------------------

fn b64url(input: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

fn create_jwt(
    private_key_pem: &str,
    client_email: &str,
    scope: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use rsa::{RsaPrivateKey, pkcs1v15::Pkcs1v15Sign, pkcs8::DecodePrivateKey};
    use sha2::{Digest, Sha256};

    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)?;

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let exp = now + 3600;

    let header = r#"{"alg":"RS256","typ":"JWT"}"#;
    let claims = format!(
        r#"{{"iss":"{}","scope":"{}","aud":"https://oauth2.googleapis.com/token","exp":{},"iat":{}}}"#,
        client_email, scope, exp, now
    );

    let signing_input = format!(
        "{}.{}",
        b64url(header.as_bytes()),
        b64url(claims.as_bytes())
    );
    let hash = Sha256::digest(signing_input.as_bytes());

    const SHA256_DIGEST_INFO: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let mut to_sign = Vec::with_capacity(SHA256_DIGEST_INFO.len() + hash.len());
    to_sign.extend_from_slice(&SHA256_DIGEST_INFO);
    to_sign.extend_from_slice(&hash);

    let signature = private_key.sign(Pkcs1v15Sign::new_unprefixed(), &to_sign)?;

    Ok(format!("{}.{}", signing_input, b64url(&signature)))
}

fn get_access_token(jwt: &str) -> Result<String, Box<dyn std::error::Error>> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();

    let mut resp = agent
        .post("https://oauth2.googleapis.com/token")
        .send_form([
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", jwt),
        ])?;

    let status = resp.status();
    let body: Value = resp.body_mut().read_json()?;

    if !status.is_success() {
        return Err(format!("Token endpoint returned HTTP {status}: {body}").into());
    }

    body["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("No access_token in response: {body}").into())
}

fn create_vm(
    access_token: &str,
    project_id: &str,
    zone: &str,
    instance_name: &str,
    machine_type: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}/instances"
    );

    let request_body = serde_json::json!({
        "name": instance_name,
        "machineType": format!("zones/{zone}/machineTypes/{machine_type}"),
        "disks": [{
            "boot": true,
            "autoDelete": true,
            "initializeParams": {
                "sourceImage": "projects/debian-cloud/global/images/family/debian-12"
            }
        }],
        "networkInterfaces": [{
            "network": "global/networks/default",
            "accessConfigs": [{
                "type": "ONE_TO_ONE_NAT",
                "name": "External NAT"
            }]
        }]
    });

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();

    let mut resp = agent
        .post(&url)
        .header("Authorization", &format!("Bearer {access_token}"))
        .header("Content-Type", "application/json")
        .send_json(request_body)?;

    let status = resp.status();
    let body: Value = resp.body_mut().read_json()?;

    if !status.is_success() {
        return Err(format!("Compute Engine API returned HTTP {status}: {body}").into());
    }

    Ok(body)
}
