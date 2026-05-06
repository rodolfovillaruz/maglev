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

// ---------------------------------------------------------------------------
// Credential-builder–specific helpers
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
// SSH key / startup-script helpers
// ---------------------------------------------------------------------------

/// Read the public key at `path`, expanding a leading `~` to `$HOME`.
fn read_ssh_public_key(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let expanded = expand_tilde(path);
    let content = fs::read_to_string(&expanded)
        .map_err(|e| format!("Cannot read SSH public key from '{expanded}': {e}"))?;
    Ok(content.trim().to_string())
}

/// Read the startup script at `path`; fall back to a sensible built-in default
/// when the file does not exist.
fn read_startup_script(path: &str) -> String {
    let expanded = expand_tilde(path);
    fs::read_to_string(&expanded)
        .unwrap_or_else(|_| "#!/bin/bash\nset -e\napt-get update\ncurl -fsSL https://github.com/rodolfovillaruz/cisak/releases/download/v0.1.10/cisak-v0.1.10-linux-amd64.tar.gz | tar -xz\ninstall -m 755 -o root -g root cisak /usr/local/bin/cisak\ncisak generate\ncisak install -y".to_string())
}

fn expand_tilde(path: &str) -> String {
    // Strip the leading `~` only when followed by a separator or end-of-string
    let after_tilde = if path == "~" {
        ""
    } else if path.starts_with("~/") || path.starts_with("~\\") {
        &path[1..] // keep the separator so joining is clean
    } else {
        return path.to_string();
    };

    let home = home_dir().unwrap_or_else(|| ".".to_string());
    format!("{}{}", home, after_tilde)
}

/// Cross-platform home directory lookup.
fn home_dir() -> Option<String> {
    // Unix: $HOME
    // Windows: %USERPROFILE%, then %HOMEDRIVE%%HOMEPATH%
    env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .ok()
        .or_else(|| {
            // Last-resort Windows fallback
            let drive = env::var("HOMEDRIVE").ok()?;
            let path = env::var("HOMEPATH").ok()?;
            Some(format!("{}{}", drive, path))
        })
}

/// Map a bare image family name to the full GCP image URI used by the API.
///
/// | Input                    | Resolved                                                             |
/// |--------------------------|----------------------------------------------------------------------|
/// | `ubuntu-2404-lts-amd64`  | `projects/ubuntu-os-cloud/global/images/family/ubuntu-2404-lts-amd64` |
/// | `debian-12`              | `projects/debian-cloud/global/images/family/debian-12`               |
/// | `cos-stable`             | `projects/cos-cloud/global/images/family/cos-stable`                 |
/// | anything containing `/`  | returned as-is (already a full path)                                 |
fn resolve_image(image: &str) -> String {
    if image.contains('/') {
        return image.to_string();
    }
    let project = if image.starts_with("ubuntu") {
        "ubuntu-os-cloud"
    } else if image.starts_with("debian") {
        "debian-cloud"
    } else if image.starts_with("cos") {
        "cos-cloud"
    } else if image.starts_with("rhel") {
        "rhel-cloud"
    } else if image.starts_with("rocky") {
        "rocky-linux-cloud"
    } else {
        "debian-cloud"
    };
    format!("projects/{project}/global/images/family/{image}")
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

#[allow(clippy::too_many_arguments)]
fn format_config(
    name: &str,
    boot_disk_image: &str,
    boot_disk_size_gb: &str,
    client_email: &str,
    instance_name: &str,
    machine_type: &str,
    private_key: &str,
    project_id: &str,
    ssh_public_key_path: &str,
    startup_script_path: &str,
    zone: &str,
) -> String {
    // Fields are listed alphabetically so the output is deterministic.
    let maglev_fields: &[(&str, &str)] = &[
        ("boot_disk_image", boot_disk_image),
        ("boot_disk_size_gb", boot_disk_size_gb),
        ("client_email", client_email),
        ("instance_name", instance_name),
        ("machine_type", machine_type),
        ("private_key", private_key),
        ("project_id", project_id),
        ("ssh_public_key_path", ssh_public_key_path),
        ("startup_script_path", startup_script_path),
        ("zone", zone),
    ];

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

    format!(
        "kubernetes_instance = {{\n  name    = \"{name}\"\n\n  maglev = {{\n{maglev_body}  }}\n}}\n"
    )
}

fn generate_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if Path::new(config_path).exists() {
        eprintln!("error: '{config_path}' already exists");
        std::process::exit(1);
    }

    // Derive the logical name from the file stem (e.g. "prod" from "prod.maglev").
    let name = Path::new(config_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("maglev")
        .to_string();

    // ── All values come from env vars; MAGLEV_CLIENT_EMAIL is required ───────

    let client_email = env::var("MAGLEV_CLIENT_EMAIL")
        .map_err(|_| "MAGLEV_CLIENT_EMAIL environment variable is not set")?;

    let derived_project = client_email
        .split('@')
        .nth(1)
        .and_then(|domain| domain.split('.').next())
        .unwrap_or("my-project")
        .to_string();

    let project_id = env::var("MAGLEV_PROJECT_ID").unwrap_or(derived_project);

    let private_key =
        env::var("MAGLEV_PRIVATE_KEY").unwrap_or_else(|_| ".keys/private_key.pem".to_string());

    let instance_name =
        env::var("MAGLEV_INSTANCE_NAME").unwrap_or_else(|_| format!("maglev-vm-{name}"));

    let machine_type = env::var("MAGLEV_MACHINE_TYPE").unwrap_or_else(|_| "e2-medium".to_string());

    let zone = env::var("MAGLEV_ZONE").unwrap_or_else(|_| "europe-north1-a".to_string());

    let boot_disk_image =
        env::var("MAGLEV_BOOT_DISK_IMAGE").unwrap_or_else(|_| "ubuntu-2404-lts-amd64".to_string());

    let boot_disk_size_gb =
        env::var("MAGLEV_BOOT_DISK_SIZE_GB").unwrap_or_else(|_| "50".to_string());

    let ssh_public_key_path = env::var("MAGLEV_SSH_PUBLIC_KEY_PATH")
        .unwrap_or_else(|_| "~/.ssh/id_ed25519.pub".to_string());

    let startup_script_path =
        env::var("MAGLEV_STARTUP_SCRIPT_PATH").unwrap_or_else(|_| "./startup.sh".to_string());

    // ── Render & write ────────────────────────────────────────────────────────

    let config = format_config(
        &name,
        &boot_disk_image,
        &boot_disk_size_gb,
        &client_email,
        &instance_name,
        &machine_type,
        &private_key,
        &project_id,
        &ssh_public_key_path,
        &startup_script_path,
        &zone,
    );

    fs::write(config_path, &config)
        .map_err(|e| format!("Cannot write config to '{config_path}': {e}"))?;

    println!("✓ Config written to: {config_path}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Original credential-builder flow
// ---------------------------------------------------------------------------

fn print_build_credential() -> Result<(), Box<dyn std::error::Error>> {
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
        fs::write(&filename, serde_json::to_string_pretty(&credentials)?)
            .map_err(|e| format!("Cannot write credentials: {e}"))?;
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

        let zone = env::var("MAGLEV_ZONE").unwrap_or_else(|_| "europe-north1-a".to_string());
        let machine_type =
            env::var("MAGLEV_MACHINE_TYPE").unwrap_or_else(|_| "e2-medium".to_string());
        let instance_name = env::var("MAGLEV_INSTANCE_NAME").unwrap_or_else(|_| {
            format!(
                "maglev-vm-{}",
                time::OffsetDateTime::now_utc().unix_timestamp()
            )
        });
        let boot_disk_image = env::var("MAGLEV_BOOT_DISK_IMAGE")
            .unwrap_or_else(|_| "ubuntu-2404-lts-amd64".to_string());
        let boot_disk_size_gb: u64 = env::var("MAGLEV_BOOT_DISK_SIZE_GB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);
        let ssh_key_path = env::var("MAGLEV_SSH_PUBLIC_KEY_PATH")
            .unwrap_or_else(|_| "~/.ssh/id_ed25519.pub".to_string());
        let startup_script_path =
            env::var("MAGLEV_STARTUP_SCRIPT_PATH").unwrap_or_else(|_| "./startup.sh".to_string());

        let ssh_key_content = read_ssh_public_key(&ssh_key_path).unwrap_or_else(|e| {
            eprintln!("  ⚠ Could not read SSH public key: {e}");
            String::new()
        });
        let ssh_keys_metadata = if ssh_key_content.is_empty() {
            String::new()
        } else {
            format!("ubuntu:{ssh_key_content}")
        };

        let startup_script = read_startup_script(&startup_script_path);

        println!("\n── Creating VM instance ────────────────────────────────────────────────");
        println!("  Project:           {project_id}");
        println!("  Zone:              {zone}");
        println!("  Machine type:      {machine_type}");
        println!("  Name:              {instance_name}");
        println!("  Boot disk image:   {boot_disk_image}");
        println!("  Boot disk size:    {boot_disk_size_gb} GB");
        println!("  SSH key path:      {ssh_key_path}");
        println!("  Startup script:    {startup_script_path}");

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
            &boot_disk_image,
            boot_disk_size_gb,
            &ssh_keys_metadata,
            &startup_script,
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
        Some("generate") => match env::args().nth(2) {
            Some(path) => generate_config(&path),
            None => {
                eprintln!("error: 'generate' requires a config file path");
                eprintln!();
                eprintln!("USAGE:");
                eprintln!("    maglev generate <config.maglev>");
                std::process::exit(1);
            }
        },

        Some("apply") => match env::args().nth(2) {
            Some(path) => apply_config(&path),
            None => {
                eprintln!("error: 'apply' requires a config file path");
                eprintln!();
                eprintln!("USAGE:");
                eprintln!("    maglev apply <config.maglev>");
                std::process::exit(1);
            }
        },

        Some("print") => print_build_credential(),

        None | Some(_) => {
            eprintln!("USAGE:");
            eprintln!("    maglev [SUBCOMMAND]");
            eprintln!();
            eprintln!("SUBCOMMANDS:");
            eprintln!("    generate <config>    Generate a .maglev config file from env vars");
            eprintln!("    apply <config>       Create a VM from a .maglev config file");
            eprintln!("    print                Run the credential builder");
            std::process::exit(1);
        }
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

#[allow(clippy::too_many_arguments)]
fn create_vm(
    access_token: &str,
    project_id: &str,
    zone: &str,
    instance_name: &str,
    machine_type: &str,
    boot_disk_image: &str,
    boot_disk_size_gb: u64,
    ssh_keys_metadata: &str,
    startup_script: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}/instances"
    );

    let mut metadata_items: Vec<Value> = Vec::new();

    if !ssh_keys_metadata.is_empty() {
        metadata_items.push(serde_json::json!({
            "key":   "ssh-keys",
            "value": ssh_keys_metadata,
        }));
    }

    if !startup_script.is_empty() {
        metadata_items.push(serde_json::json!({
            "key":   "startup-script",
            "value": startup_script,
        }));
    }

    let request_body = serde_json::json!({
        "name": instance_name,
        "machineType": format!("zones/{zone}/machineTypes/{machine_type}"),
        "disks": [{
            "boot": true,
            "autoDelete": true,
            "initializeParams": {
                "sourceImage": resolve_image(boot_disk_image),
                "diskSizeGb": boot_disk_size_gb.to_string(),
            }
        }],
        "networkInterfaces": [{
            "network": "global/networks/default",
            "accessConfigs": [{
                "type": "ONE_TO_ONE_NAT",
                "name": "External NAT",
            }]
        }],
        "metadata": {
            "items": metadata_items,
        }
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

// ---------------------------------------------------------------------------
// .maglev config parser
// ---------------------------------------------------------------------------

fn parse_maglev_config(
    content: &str,
) -> Result<std::collections::HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut map = std::collections::HashMap::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();

        if line.is_empty() || line == "}" || line.ends_with('{') {
            continue;
        }

        let Some(eq_pos) = line.find('=') else {
            continue;
        };

        let key = line[..eq_pos].trim().to_string();
        let value_part = line[eq_pos + 1..].trim();

        if value_part.starts_with('"') && value_part.ends_with('"') && value_part.len() >= 2 {
            let value = value_part[1..value_part.len() - 1].to_string();
            map.insert(key, value);
        }
    }

    Ok(map)
}

// ---------------------------------------------------------------------------
// `apply` subcommand
// ---------------------------------------------------------------------------

fn apply_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Apply ===\n");
    println!("Reading config: {config_path}");

    let content = fs::read_to_string(config_path)
        .map_err(|e| format!("Cannot read config file '{config_path}': {e}"))?;

    let config = parse_maglev_config(&content)?;

    let require = |key: &str| -> Result<String, Box<dyn std::error::Error>> {
        config
            .get(key)
            .cloned()
            .ok_or_else(|| format!("Missing required field '{key}' in {config_path}").into())
    };

    let client_email = require("client_email")?;
    let instance_name = require("instance_name")?;
    let machine_type = require("machine_type")?;
    let project_id = require("project_id")?;
    let zone = require("zone")?;
    let boot_disk_image = require("boot_disk_image")?;
    let private_key_path = require("private_key")?;
    let ssh_public_key_path = require("ssh_public_key_path")?;
    let startup_script_path = require("startup_script_path")?;

    let boot_disk_size_gb: u64 = require("boot_disk_size_gb")?
        .parse()
        .map_err(|_| "Field 'boot_disk_size_gb' must be a positive integer")?;

    let expanded_key_path = expand_tilde(&private_key_path);
    let private_key = fs::read_to_string(&expanded_key_path)
        .map_err(|e| format!("Cannot read private key from '{expanded_key_path}': {e}"))?;

    let ssh_key_content = read_ssh_public_key(&ssh_public_key_path).unwrap_or_else(|e| {
        eprintln!("  ⚠ Could not read SSH public key: {e}");
        String::new()
    });

    let ssh_keys_metadata = if ssh_key_content.is_empty() {
        String::new()
    } else {
        format!("ubuntu:{ssh_key_content}")
    };

    let startup_script = read_startup_script(&startup_script_path);

    println!("\n── Instance details ────────────────────────────────────────────────────");
    println!("  Project:           {project_id}");
    println!("  Zone:              {zone}");
    println!("  Machine type:      {machine_type}");
    println!("  Name:              {instance_name}");
    println!("  Boot disk image:   {boot_disk_image}");
    println!("  Boot disk size:    {boot_disk_size_gb} GB");
    println!("  SSH key path:      {ssh_public_key_path}");
    println!("  Startup script:    {startup_script_path}");
    println!("  Service account:   {client_email}");

    if !prompt_yes_no("\nProceed with creating the VM instance?") {
        println!("Aborted.");
        return Ok(());
    }

    println!("\n  Signing JWT with RSA-SHA256...");
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
        &boot_disk_image,
        boot_disk_size_gb,
        &ssh_keys_metadata,
        &startup_script,
    )?;

    println!("\n✓ VM creation requested. Operation response:\n");
    println!("{}", serde_json::to_string_pretty(&response)?);

    Ok(())
}
