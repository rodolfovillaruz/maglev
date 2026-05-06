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

fn read_ssh_public_key(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let expanded = expand_tilde(path);
    let content = fs::read_to_string(&expanded)
        .map_err(|e| format!("Cannot read SSH public key from '{expanded}': {e}"))?;
    Ok(content.trim().to_string())
}

fn read_startup_script(path: &str) -> String {
    let expanded = expand_tilde(path);
    fs::read_to_string(&expanded).unwrap_or_else(|_| {
        "#!/bin/bash\nset -e\napt-get update\n\
         curl -fsSL https://github.com/rodolfovillaruz/cisak/releases/download/v0.1.11/\
         cisak-v0.1.11-linux-amd64.tar.gz | tar -xz\n\
         install -m 755 -o root -g root cisak /usr/local/bin/cisak\n\
         cisak generate\ncisak install -y"
            .to_string()
    })
}

fn expand_tilde(path: &str) -> String {
    let after_tilde = if path == "~" {
        ""
    } else if path.starts_with("~/") || path.starts_with("~\\") {
        &path[1..]
    } else {
        return path.to_string();
    };

    let home = home_dir().unwrap_or_else(|| ".".to_string());
    format!("{}{}", home, after_tilde)
}

fn home_dir() -> Option<String> {
    env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .ok()
        .or_else(|| {
            let drive = env::var("HOMEDRIVE").ok()?;
            let path = env::var("HOMEPATH").ok()?;
            Some(format!("{}{}", drive, path))
        })
}

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

        if let Some(parent) = Path::new(&key_path).parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create parent directories: {e}"))?;
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
// HCL block renderers
// ---------------------------------------------------------------------------

/// Renders an unlabeled block:
///   <indent><name> {
///     key = "value"
///   }
fn render_block(indent: usize, block_name: &str, fields: &[(&str, &str)]) -> String {
    let outer = " ".repeat(indent);
    let inner = " ".repeat(indent + 2);
    let max_key = fields.iter().map(|(k, _)| k.len()).max().unwrap_or(0);

    let mut out = format!("{outer}{block_name} {{\n");
    for (key, value) in fields {
        let pad = " ".repeat(max_key - key.len() + 1);
        out.push_str(&format!("{inner}{key}{pad}= \"{value}\"\n"));
    }
    out.push_str(&format!("{outer}}}\n"));
    out
}

/// Renders a labeled block:
///   <indent><block_type> "<label>" {
///     key = "value"
///   }
fn render_labeled_block(
    indent: usize,
    block_type: &str,
    label: &str,
    fields: &[(&str, &str)],
) -> String {
    let outer = " ".repeat(indent);
    let inner = " ".repeat(indent + 2);
    let max_key = fields.iter().map(|(k, _)| k.len()).max().unwrap_or(0);

    let mut out = format!("{outer}{block_type} \"{label}\" {{\n");
    for (key, value) in fields {
        let pad = " ".repeat(max_key - key.len() + 1);
        out.push_str(&format!("{inner}{key}{pad}= \"{value}\"\n"));
    }
    out.push_str(&format!("{outer}}}\n"));
    out
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

    println!("\n── Credentials ─────────────────────────────────────────────────────────\n");

    let credentials = ServiceAccountCredentials {
        credential_type: "service_account".to_string(),
        private_key: private_key.clone(),
        client_email: client_email.clone(),
    };

    if prompt_yes_no("\nPrint the JSON file") {
        let json_str = serde_json::to_string_pretty(&credentials)?;
        println!("{json_str}");
    }

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

    if prompt_yes_no("\nCreate VM instances now?") {
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
        let boot_disk_image = env::var("MAGLEV_BOOT_DISK_IMAGE")
            .unwrap_or_else(|_| "ubuntu-2404-lts-amd64".to_string());
        let boot_disk_size_gb: u64 = env::var("MAGLEV_BOOT_DISK_SIZE_GB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);
        let ssh_key_path = env::var("MAGLEV_SSH_PUBLIC_KEY_PATH")
            .unwrap_or_else(|_| "~/.ssh/id_ed25519.pub".to_string());

        let ssh_key_content = read_ssh_public_key(&ssh_key_path).unwrap_or_else(|e| {
            eprintln!("  ⚠ Could not read SSH public key: {e}");
            String::new()
        });
        let ssh_keys_metadata = if ssh_key_content.is_empty() {
            String::new()
        } else {
            format!("ubuntu:{ssh_key_content}")
        };

        let ts = time::OffsetDateTime::now_utc().unix_timestamp();

        // ── Control-plane node ───────────────────────────────────────────────
        let cp_instance_name =
            env::var("MAGLEV_CP_INSTANCE_NAME").unwrap_or_else(|_| format!("maglev-cp-{ts}"));
        let cp_startup_script_path = env::var("MAGLEV_CP_STARTUP_SCRIPT_PATH")
            .unwrap_or_else(|_| "./startup-cp.sh".to_string());
        let cp_startup_script = read_startup_script(&cp_startup_script_path);

        // ── Worker node ──────────────────────────────────────────────────────
        let worker_instance_name = env::var("MAGLEV_WORKER_INSTANCE_NAME")
            .unwrap_or_else(|_| format!("maglev-worker-{ts}"));
        let worker_startup_script_path = env::var("MAGLEV_WORKER_STARTUP_SCRIPT_PATH")
            .unwrap_or_else(|_| "./startup.sh".to_string());
        let worker_startup_script = read_startup_script(&worker_startup_script_path);

        println!("\n── Creating VM instances ───────────────────────────────────────────────");
        println!("  Project:                  {project_id}");
        println!("  Zone:                     {zone}");
        println!("  Machine type:             {machine_type}");
        println!("  Boot disk image:          {boot_disk_image}");
        println!("  Boot disk size:           {boot_disk_size_gb} GB");
        println!("  SSH key path:             {ssh_key_path}");
        println!("  [control-plane] Name:     {cp_instance_name}");
        println!("  [control-plane] Script:   {cp_startup_script_path}");
        println!("  [worker]        Name:     {worker_instance_name}");
        println!("  [worker]        Script:   {worker_startup_script_path}");

        println!("  Signing JWT...");
        let jwt = create_jwt(
            &private_key,
            &client_email,
            "https://www.googleapis.com/auth/compute",
        )?;

        println!("  Exchanging JWT for OAuth2 access token...");
        let access_token = get_access_token(&jwt)?;

        println!("\n  ── Creating control-plane node ({cp_instance_name}) ──");
        let cp_response = create_vm(
            &access_token,
            &project_id,
            &zone,
            &cp_instance_name,
            &machine_type,
            &boot_disk_image,
            boot_disk_size_gb,
            &ssh_keys_metadata,
            &cp_startup_script,
        )?;
        println!("{}", serde_json::to_string_pretty(&cp_response)?);

        println!("\n  ── Creating worker node ({worker_instance_name}) ──");
        let worker_response = create_vm(
            &access_token,
            &project_id,
            &zone,
            &worker_instance_name,
            &machine_type,
            &boot_disk_image,
            boot_disk_size_gb,
            &ssh_keys_metadata,
            &worker_startup_script,
        )?;
        println!("{}", serde_json::to_string_pretty(&worker_response)?);

        println!("\n✓ Both VM creation requests submitted successfully.");
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

        Some("destroy") => match env::args().nth(2) {
            Some(path) => destroy_config(&path),
            None => {
                eprintln!("error: 'destroy' requires a config file path");
                eprintln!();
                eprintln!("USAGE:");
                eprintln!("    maglev destroy <config.maglev>");
                std::process::exit(1);
            }
        },

        // ── NEW ──────────────────────────────────────────────────────────────
        Some("play") => match env::args().nth(2) {
            Some(path) => play_config(&path),
            None => {
                eprintln!("error: 'play' requires a config file path");
                eprintln!();
                eprintln!("USAGE:");
                eprintln!("    maglev play <config.maglev>");
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
            eprintln!("    apply <config>       Create VMs from a .maglev config file");
            eprintln!(
                "    destroy <config>     Permanently delete VMs described in a .maglev config"
            );
            eprintln!(
                "    play <config>        Provision Kubernetes and join the worker to the control-plane"
            );
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
                "diskSizeGb":  boot_disk_size_gb.to_string(),
            }
        }],
        "networkInterfaces": [{
            "network": "global/networks/default",
            "accessConfigs": [{
                "type": "ONE_TO_ONE_NAT",
                "name": "External NAT",
            }]
        }],
        "metadata": { "items": metadata_items }
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
//
// Supports labeled node blocks:
//
//   maglev "prod" {
//     node "control_plane" { ... }   → keys: node_control_plane.<key>
//     node "worker"        { ... }   → keys: node_worker.<key>
//     node_pool  { ... }             → keys: node_pool.<key>
//     gcp_config { ... }             → keys: gcp_config.<key>
//   }
//
// The maglev label is stored as "name".
// ---------------------------------------------------------------------------

fn parse_maglev_config(
    content: &str,
) -> Result<std::collections::HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut map = std::collections::HashMap::new();
    let mut block_stack: Vec<String> = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // ── Close a block ────────────────────────────────────────────────────
        if line == "}" {
            block_stack.pop();
            continue;
        }

        // ── Open a block ─────────────────────────────────────────────────────
        if line.ends_with('{') {
            let header = line.trim_end_matches('{').trim();

            if header.starts_with("maglev") {
                // maglev "label" → store label under "name"
                let label = header
                    .split_once('"')
                    .map(|x| x.1)
                    .and_then(|s| s.split('"').next())
                    .unwrap_or("")
                    .to_string();

                if !label.is_empty() {
                    map.insert("name".to_string(), label);
                }

                block_stack.push("maglev".to_string());
            } else if let Some((block_type, rest)) = header.split_once(' ') {
                // block_type "label"  →  block_type_label
                let label = rest.trim().trim_matches('"');
                let prefix = if label.is_empty() {
                    block_type.to_string()
                } else {
                    format!("{block_type}_{label}")
                };
                block_stack.push(prefix);
            } else {
                // Bare block name: node_pool, gcp_config, …
                block_stack.push(header.to_string());
            }

            continue;
        }

        // ── key = "value" ────────────────────────────────────────────────────
        let Some(eq_pos) = line.find('=') else {
            continue;
        };

        let key = line[..eq_pos].trim();
        let value_part = line[eq_pos + 1..].trim();

        if !(value_part.starts_with('"') && value_part.ends_with('"') && value_part.len() >= 2) {
            continue;
        }

        let value = value_part[1..value_part.len() - 1].to_string();

        // Prefix with the innermost non-maglev block, if any.
        let full_key = block_stack
            .iter()
            .rfind(|b| b.as_str() != "maglev")
            .map(|b| format!("{b}.{key}"))
            .unwrap_or_else(|| key.to_string());

        map.insert(full_key, value);
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

    // ── node "control_plane" block ───────────────────────────────────────────
    let cp_instance_name = require("node_control_plane.instance_name")?;
    let cp_ssh_public_key_path = require("node_control_plane.ssh_public_key_path")?;
    let cp_startup_script_path = require("node_control_plane.startup_script_path")?;

    // ── node "worker" block ──────────────────────────────────────────────────
    let worker_instance_name = require("node_worker.instance_name")?;
    let worker_ssh_public_key_path = require("node_worker.ssh_public_key_path")?;
    let worker_startup_script_path = require("node_worker.startup_script_path")?;

    // ── node_pool block ──────────────────────────────────────────────────────
    let boot_disk_image = require("node_pool.boot_disk_image")?;
    let boot_disk_size_gb: u64 = require("node_pool.boot_disk_size_gb")?
        .parse()
        .map_err(|_| "Field 'node_pool.boot_disk_size_gb' must be a positive integer")?;
    let machine_type = require("node_pool.machine_type")?;
    let _pool_name = config
        .get("node_pool.name")
        .cloned()
        .unwrap_or_else(|| config.get("name").cloned().unwrap_or_default());

    // ── gcp_config block ─────────────────────────────────────────────────────
    let client_email = require("gcp_config.client_email")?;
    let private_key_path = require("gcp_config.private_key")?;
    let project_id = require("gcp_config.project_id")?;
    let zone = require("gcp_config.zone")?;

    // ── Load the private key from disk ───────────────────────────────────────
    let expanded_key_path = expand_tilde(&private_key_path);
    let private_key = fs::read_to_string(&expanded_key_path)
        .map_err(|e| format!("Cannot read private key from '{expanded_key_path}': {e}"))?;

    // ── SSH public keys ──────────────────────────────────────────────────────
    let make_ssh_metadata = |path: &str| -> String {
        read_ssh_public_key(path)
            .map(|k| format!("ubuntu:{k}"))
            .unwrap_or_else(|e| {
                eprintln!("  ⚠ Could not read SSH public key from '{path}': {e}");
                String::new()
            })
    };

    let cp_ssh_metadata = make_ssh_metadata(&cp_ssh_public_key_path);
    let worker_ssh_metadata = make_ssh_metadata(&worker_ssh_public_key_path);

    let cp_startup_script = read_startup_script(&cp_startup_script_path);
    let worker_startup_script = read_startup_script(&worker_startup_script_path);

    // ── Summary ──────────────────────────────────────────────────────────────
    println!("\n── Shared settings ─────────────────────────────────────────────────────");
    println!("  Project:           {project_id}");
    println!("  Zone:              {zone}");
    println!("  Machine type:      {machine_type}");
    println!("  Boot disk image:   {boot_disk_image}");
    println!("  Boot disk size:    {boot_disk_size_gb} GB");
    println!("  Service account:   {client_email}");
    println!("\n── control-plane node ──────────────────────────────────────────────────");
    println!("  Name:              {cp_instance_name}");
    println!("  SSH key:           {cp_ssh_public_key_path}");
    println!("  Startup script:    {cp_startup_script_path}");
    println!("\n── worker node ─────────────────────────────────────────────────────────");
    println!("  Name:              {worker_instance_name}");
    println!("  SSH key:           {worker_ssh_public_key_path}");
    println!("  Startup script:    {worker_startup_script_path}");

    if !prompt_yes_no("\nProceed with creating both VM instances?") {
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

    // ── Create control-plane node ────────────────────────────────────────────
    println!("\n  ── Creating control-plane node ({cp_instance_name}) ──");
    let cp_response = create_vm(
        &access_token,
        &project_id,
        &zone,
        &cp_instance_name,
        &machine_type,
        &boot_disk_image,
        boot_disk_size_gb,
        &cp_ssh_metadata,
        &cp_startup_script,
    )?;
    println!("{}", serde_json::to_string_pretty(&cp_response)?);

    // ── Create worker node ───────────────────────────────────────────────────
    println!("\n  ── Creating worker node ({worker_instance_name}) ──");
    let worker_response = create_vm(
        &access_token,
        &project_id,
        &zone,
        &worker_instance_name,
        &machine_type,
        &boot_disk_image,
        boot_disk_size_gb,
        &worker_ssh_metadata,
        &worker_startup_script,
    )?;
    println!("{}", serde_json::to_string_pretty(&worker_response)?);

    println!("\n✓ Both VM creation requests submitted successfully.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Configuration structs (mirror the HCL blocks)
// ---------------------------------------------------------------------------

/// A single node entry (control_plane or worker).
struct NodeConfig<'a> {
    /// The block label used in the config file, e.g. `"control_plane"` or `"worker"`.
    label: &'a str,
    instance_name: &'a str,
    ssh_public_key_path: &'a str,
    startup_script_path: &'a str,
}

struct NodePoolConfig<'a> {
    boot_disk_image: &'a str,
    boot_disk_size_gb: &'a str,
    machine_type: &'a str,
    name: &'a str,
}

struct GcpConfig<'a> {
    client_email: &'a str,
    private_key: &'a str,
    project_id: &'a str,
    zone: &'a str,
}

// ---------------------------------------------------------------------------
// `generate` subcommand
// ---------------------------------------------------------------------------

fn format_config(
    name: &str,
    nodes: &[NodeConfig<'_>],
    node_pool: &NodePoolConfig<'_>,
    gcp: &GcpConfig<'_>,
) -> String {
    let mut body = String::new();

    // One labeled node block per entry.
    for node in nodes {
        let block = render_labeled_block(
            2,
            "node",
            node.label,
            &[
                ("instance_name", node.instance_name),
                ("ssh_public_key_path", node.ssh_public_key_path),
                ("startup_script_path", node.startup_script_path),
            ],
        );
        body.push_str(&block);
        body.push('\n');
    }

    body.push_str(&render_block(
        2,
        "node_pool",
        &[
            ("boot_disk_image", node_pool.boot_disk_image),
            ("boot_disk_size_gb", node_pool.boot_disk_size_gb),
            ("machine_type", node_pool.machine_type),
            ("name", node_pool.name),
        ],
    ));
    body.push('\n');

    body.push_str(&render_block(
        2,
        "gcp_config",
        &[
            ("client_email", gcp.client_email),
            ("private_key", gcp.private_key),
            ("project_id", gcp.project_id),
            ("zone", gcp.zone),
        ],
    ));

    format!("maglev \"{name}\" {{\n\n{body}\n}}\n")
}

fn generate_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if Path::new(config_path).exists() {
        eprintln!("error: '{config_path}' already exists");
        std::process::exit(1);
    }

    let name = Path::new(config_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("maglev")
        .to_string();

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
    let machine_type = env::var("MAGLEV_MACHINE_TYPE").unwrap_or_else(|_| "e2-medium".to_string());
    let zone = env::var("MAGLEV_ZONE").unwrap_or_else(|_| "europe-north1-a".to_string());
    let boot_disk_image =
        env::var("MAGLEV_BOOT_DISK_IMAGE").unwrap_or_else(|_| "ubuntu-2404-lts-amd64".to_string());
    let boot_disk_size_gb =
        env::var("MAGLEV_BOOT_DISK_SIZE_GB").unwrap_or_else(|_| "50".to_string());
    let ssh_public_key_path = env::var("MAGLEV_SSH_PUBLIC_KEY_PATH")
        .unwrap_or_else(|_| "~/.ssh/id_ed25519.pub".to_string());

    // ── control-plane defaults ───────────────────────────────────────────────
    let cp_instance_name =
        env::var("MAGLEV_CP_INSTANCE_NAME").unwrap_or_else(|_| format!("maglev-cp-{name}"));
    let cp_startup_script_path =
        env::var("MAGLEV_CP_STARTUP_SCRIPT_PATH").unwrap_or_else(|_| "./startup-cp.sh".to_string());

    // ── worker defaults ──────────────────────────────────────────────────────
    let worker_instance_name =
        env::var("MAGLEV_WORKER_INSTANCE_NAME").unwrap_or_else(|_| format!("maglev-worker-{name}"));
    let worker_startup_script_path = env::var("MAGLEV_WORKER_STARTUP_SCRIPT_PATH")
        .unwrap_or_else(|_| "./startup.sh".to_string());

    let config = format_config(
        &name,
        &[
            NodeConfig {
                label: "control_plane",
                instance_name: &cp_instance_name,
                ssh_public_key_path: &ssh_public_key_path,
                startup_script_path: &cp_startup_script_path,
            },
            NodeConfig {
                label: "worker",
                instance_name: &worker_instance_name,
                ssh_public_key_path: &ssh_public_key_path,
                startup_script_path: &worker_startup_script_path,
            },
        ],
        &NodePoolConfig {
            boot_disk_image: &boot_disk_image,
            boot_disk_size_gb: &boot_disk_size_gb,
            machine_type: &machine_type,
            name: &name,
        },
        &GcpConfig {
            client_email: &client_email,
            private_key: &private_key,
            project_id: &project_id,
            zone: &zone,
        },
    );

    fs::write(config_path, &config)
        .map_err(|e| format!("Cannot write config to '{config_path}': {e}"))?;

    println!("✓ Config written to: {config_path}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Compute Engine — DELETE instance  (add after create_vm)
// ---------------------------------------------------------------------------

/// Sends `DELETE .../instances/{instance_name}` and returns the Operation JSON.
fn delete_vm(
    access_token: &str,
    project_id: &str,
    zone: &str,
    instance_name: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}/instances/{instance_name}"
    );

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();

    let mut resp = agent
        .delete(&url)
        .header("Authorization", &format!("Bearer {access_token}"))
        .call()?;

    let status = resp.status();
    let body: Value = resp.body_mut().read_json()?;

    if !status.is_success() {
        return Err(format!("Compute Engine API returned HTTP {status}: {body}").into());
    }

    Ok(body)
}

// ---------------------------------------------------------------------------
// `destroy` subcommand  (add after apply_config)
// ---------------------------------------------------------------------------

fn destroy_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Destroy ===\n");
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

    // ── Instance names ───────────────────────────────────────────────────────
    let cp_instance_name = require("node_control_plane.instance_name")?;
    let worker_instance_name = require("node_worker.instance_name")?;

    // ── GCP credentials ──────────────────────────────────────────────────────
    let client_email = require("gcp_config.client_email")?;
    let private_key_path = require("gcp_config.private_key")?;
    let project_id = require("gcp_config.project_id")?;
    let zone = require("gcp_config.zone")?;

    let expanded_key_path = expand_tilde(&private_key_path);
    let private_key = fs::read_to_string(&expanded_key_path)
        .map_err(|e| format!("Cannot read private key from '{expanded_key_path}': {e}"))?;

    // ── Summary + confirmation ───────────────────────────────────────────────
    println!("\n── Instances to destroy ────────────────────────────────────────────────");
    println!("  Project:         {project_id}");
    println!("  Zone:            {zone}");
    println!("  Service account: {client_email}");
    println!();
    println!("  control-plane  → {cp_instance_name}");
    println!("  worker         → {worker_instance_name}");
    println!();
    println!("⚠  This action is IRREVERSIBLE. Both VM instances and their boot disks");
    println!("   will be permanently deleted.");

    if !prompt_yes_no("\nProceed with destroying both VM instances?") {
        println!("Aborted — nothing was deleted.");
        return Ok(());
    }

    // ── Authenticate ─────────────────────────────────────────────────────────
    println!("\n  Signing JWT with RSA-SHA256...");
    let jwt = create_jwt(
        &private_key,
        &client_email,
        "https://www.googleapis.com/auth/compute",
    )?;

    println!("  Exchanging JWT for OAuth2 access token...");
    let access_token = get_access_token(&jwt)?;

    // ── Delete control-plane ─────────────────────────────────────────────────
    println!("\n  ── Deleting control-plane node ({cp_instance_name}) ──");
    match delete_vm(&access_token, &project_id, &zone, &cp_instance_name) {
        Ok(body) => println!("{}", serde_json::to_string_pretty(&body)?),
        Err(e) => {
            eprintln!("  ✗ Failed to delete control-plane node: {e}");
            eprintln!("    The worker node will still be attempted.");
        }
    }

    // ── Delete worker ────────────────────────────────────────────────────────
    println!("\n  ── Deleting worker node ({worker_instance_name}) ──");
    match delete_vm(&access_token, &project_id, &zone, &worker_instance_name) {
        Ok(body) => println!("{}", serde_json::to_string_pretty(&body)?),
        Err(e) => {
            eprintln!("  ✗ Failed to delete worker node: {e}");
        }
    }

    println!("\n✓ Deletion requests submitted. GCP operations may take a minute to complete.");
    println!("  Track progress:");
    println!("    gcloud compute operations list --filter=\"zone:{zone}\" --project={project_id}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Compute Engine — GET instance  (fetch external IP)
// ---------------------------------------------------------------------------

fn get_vm_ip(
    access_token: &str,
    project_id: &str,
    zone: &str,
    instance_name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}/instances/{instance_name}"
    );

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();

    let mut resp = agent
        .get(&url)
        .header("Authorization", &format!("Bearer {access_token}"))
        .call()?;

    let status = resp.status();
    let body: Value = resp.body_mut().read_json()?;

    if !status.is_success() {
        return Err(format!(
            "Compute Engine API returned HTTP {status} while fetching '{instance_name}': {body}"
        )
        .into());
    }

    body["networkInterfaces"][0]["accessConfigs"][0]["natIP"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("No external (NAT) IP found for instance '{instance_name}'").into())
}

// ---------------------------------------------------------------------------
// SSH helpers  (uses the system `ssh` binary — no native dep needed)
// ---------------------------------------------------------------------------

/// Run a command over SSH and **capture** its stdout.
/// The command must always exit 0 (e.g. `test … && echo yes || echo no`).
fn ssh_capture(
    ip: &str,
    user: &str,
    private_key_path: &str,
    command: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let out = std::process::Command::new("ssh")
        .args([
            "-i",
            private_key_path,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "LogLevel=ERROR",
            &format!("{user}@{ip}"),
            command,
        ])
        .output()
        .map_err(|e| format!("Failed to spawn ssh for capture: {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "ssh capture command exited {} — stderr: {stderr}",
            out.status.code().unwrap_or(-1),
        )
        .into());
    }

    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Run a command over SSH and **stream** its output to the terminal.
/// Pass `-t` so `sudo` can inherit the PTY when needed.
fn ssh_run(
    ip: &str,
    user: &str,
    private_key_path: &str,
    command: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = std::process::Command::new("ssh")
        .args([
            "-i",
            private_key_path,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=30",
            "-o",
            "LogLevel=ERROR",
            "-t", // allocate pseudo-TTY so sudo / interactive tools work
            &format!("{user}@{ip}"),
            command,
        ])
        .status()
        .map_err(|e| format!("Failed to spawn ssh for run: {e}"))?;

    if !status.success() {
        return Err(format!(
            "Remote command exited with code {}",
            status.code().unwrap_or(-1)
        )
        .into());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// `play` subcommand
//
// 1. Check if /etc/kubernetes/admin.conf exists on the control-plane.
//    • If missing  → ask → run `sudo cisak install --control-plane -y`
//    • If present  → skip
// 2. Ask → run `sudo cisak install -y` on the worker.
// 3. Ask → fetch `kubeadm token create --print-join-command` from the
//    control-plane, show it, ask again, then run it on the worker.
// ---------------------------------------------------------------------------

fn play_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Play ===\n");
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

    // ── Config fields ────────────────────────────────────────────────────────
    let cp_instance_name = require("node_control_plane.instance_name")?;
    let cp_ssh_pub_path = require("node_control_plane.ssh_public_key_path")?;

    let worker_instance_name = require("node_worker.instance_name")?;
    let worker_ssh_pub_path = require("node_worker.ssh_public_key_path")?;

    let client_email = require("gcp_config.client_email")?;
    let gcp_private_key_path = require("gcp_config.private_key")?;
    let project_id = require("gcp_config.project_id")?;
    let zone = require("gcp_config.zone")?;

    // Derive private SSH key paths: strip the `.pub` suffix (standard convention).
    let cp_ssh_priv_path = expand_tilde(
        cp_ssh_pub_path
            .strip_suffix(".pub")
            .unwrap_or(&cp_ssh_pub_path),
    );
    let worker_ssh_priv_path = expand_tilde(
        worker_ssh_pub_path
            .strip_suffix(".pub")
            .unwrap_or(&worker_ssh_pub_path),
    );

    // SSH user — configurable via env, defaulting to "ubuntu".
    let ssh_user = env::var("MAGLEV_SSH_USER").unwrap_or_else(|_| "ubuntu".to_string());

    // ── Authenticate with GCP ────────────────────────────────────────────────
    let expanded_gcp_key = expand_tilde(&gcp_private_key_path);
    let gcp_private_key = fs::read_to_string(&expanded_gcp_key)
        .map_err(|e| format!("Cannot read GCP private key from '{expanded_gcp_key}': {e}"))?;

    println!("\n  Signing JWT...");
    let jwt = create_jwt(
        &gcp_private_key,
        &client_email,
        "https://www.googleapis.com/auth/compute",
    )?;

    println!("  Exchanging JWT for OAuth2 access token...");
    let access_token = get_access_token(&jwt)?;

    // ── Resolve external IPs ─────────────────────────────────────────────────
    println!("\n  Fetching external IPs from Compute Engine API...");
    let cp_ip = get_vm_ip(&access_token, &project_id, &zone, &cp_instance_name)?;
    let worker_ip = get_vm_ip(&access_token, &project_id, &zone, &worker_instance_name)?;

    println!("  Control-plane : {cp_instance_name}  →  {cp_ip}");
    println!("  Worker        : {worker_instance_name}  →  {worker_ip}");
    println!("  SSH user      : {ssh_user}");
    println!("  SSH key (cp)  : {cp_ssh_priv_path}");
    println!("  SSH key (wkr) : {worker_ssh_priv_path}");

    // ════════════════════════════════════════════════════════════════════════
    // Step 1 — Control-plane
    // ════════════════════════════════════════════════════════════════════════
    println!("\n━━ Step 1 / 3 — Control-plane provisioning ━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  Checking /etc/kubernetes/admin.conf on {cp_instance_name} ({cp_ip}) …");

    if !prompt_yes_no(&format!("  Run check command on {ssh_user}@{cp_ip}?")) {
        println!("Aborted.");
        return Ok(());
    }

    let check_out = ssh_capture(
        &cp_ip,
        &ssh_user,
        &cp_ssh_priv_path,
        "test -f /etc/kubernetes/admin.conf && echo yes || echo no",
    )?;

    let cp_ready = check_out.trim() == "yes";

    if cp_ready {
        println!("  ✓ /etc/kubernetes/admin.conf found — control-plane is already provisioned.");
    } else {
        println!("  /etc/kubernetes/admin.conf not found — control-plane needs provisioning.");
        println!();
        println!("  Host    : {ssh_user}@{cp_ip}");
        println!("  Command : sudo cisak install --control-plane -y");
        println!();
        println!("  ⚠  This will install Kubernetes on the control-plane node.");

        if !prompt_yes_no("  Proceed?") {
            println!("Aborted.");
            return Ok(());
        }

        println!("\n  Running provisioning on control-plane — this may take several minutes …\n");
        ssh_run(
            &cp_ip,
            &ssh_user,
            &cp_ssh_priv_path,
            "sudo cisak install --control-plane -y",
        )?;
        println!("\n  ✓ Control-plane provisioned.");
    }

    // ════════════════════════════════════════════════════════════════════════
    // Step 2 — Join worker to control-plane
    // ════════════════════════════════════════════════════════════════════════
    println!("\n━━ Step 3 / 3 — Join worker to control-plane ━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  Host    : {ssh_user}@{cp_ip}");
    println!("  Command : sudo kubeadm token create --print-join-command");

    if !prompt_yes_no("  Fetch join command from control-plane?") {
        println!("Aborted.");
        return Ok(());
    }

    let join_command = ssh_capture(
        &cp_ip,
        &ssh_user,
        &cp_ssh_priv_path,
        "sudo kubeadm token create --print-join-command",
    )?;

    if join_command.is_empty() {
        return Err(
            "kubeadm returned an empty join command — is the control-plane fully up?".into(),
        );
    }

    println!();
    println!("  Join command received:");
    println!("    {join_command}");
    println!();
    println!("  Will run on worker ({ssh_user}@{worker_ip}):");
    println!("    sudo {join_command}");
    println!();
    println!("  ⚠  The worker will be permanently joined to this cluster.");

    if !prompt_yes_no("  Proceed?") {
        println!("Aborted.");
        return Ok(());
    }

    println!("\n  Joining worker to control-plane …\n");
    ssh_run(
        &worker_ip,
        &ssh_user,
        &worker_ssh_priv_path,
        &format!("sudo {join_command}"),
    )?;

    println!("\n✓ Cluster is ready!");
    println!();
    println!("  Verify from the control-plane:");
    println!("    ssh -i {cp_ssh_priv_path} {ssh_user}@{cp_ip}");
    println!("    kubectl get nodes -o wide");

    Ok(())
}
