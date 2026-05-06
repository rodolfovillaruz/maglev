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
            && !parent.as_os_str().is_empty() {
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
// HCL block renderer
//
//   render_block(2, "node", &[("machine_type", "e2-medium"), ...])
//
//   →   node {
//         machine_type = "e2-medium"
//         ...
//       }
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// `generate` subcommand
// ---------------------------------------------------------------------------
//
// Output format:
//
//   maglev "prod" {
//
//     node {
//       boot_disk_image     = "ubuntu-2404-lts-amd64"
//       boot_disk_size_gb   = "50"
//       instance_name       = "maglev-vm-prod"
//       machine_type        = "e2-medium"
//       ssh_public_key_path = "~/.ssh/id_ed25519.pub"
//       startup_script_path = "./startup.sh"
//     }
//
//     node_pool {
//       name = "prod"
//     }
//
//     gcp_config {
//       client_email = "sa@project.iam.gserviceaccount.com"
//       private_key  = ".keys/private_key.pem"
//       project_id   = "my-project"
//       zone         = "europe-north1-a"
//     }
//
//   }

fn format_config(
    name: &str,
    // ── node ──────────────────────────────────────────────────────────────────
    boot_disk_image: &str,
    boot_disk_size_gb: &str,
    instance_name: &str,
    machine_type: &str,
    ssh_public_key_path: &str,
    startup_script_path: &str,
    // ── gcp_config ────────────────────────────────────────────────────────────
    client_email: &str,
    private_key: &str,
    project_id: &str,
    zone: &str,
) -> String {
    let node = render_block(
        2,
        "node",
        &[
            ("boot_disk_image", boot_disk_image),
            ("boot_disk_size_gb", boot_disk_size_gb),
            ("instance_name", instance_name),
            ("machine_type", machine_type),
            ("ssh_public_key_path", ssh_public_key_path),
            ("startup_script_path", startup_script_path),
        ],
    );

    let node_pool = render_block(2, "node_pool", &[("name", name)]);

    let gcp_config = render_block(
        2,
        "gcp_config",
        &[
            ("client_email", client_email),
            ("private_key", private_key),
            ("project_id", project_id),
            ("zone", zone),
        ],
    );

    format!("maglev \"{name}\" {{\n\n{node}\n{node_pool}\n{gcp_config}\n}}\n")
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

    let config = format_config(
        &name,
        &boot_disk_image,
        &boot_disk_size_gb,
        &instance_name,
        &machine_type,
        &ssh_public_key_path,
        &startup_script_path,
        &client_email,
        &private_key,
        &project_id,
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
// Supports the nested HCL-like structure produced by `format_config`:
//
//   maglev "prod" {
//     node       { ... }
//     node_pool  { ... }
//     gcp_config { ... }
//   }
//
// Keys from nested blocks are stored as "<block>.<key>", e.g.
//   "node.machine_type", "gcp_config.project_id", "node_pool.name".
//
// The maglev label itself is stored as "name".
// ---------------------------------------------------------------------------

fn parse_maglev_config(
    content: &str,
) -> Result<std::collections::HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut map = std::collections::HashMap::new();

    // A stack of block names; the outermost entry is always "maglev".
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
                // Extract the optional label: maglev "prod" → "prod"
                let label = header.split_once('"').map(|x| x.1)
                    .and_then(|s| s.split('"').next())
                    .unwrap_or("")
                    .to_string();

                if !label.is_empty() {
                    map.insert("name".to_string(), label);
                }

                block_stack.push("maglev".to_string());
            } else {
                // Bare block names: node, node_pool, gcp_config, …
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
            .iter().rfind(|b| b.as_str() != "maglev")
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

    // Helper — look up a dotted key and give a clear error when it is absent.
    let require = |key: &str| -> Result<String, Box<dyn std::error::Error>> {
        config
            .get(key)
            .cloned()
            .ok_or_else(|| format!("Missing required field '{key}' in {config_path}").into())
    };

    // ── node block ───────────────────────────────────────────────────────────
    let boot_disk_image = require("node.boot_disk_image")?;
    let boot_disk_size_gb: u64 = require("node.boot_disk_size_gb")?
        .parse()
        .map_err(|_| "Field 'node.boot_disk_size_gb' must be a positive integer")?;
    let instance_name = require("node.instance_name")?;
    let machine_type = require("node.machine_type")?;
    let ssh_public_key_path = require("node.ssh_public_key_path")?;
    let startup_script_path = require("node.startup_script_path")?;

    // ── node_pool block ──────────────────────────────────────────────────────
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

    // ── SSH public key ───────────────────────────────────────────────────────
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

    // ── Summary ──────────────────────────────────────────────────────────────
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
