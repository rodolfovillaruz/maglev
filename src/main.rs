use std::collections::HashMap;
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
// Parsed config types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct NodeEntry {
    instance_name: String,
    ssh_public_key_path: String,
    startup_script_path: String,
}

#[derive(Debug, Clone)]
struct NodePoolEntry {
    boot_disk_image: String,
    boot_disk_size_gb: u64,
    machine_type: String,
    name: String,
}

#[derive(Debug, Clone)]
struct GcpEntry {
    client_email: String,
    private_key: String,
    project_id: String,
    zone: String,
}

#[derive(Debug)]
struct MaglevConfig {
    name: String,
    control_planes: Vec<NodeEntry>,
    workers: Vec<NodeEntry>,
    node_pool: NodePoolEntry,
    gcp: GcpEntry,
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

    Ok(())
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

// ---------------------------------------------------------------------------
// Compute Engine — CREATE instance
// ---------------------------------------------------------------------------

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
// Compute Engine — DELETE instance
// ---------------------------------------------------------------------------

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
// Compute Engine — GET instance (fetch external IP)
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
// SSH helpers
// ---------------------------------------------------------------------------

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
            "-t",
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
// .maglev HCL config — parser
//
// File format:
//
//   maglev "prod" {
//
//     node "control_plane" "maglev-cp-alpha" {
//       ssh_public_key_path = "~/.ssh/id_ed25519.pub"
//       startup_script_path = "./startup-cp.sh"
//     }
//
//     node "control_plane" "maglev-cp-beta" {
//       ssh_public_key_path = "~/.ssh/id_ed25519.pub"
//       startup_script_path = "./startup-cp.sh"
//     }
//
//     node "worker" "maglev-worker-alpha" {
//       ssh_public_key_path = "~/.ssh/id_ed25519.pub"
//       startup_script_path = "./startup.sh"
//     }
//
//     node "worker" "maglev-worker-beta" { … }
//     node "worker" "maglev-worker-gamma" { … }
//
//     node_pool {
//       boot_disk_image   = "ubuntu-2404-lts-amd64"
//       boot_disk_size_gb = 50
//       machine_type      = "e2-medium"
//       name              = "prod"
//     }
//
//     gcp_config {
//       client_email = "sa@project.iam.gserviceaccount.com"
//       private_key  = ".keys/private_key.pem"
//       project_id   = "my-project"
//       zone         = "europe-north1-a"
//     }
//   }
// ---------------------------------------------------------------------------

fn expr_to_string(expr: &hcl::Expression) -> Option<String> {
    match expr {
        hcl::Expression::String(s) => Some(s.clone()),
        hcl::Expression::Number(n) => Some(n.to_string()),
        hcl::Expression::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Collect all attributes of a block body into a flat `HashMap<key, value>`.
fn block_attrs(body: &hcl::Body) -> HashMap<String, String> {
    body.attributes()
        .filter_map(|a| expr_to_string(a.expr()).map(|v| (a.key().to_string(), v)))
        .collect()
}

fn parse_maglev_config(content: &str) -> Result<MaglevConfig, Box<dyn std::error::Error>> {
    let body = hcl::parse(content).map_err(|e| format!("HCL parse error: {e}"))?;

    // Find the first `maglev` block.
    let maglev_block = body
        .blocks()
        .find(|b| b.identifier() == "maglev")
        .ok_or("No 'maglev' block found in config")?;

    let name = maglev_block
        .labels()
        .first()
        .map(|l| l.as_str().to_string())
        .unwrap_or_else(|| "maglev".to_string());

    let mut control_planes: Vec<NodeEntry> = Vec::new();
    let mut workers: Vec<NodeEntry> = Vec::new();
    let mut node_pool: Option<NodePoolEntry> = None;
    let mut gcp: Option<GcpEntry> = None;

    for block in maglev_block.body().blocks() {
        match block.identifier() {
            // node "control_plane" "maglev-cp-alpha" { … }
            // node "worker"       "maglev-worker-alpha" { … }
            "node" => {
                let labels = block.labels();
                let role = labels
                    .first()
                    .map(|l| l.as_str())
                    .ok_or("'node' block is missing its role label")?;
                let instance_name =
                    labels
                        .get(1)
                        .map(|l| l.as_str().to_string())
                        .ok_or_else(|| {
                            format!("'node \"{role}\"' block is missing its instance-name label")
                        })?;

                let attrs = block_attrs(block.body());

                let entry = NodeEntry {
                    instance_name,
                    ssh_public_key_path: attrs
                        .get("ssh_public_key_path")
                        .cloned()
                        .unwrap_or_else(|| "~/.ssh/id_ed25519.pub".to_string()),
                    startup_script_path: attrs.get("startup_script_path").cloned().unwrap_or_else(
                        || match role {
                            "control_plane" => "./startup-cp.sh".to_string(),
                            _ => "./startup.sh".to_string(),
                        },
                    ),
                };

                match role {
                    "control_plane" => control_planes.push(entry),
                    "worker" => workers.push(entry),
                    other => {
                        return Err(format!(
                            "Unknown node role '{other}'; expected 'control_plane' or 'worker'"
                        )
                        .into());
                    }
                }
            }

            "node_pool" => {
                let attrs = block_attrs(block.body());
                let size: u64 = attrs
                    .get("boot_disk_size_gb")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(50);
                node_pool = Some(NodePoolEntry {
                    boot_disk_image: attrs
                        .get("boot_disk_image")
                        .cloned()
                        .unwrap_or_else(|| "ubuntu-2404-lts-amd64".to_string()),
                    boot_disk_size_gb: size,
                    machine_type: attrs
                        .get("machine_type")
                        .cloned()
                        .unwrap_or_else(|| "e2-medium".to_string()),
                    name: attrs.get("name").cloned().unwrap_or_else(|| name.clone()),
                });
            }

            "gcp_config" => {
                let attrs = block_attrs(block.body());
                let require_attr = |key: &str| -> Result<String, Box<dyn std::error::Error>> {
                    attrs
                        .get(key)
                        .cloned()
                        .ok_or_else(|| format!("Missing '{key}' in gcp_config block").into())
                };
                gcp = Some(GcpEntry {
                    client_email: require_attr("client_email")?,
                    private_key: require_attr("private_key")?,
                    project_id: require_attr("project_id")?,
                    zone: require_attr("zone")?,
                });
            }

            other => {
                // Silently ignore unknown blocks so the format stays extensible.
                eprintln!("  ⚠  Unknown block '{other}' in maglev config — skipping.");
            }
        }
    }

    if control_planes.is_empty() {
        return Err("Config contains no 'node \"control_plane\" …' blocks".into());
    }
    if workers.is_empty() {
        return Err("Config contains no 'node \"worker\" …' blocks".into());
    }

    Ok(MaglevConfig {
        name,
        control_planes,
        workers,
        node_pool: node_pool.ok_or("Missing 'node_pool' block in config")?,
        gcp: gcp.ok_or("Missing 'gcp_config' block in config")?,
    })
}

// ---------------------------------------------------------------------------
// .maglev HCL config — generator (uses hcl-rs builders)
// ---------------------------------------------------------------------------

fn build_node_block(role: &str, entry: &NodeEntry) -> hcl::Block {
    hcl::Block::builder("node")
        .add_label(role)
        .add_label(&entry.instance_name)
        .add_attribute(("ssh_public_key_path", entry.ssh_public_key_path.as_str()))
        .add_attribute(("startup_script_path", entry.startup_script_path.as_str()))
        .build()
}

fn build_node_pool_block(pool: &NodePoolEntry) -> hcl::Block {
    hcl::Block::builder("node_pool")
        .add_attribute(("boot_disk_image", pool.boot_disk_image.as_str()))
        .add_attribute(("boot_disk_size_gb", pool.boot_disk_size_gb))
        .add_attribute(("machine_type", pool.machine_type.as_str()))
        .add_attribute(("name", pool.name.as_str()))
        .build()
}

fn build_gcp_config_block(gcp: &GcpEntry) -> hcl::Block {
    hcl::Block::builder("gcp_config")
        .add_attribute(("client_email", gcp.client_email.as_str()))
        .add_attribute(("private_key", gcp.private_key.as_str()))
        .add_attribute(("project_id", gcp.project_id.as_str()))
        .add_attribute(("zone", gcp.zone.as_str()))
        .build()
}

fn serialize_config(cfg: &MaglevConfig) -> Result<String, Box<dyn std::error::Error>> {
    let mut inner = hcl::Body::builder();

    for entry in &cfg.control_planes {
        inner = inner.add_block(build_node_block("control_plane", entry));
    }
    for entry in &cfg.workers {
        inner = inner.add_block(build_node_block("worker", entry));
    }
    inner = inner.add_block(build_node_pool_block(&cfg.node_pool));
    inner = inner.add_block(build_gcp_config_block(&cfg.gcp));

    // hcl-rs can only render a top-level Body, so we embed the inner body
    // attributes/blocks into a `maglev "<name>" { … }` wrapper block.
    let maglev_block = hcl::Block::builder("maglev")
        .add_label(&cfg.name)
        .add_blocks(inner.build().into_blocks())
        .build();

    let outer = hcl::Body::builder().add_block(maglev_block).build();
    Ok(hcl::to_string(&outer)?)
}

// ---------------------------------------------------------------------------
// `generate` subcommand
// ---------------------------------------------------------------------------

/// Parse a comma-separated env var into a `Vec<String>`, stripping whitespace.
fn env_list(var: &str) -> Option<Vec<String>> {
    env::var(var).ok().map(|v| {
        v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

fn generate_config(config_path: &str, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    if !force && Path::new(config_path).exists() {
        eprintln!("error: '{config_path}' already exists");
        eprintln!("  Use -f to overwrite.");
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
    let boot_disk_size_gb: u64 = env::var("MAGLEV_BOOT_DISK_SIZE_GB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let ssh_public_key_path = env::var("MAGLEV_SSH_PUBLIC_KEY_PATH")
        .unwrap_or_else(|_| "~/.ssh/id_ed25519.pub".to_string());
    let cp_startup_script_path =
        env::var("MAGLEV_CP_STARTUP_SCRIPT_PATH").unwrap_or_else(|_| "./startup-cp.sh".to_string());
    let worker_startup_script_path = env::var("MAGLEV_WORKER_STARTUP_SCRIPT_PATH")
        .unwrap_or_else(|_| "./startup.sh".to_string());

    // ── Node arrays ──────────────────────────────────────────────────────────
    //
    // Override via comma-separated env vars:
    //   MAGLEV_CP_INSTANCES=maglev-cp-alpha,maglev-cp-beta
    //   MAGLEV_WORKER_INSTANCES=maglev-worker-alpha,maglev-worker-beta,maglev-worker-gamma
    let cp_names = env_list("MAGLEV_CP_INSTANCES")
        .unwrap_or_else(|| vec![format!("maglev-cp-alpha"), format!("maglev-cp-beta")]);

    let worker_names = env_list("MAGLEV_WORKER_INSTANCES").unwrap_or_else(|| {
        vec![
            format!("maglev-worker-alpha"),
            format!("maglev-worker-beta"),
            format!("maglev-worker-gamma"),
        ]
    });

    let control_planes: Vec<NodeEntry> = cp_names
        .iter()
        .map(|n| NodeEntry {
            instance_name: n.clone(),
            ssh_public_key_path: ssh_public_key_path.clone(),
            startup_script_path: cp_startup_script_path.clone(),
        })
        .collect();

    let workers: Vec<NodeEntry> = worker_names
        .iter()
        .map(|n| NodeEntry {
            instance_name: n.clone(),
            ssh_public_key_path: ssh_public_key_path.clone(),
            startup_script_path: worker_startup_script_path.clone(),
        })
        .collect();

    let cfg = MaglevConfig {
        name: name.clone(),
        control_planes,
        workers,
        node_pool: NodePoolEntry {
            boot_disk_image,
            boot_disk_size_gb,
            machine_type,
            name: name.clone(),
        },
        gcp: GcpEntry {
            client_email,
            private_key,
            project_id,
            zone,
        },
    };

    let hcl_text = serialize_config(&cfg)?;

    fs::write(config_path, &hcl_text)
        .map_err(|e| format!("Cannot write config to '{config_path}': {e}"))?;

    println!("✓ Config written to: {config_path}");
    println!(
        "  control-plane nodes : {}",
        cfg.control_planes
            .iter()
            .map(|n| n.instance_name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  worker nodes        : {}",
        cfg.workers
            .iter()
            .map(|n| n.instance_name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared: load GCP private key from config
// ---------------------------------------------------------------------------

fn load_gcp_private_key(gcp: &GcpEntry) -> Result<String, Box<dyn std::error::Error>> {
    let expanded = expand_tilde(&gcp.private_key);
    fs::read_to_string(&expanded)
        .map_err(|e| format!("Cannot read GCP private key from '{expanded}': {e}").into())
}

// ---------------------------------------------------------------------------
// `apply` subcommand
// ---------------------------------------------------------------------------

fn apply_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Apply ===\n");
    println!("Reading config: {config_path}");

    let content = fs::read_to_string(config_path)
        .map_err(|e| format!("Cannot read config file '{config_path}': {e}"))?;
    let cfg = parse_maglev_config(&content)?;

    let pool = &cfg.node_pool;
    let gcp = &cfg.gcp;

    println!("\n── Shared settings ─────────────────────────────────────────────────────");
    println!("  Project:           {}", gcp.project_id);
    println!("  Zone:              {}", gcp.zone);
    println!("  Machine type:      {}", pool.machine_type);
    println!("  Boot disk image:   {}", pool.boot_disk_image);
    println!("  Boot disk size:    {} GB", pool.boot_disk_size_gb);
    println!("  Service account:   {}", gcp.client_email);

    println!(
        "\n── Control-plane nodes ({}) ─────────────────────────────────────────────",
        cfg.control_planes.len()
    );
    for cp in &cfg.control_planes {
        println!(
            "  {}  (ssh key: {})",
            cp.instance_name, cp.ssh_public_key_path
        );
        println!("    startup: {}", cp.startup_script_path);
    }

    println!(
        "\n── Worker nodes ({}) ────────────────────────────────────────────────────",
        cfg.workers.len()
    );
    for w in &cfg.workers {
        println!(
            "  {}  (ssh key: {})",
            w.instance_name, w.ssh_public_key_path
        );
        println!("    startup: {}", w.startup_script_path);
    }

    let total = cfg.control_planes.len() + cfg.workers.len();
    if !prompt_yes_no(&format!("\nProceed with creating {total} VM instances?")) {
        println!("Aborted.");
        return Ok(());
    }

    let private_key = load_gcp_private_key(gcp)?;

    println!("\n  Signing JWT with RSA-SHA256...");
    let jwt = create_jwt(
        &private_key,
        &gcp.client_email,
        "https://www.googleapis.com/auth/compute",
    )?;

    println!("  Exchanging JWT for OAuth2 access token...");
    let access_token = get_access_token(&jwt)?;

    // ── Create control-plane nodes ───────────────────────────────────────────
    for cp in &cfg.control_planes {
        println!(
            "\n  ── Creating control-plane node ({}) ──",
            cp.instance_name
        );

        let ssh_meta = read_ssh_public_key(&cp.ssh_public_key_path)
            .map(|k| format!("ubuntu:{k}"))
            .unwrap_or_else(|e| {
                eprintln!("  ⚠ Could not read SSH public key: {e}");
                String::new()
            });
        let script = read_startup_script(&cp.startup_script_path);

        let resp = create_vm(
            &access_token,
            &gcp.project_id,
            &gcp.zone,
            &cp.instance_name,
            &pool.machine_type,
            &pool.boot_disk_image,
            pool.boot_disk_size_gb,
            &ssh_meta,
            &script,
        )?;
        println!("{}", serde_json::to_string_pretty(&resp)?);
    }

    // ── Create worker nodes ──────────────────────────────────────────────────
    for w in &cfg.workers {
        println!("\n  ── Creating worker node ({}) ──", w.instance_name);

        let ssh_meta = read_ssh_public_key(&w.ssh_public_key_path)
            .map(|k| format!("ubuntu:{k}"))
            .unwrap_or_else(|e| {
                eprintln!("  ⚠ Could not read SSH public key: {e}");
                String::new()
            });
        let script = read_startup_script(&w.startup_script_path);

        let resp = create_vm(
            &access_token,
            &gcp.project_id,
            &gcp.zone,
            &w.instance_name,
            &pool.machine_type,
            &pool.boot_disk_image,
            pool.boot_disk_size_gb,
            &ssh_meta,
            &script,
        )?;
        println!("{}", serde_json::to_string_pretty(&resp)?);
    }

    println!("\n✓ All {total} VM creation requests submitted successfully.");
    Ok(())
}

// ---------------------------------------------------------------------------
// `destroy` subcommand
// ---------------------------------------------------------------------------

fn destroy_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Destroy ===\n");
    println!("Reading config: {config_path}");

    let content = fs::read_to_string(config_path)
        .map_err(|e| format!("Cannot read config file '{config_path}': {e}"))?;
    let cfg = parse_maglev_config(&content)?;

    let gcp = &cfg.gcp;

    println!("\n── Instances to destroy ────────────────────────────────────────────────");
    println!("  Project:         {}", gcp.project_id);
    println!("  Zone:            {}", gcp.zone);
    println!("  Service account: {}", gcp.client_email);
    println!();
    for cp in &cfg.control_planes {
        println!("  control-plane  → {}", cp.instance_name);
    }
    for w in &cfg.workers {
        println!("  worker         → {}", w.instance_name);
    }

    let total = cfg.control_planes.len() + cfg.workers.len();
    println!();
    println!("⚠  This action is IRREVERSIBLE. All {total} VM instances and their boot");
    println!("   disks will be permanently deleted.");

    if !prompt_yes_no("\nProceed with destroying all VM instances?") {
        println!("Aborted — nothing was deleted.");
        return Ok(());
    }

    let private_key = load_gcp_private_key(gcp)?;

    println!("\n  Signing JWT with RSA-SHA256...");
    let jwt = create_jwt(
        &private_key,
        &gcp.client_email,
        "https://www.googleapis.com/auth/compute",
    )?;

    println!("  Exchanging JWT for OAuth2 access token...");
    let access_token = get_access_token(&jwt)?;

    for cp in &cfg.control_planes {
        println!(
            "\n  ── Deleting control-plane node ({}) ──",
            cp.instance_name
        );
        match delete_vm(&access_token, &gcp.project_id, &gcp.zone, &cp.instance_name) {
            Ok(body) => println!("{}", serde_json::to_string_pretty(&body)?),
            Err(e) => eprintln!("  ✗ Failed to delete {}: {e}", cp.instance_name),
        }
    }

    for w in &cfg.workers {
        println!("\n  ── Deleting worker node ({}) ──", w.instance_name);
        match delete_vm(&access_token, &gcp.project_id, &gcp.zone, &w.instance_name) {
            Ok(body) => println!("{}", serde_json::to_string_pretty(&body)?),
            Err(e) => eprintln!("  ✗ Failed to delete {}: {e}", w.instance_name),
        }
    }

    println!("\n✓ Deletion requests submitted. GCP operations may take a minute to complete.");
    println!("  Track progress:");
    println!(
        "    gcloud compute operations list --filter=\"zone:{}\" --project={}",
        gcp.zone, gcp.project_id
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// `play` subcommand
//
// 1. For each control-plane node:
//      • Check if /etc/kubernetes/admin.conf exists.
//      • If not → prompt → run `sudo cisak install --control-plane -y`.
// 2. For each worker node:
//      • Fetch a fresh join command from the first control-plane.
//      • Prompt → run `sudo <join-command>` on the worker.
// ---------------------------------------------------------------------------

fn play_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Play ===\n");
    println!("Reading config: {config_path}");

    let content = fs::read_to_string(config_path)
        .map_err(|e| format!("Cannot read config file '{config_path}': {e}"))?;
    let cfg = parse_maglev_config(&content)?;

    let gcp = &cfg.gcp;
    let ssh_user = env::var("MAGLEV_SSH_USER").unwrap_or_else(|_| "ubuntu".to_string());

    // ── GCP authentication ───────────────────────────────────────────────────
    let gcp_private_key = load_gcp_private_key(gcp)?;

    println!("\n  Signing JWT...");
    let jwt = create_jwt(
        &gcp_private_key,
        &gcp.client_email,
        "https://www.googleapis.com/auth/compute",
    )?;
    println!("  Exchanging JWT for OAuth2 access token...");
    let access_token = get_access_token(&jwt)?;

    // ── Resolve external IPs for every node ──────────────────────────────────
    println!("\n  Fetching external IPs from Compute Engine API...");

    struct NodeInfo {
        entry: NodeEntry,
        ip: String,
        ssh_priv: String,
    }

    let resolve = |entries: &[NodeEntry]| -> Result<Vec<NodeInfo>, Box<dyn std::error::Error>> {
        entries
            .iter()
            .map(|e| {
                let ip = get_vm_ip(&access_token, &gcp.project_id, &gcp.zone, &e.instance_name)?;
                let ssh_priv = expand_tilde(
                    e.ssh_public_key_path
                        .strip_suffix(".pub")
                        .unwrap_or(&e.ssh_public_key_path),
                );
                println!("  {:<30} →  {ip}", e.instance_name);
                Ok(NodeInfo {
                    entry: e.clone(),
                    ip,
                    ssh_priv,
                })
            })
            .collect()
    };

    let cp_nodes = resolve(&cfg.control_planes)?;
    let worker_nodes = resolve(&cfg.workers)?;

    println!("  SSH user: {ssh_user}");

    // ════════════════════════════════════════════════════════════════════════
    // Step 1 — Provision each control-plane node
    // ════════════════════════════════════════════════════════════════════════
    println!(
        "\n━━ Step 1 / 2 — Control-plane provisioning ({} nodes) ━━━━━━━━━━━━━━━━━",
        cp_nodes.len()
    );

    for (idx, cp) in cp_nodes.iter().enumerate() {
        let ordinal = idx + 1;
        let name = &cp.entry.instance_name;
        let ip = &cp.ip;

        println!("\n  [{ordinal}/{}] {name}  ({ip})", cp_nodes.len());
        println!("  Checking /etc/kubernetes/admin.conf …");

        if !prompt_yes_no(&format!("  Run SSH check on {ssh_user}@{ip}?")) {
            println!("  Skipped.");
            continue;
        }

        let check = ssh_capture(
            ip,
            &ssh_user,
            &cp.ssh_priv,
            "test -f /etc/kubernetes/admin.conf && echo yes || echo no",
        )?;

        if check.trim() == "yes" {
            println!("  ✓ Already provisioned — skipping.");
            continue;
        }

        println!("  Not provisioned yet.");
        println!("  Command : sudo cisak install --control-plane -y");
        println!("  ⚠  This will install Kubernetes on the control-plane node.");

        if !prompt_yes_no("  Proceed?") {
            println!("  Skipped.");
            continue;
        }

        println!("\n  Running provisioning — this may take several minutes …\n");
        ssh_run(
            ip,
            &ssh_user,
            &cp.ssh_priv,
            "sudo cisak install --control-plane -y",
        )?;
        println!("\n  ✓ {name} provisioned.");
    }

    // ════════════════════════════════════════════════════════════════════════
    // Step 2 — Join each worker to the control-plane
    //
    // Join commands are fetched from the *first* control-plane each time so
    // the token is always fresh (kubeadm tokens expire after 24 h by default).
    // ════════════════════════════════════════════════════════════════════════
    println!(
        "\n━━ Step 2 / 2 — Join workers ({} nodes) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        worker_nodes.len()
    );

    let primary_cp = cp_nodes
        .first()
        .ok_or("No control-plane nodes available to issue join commands")?;

    for (idx, w) in worker_nodes.iter().enumerate() {
        let ordinal = idx + 1;
        let name = &w.entry.instance_name;
        let ip = &w.ip;

        println!("\n  [{ordinal}/{}] {name}  ({ip})", worker_nodes.len());
        println!(
            "  Fetching join command from {} …",
            primary_cp.entry.instance_name
        );
        println!("  Command on CP: sudo kubeadm token create --print-join-command");

        if !prompt_yes_no("  Fetch join command?") {
            println!("  Skipped.");
            continue;
        }

        let join_command = ssh_capture(
            &primary_cp.ip,
            &ssh_user,
            &primary_cp.ssh_priv,
            "sudo kubeadm token create --print-join-command",
        )?;

        if join_command.is_empty() {
            eprintln!(
                "  ✗ kubeadm returned an empty join command — is {} fully up?",
                primary_cp.entry.instance_name
            );
            continue;
        }

        println!("  Join command : {join_command}");
        println!("  Will run on  : {ssh_user}@{ip}");
        println!("  ⚠  The worker will be permanently joined to the cluster.");

        if !prompt_yes_no("  Proceed?") {
            println!("  Skipped.");
            continue;
        }

        println!("\n  Joining {name} to cluster …\n");
        ssh_run(ip, &ssh_user, &w.ssh_priv, &format!("sudo {join_command}"))?;
        println!("\n  ✓ {name} joined.");
    }

    println!("\n✓ Cluster provisioning complete!");
    println!();
    println!("  Verify from the primary control-plane:");
    println!(
        "    ssh -i {} {ssh_user}@{}",
        primary_cp.ssh_priv, primary_cp.ip
    );
    println!("    kubectl get nodes -o wide");

    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point — subcommand dispatch
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    match env::args().nth(1).as_deref() {
        Some("generate") => {
            // Collect every arg after the sub-command name.
            let rest: Vec<String> = env::args().skip(2).collect();
            let force = rest.iter().any(|a| a == "-f" || a == "--force");
            let path = rest.iter().find(|a| !a.starts_with('-'));

            match path {
                Some(p) => generate_config(p, force),
                None => {
                    eprintln!("error: 'generate' requires a config file path");
                    eprintln!();
                    eprintln!("USAGE:");
                    eprintln!("    maglev generate [-f] <config.maglev>");
                    std::process::exit(1);
                }
            }
        }

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
            eprintln!("    generate [-f] <config>   Generate a .maglev config file from env vars");
            eprintln!("    apply <config>           Create VMs from a .maglev config file");
            eprintln!(
                "    destroy <config>         Permanently delete VMs described in a .maglev config"
            );
            eprintln!(
                "    play <config>            Provision Kubernetes and join workers to the control-plane"
            );
            eprintln!("    print                    Run the credential builder");
            std::process::exit(1);
        }
    }
}
