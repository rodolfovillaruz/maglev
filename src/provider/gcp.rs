use crate::provider::Provider;
use crate::structs::{GenericsYaml, GroupYaml, ProvisionerYaml, RuleYaml};
use crate::utils::prompt_yes_no;
use std::io::{BufRead, Write, stdin, stdout};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::Path;

// ---------------------------------------------------------------------------
// Credential types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct ServiceAccountCredentials {
    #[serde(rename = "type")]
    credential_type: String,
    private_key: String,
    client_email: String,
}

#[derive(Debug, Clone)]
pub struct GcpCredentials {
    pub client_email: String,
    /// Path to the PEM private key file.
    pub private_key_path: String,
    pub project_id: String,
    pub zone: String,
}

// ---------------------------------------------------------------------------
// Provider-specific credential types
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct GcpCredentialsYaml {
    #[serde(rename = "client-email")]
    pub client_email: String,
    #[serde(rename = "private-key")]
    pub private_key: String,
    #[serde(rename = "project-id")]
    pub project_id: String,
    pub zone: String,
}

// ---------------------------------------------------------------------------
// GcpProvider — implements Provider
// ---------------------------------------------------------------------------

pub struct GcpProvider {
    access_token: String,
    project_id: String,
    zone: String,
}

impl GcpProvider {
    pub fn new(creds: &GcpCredentials) -> Result<Self, Box<dyn std::error::Error>> {
        let private_key_pem = fs::read_to_string(&creds.private_key_path).map_err(|e| {
            format!(
                "Cannot read GCP private key from '{}': {e}",
                creds.private_key_path
            )
        })?;

        println!("  Signing JWT with RSA-SHA256 …");
        let jwt = create_jwt(
            &private_key_pem,
            &creds.client_email,
            "https://www.googleapis.com/auth/compute",
        )?;

        println!("  Exchanging JWT for OAuth2 access token …");
        let access_token = get_access_token(&jwt)?;

        Ok(Self {
            access_token,
            project_id: creds.project_id.clone(),
            zone: creds.zone.clone(),
        })
    }
}

impl Provider for GcpProvider {
    /// Create a GCE instance.
    ///
    /// When `assign_public_ip` is `true` an ephemeral external IP is attached
    /// via an `accessConfigs` entry on the first network interface.  When
    /// `false` the instance is created with an internal IP only.
    fn create_vm(
        &self,
        instance_name: &str,
        machine_type: &str,
        boot_disk_image: &str,
        boot_disk_size_gb: u64,
        ssh_keys_metadata: &str,
        startup_script: &str,
        assign_public_ip: bool,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let url = format!(
            "https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances",
            self.project_id, self.zone
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

        // Build the network interface.  An `accessConfigs` block with type
        // ONE_TO_ONE_NAT gives the instance an ephemeral external IP; omitting
        // it means internal-only.
        let network_interface = if assign_public_ip {
            serde_json::json!({
                "network": "global/networks/default",
                "accessConfigs": [{
                    "type": "ONE_TO_ONE_NAT",
                    "name": "External NAT",
                    "networkTier": "PREMIUM"
                }]
            })
        } else {
            serde_json::json!({
                "network": "global/networks/default"
            })
        };

        let zone = &self.zone;
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
            "networkInterfaces": [network_interface],
            "metadata": { "items": metadata_items }
        });

        let agent = build_agent();
        let mut resp = agent
            .post(&url)
            .header("Authorization", &format!("Bearer {}", self.access_token))
            .header("Content-Type", "application/json")
            .send_json(request_body)?;

        let status = resp.status();
        let body: Value = resp.body_mut().read_json()?;

        if !status.is_success() {
            return Err(format!("Compute Engine API returned HTTP {status}: {body}").into());
        }

        Ok(body)
    }

    fn destroy_vm(&self, instance_name: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let url = format!(
            "https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}",
            self.project_id, self.zone, instance_name
        );

        let agent = build_agent();
        let mut resp = agent
            .delete(&url)
            .header("Authorization", &format!("Bearer {}", self.access_token))
            .call()?;

        let status = resp.status();
        let body: Value = resp.body_mut().read_json()?;

        if !status.is_success() {
            return Err(format!("Compute Engine API returned HTTP {status}: {body}").into());
        }

        Ok(body)
    }

    /// Return the IP address of a GCE instance.
    ///
    /// `prefer_public = true`  → `networkInterfaces[0].accessConfigs[0].natIP`
    ///                           (the external ephemeral IP, if one was assigned)
    /// `prefer_public = false` → `networkInterfaces[0].networkIP`
    ///                           (the internal VPC IP)
    fn get_vm_ip(
        &self,
        instance_name: &str,
        prefer_public: bool,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let url = format!(
            "https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}",
            self.project_id, self.zone, instance_name
        );

        let agent = build_agent();
        let mut resp = agent
            .get(&url)
            .header("Authorization", &format!("Bearer {}", self.access_token))
            .call()?;

        let status = resp.status();
        let body: Value = resp.body_mut().read_json()?;

        if !status.is_success() {
            return Err(format!(
                "Compute Engine API returned HTTP {status} while fetching '{instance_name}': {body}"
            )
            .into());
        }

        let iface = &body["networkInterfaces"][0];

        if prefer_public {
            // natIP is only present when an accessConfig of type ONE_TO_ONE_NAT
            // was attached at creation time.
            iface["accessConfigs"][0]["natIP"]
                .as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    format!(
                        "No external (public) IP found for instance '{instance_name}'. \
                         Was it created with ip-address: public?"
                    )
                    .into()
                })
        } else {
            iface["networkIP"]
                .as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    format!("No internal IP found for instance '{instance_name}'").into()
                })
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn build_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into()
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
    let agent = build_agent();
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
// Credential-builder (`maglev print`)
// ---------------------------------------------------------------------------

pub fn print_build_credential() -> Result<(), Box<dyn std::error::Error>> {
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

    println!("\n── Credentials ─────────────────────────────────────────────────────────\n");

    let credentials = ServiceAccountCredentials {
        credential_type: "service_account".to_string(),
        private_key: private_key.clone(),
        client_email: client_email.clone(),
    };

    if prompt_yes_no("\nPrint the JSON file?") {
        println!("{}", serde_json::to_string_pretty(&credentials)?);
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
            .ok_or("Missing 'private_key' in credentials file")?
            .to_string();
        let client_email = json["client_email"]
            .as_str()
            .ok_or("Missing 'client_email' in credentials file")?
            .to_string();
        Ok((private_key, client_email))
    })();

    Some(result)
}

fn load_maglev_private_key() -> Result<(String, String), Box<dyn std::error::Error>> {
    let key_path = env::var("MAGLEV_PRIVATE_KEY")
        .map_err(|_| "MAGLEV_PRIVATE_KEY environment variable is not set")?;

    println!("MAGLEV_PRIVATE_KEY = {key_path}");

    let private_key = if Path::new(&key_path).exists() {
        println!("  Key file found — reading …");
        fs::read_to_string(&key_path).map_err(|e| format!("Cannot read '{key_path}': {e}"))?
    } else {
        println!("  Key file does not exist at: {key_path}");
        if !prompt_yes_no("  Generate and save a new RSA-2048 private key?") {
            eprintln!("  Aborted.");
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

fn prompt_client_email() -> Result<String, Box<dyn std::error::Error>> {
    print!("  Enter client email: ");
    stdout()
        .flush()
        .map_err(|e| format!("Failed to flush stdout: {e}"))?;
    let mut line = String::new();
    stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("Failed to read stdin: {e}"))?;
    let email = line.trim().to_string();
    if email.is_empty() {
        Err("Client email cannot be empty.".into())
    } else {
        Ok(email)
    }
}

fn generate_rsa_private_key_pem() -> Result<String, Box<dyn std::error::Error>> {
    use rsa::{
        RsaPrivateKey,
        pkcs8::{EncodePrivateKey, LineEnding},
    };
    println!("  Generating RSA-2048 private key …");
    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let pem = private_key.to_pkcs8_pem(LineEnding::LF)?;
    Ok(pem.to_string())
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct GcpYaml {
    pub group: Vec<GroupYaml>,
    pub specs: Vec<GenericsYaml>,
    pub rules: Vec<RuleYaml>,
    pub credentials: GcpCredentialsYaml,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioner: Option<ProvisionerYaml>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct GcpRoot {
    pub gcp: GcpYaml,
}
