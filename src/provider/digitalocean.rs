use crate::provider::Provider;
use crate::structs::{GroupYaml, ProvisionerYaml, RuleYaml, SpecYaml};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Credential types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DigitalOceanCredentials {
    pub token: String,
    pub region: String,
}

// ---------------------------------------------------------------------------
// DigitalOceanProvider — implements Provider
// ---------------------------------------------------------------------------

pub struct DigitalOceanProvider {
    token: String,
    region: String,
}

impl DigitalOceanProvider {
    pub fn new(creds: &DigitalOceanCredentials) -> Result<Self, Box<dyn std::error::Error>> {
        println!("  Validating DigitalOcean API token …");

        let agent = build_agent();
        let mut resp = agent
            .get("https://api.digitalocean.com/v2/account")
            .header("Authorization", &format!("Bearer {}", creds.token))
            .call()?;

        let status = resp.status();
        let body: Value = resp.body_mut().read_json()?;

        if !status.is_success() {
            return Err(
                format!("DigitalOcean authentication failed (HTTP {status}): {body}").into(),
            );
        }

        Ok(Self {
            token: creds.token.clone(),
            region: creds.region.clone(),
        })
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Look up a droplet by name and return its numeric ID.
    fn get_droplet_id(&self, name: &str) -> Result<u64, Box<dyn std::error::Error>> {
        let url = format!("https://api.digitalocean.com/v2/droplets?name={}", name);

        let agent = build_agent();
        let mut resp = agent
            .get(&url)
            .header("Authorization", &format!("Bearer {}", self.token))
            .call()?;

        let status = resp.status();
        let body: Value = resp.body_mut().read_json()?;

        if !status.is_success() {
            return Err(format!(
                "DigitalOcean API returned HTTP {status} while looking up '{name}': {body}"
            )
            .into());
        }

        body["droplets"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|d| d["id"].as_u64())
            .ok_or_else(|| format!("No droplet found with name '{name}'").into())
    }

    /// Ensure `public_key` is registered in the account and return its
    /// fingerprint.  If the key already exists a list lookup is performed to
    /// find the matching fingerprint rather than attempting re-registration.
    fn ensure_ssh_key(&self, public_key: &str) -> Result<String, Box<dyn std::error::Error>> {
        let public_key = public_key.trim();

        let key_name = public_key.split_whitespace().nth(2).unwrap_or("maglev-key");

        let agent = build_agent();
        let mut resp = agent
            .post("https://api.digitalocean.com/v2/account/keys")
            .header("Authorization", &format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .send_json(serde_json::json!({
                "name": key_name,
                "public_key": public_key,
            }))?;

        let status = resp.status();
        let body: Value = resp.body_mut().read_json()?;

        if status.as_u16() == 201 {
            return body["ssh_key"]["fingerprint"]
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| "Missing fingerprint in SSH key registration response".into());
        }

        if status.as_u16() == 422 {
            return self.find_ssh_key_fingerprint(public_key);
        }

        Err(format!("Failed to register SSH key (HTTP {status}): {body}").into())
    }

    /// List all registered SSH keys and return the fingerprint of the one
    /// whose type+blob matches `public_key`.
    fn find_ssh_key_fingerprint(
        &self,
        public_key: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let needle: String = public_key
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");

        let agent = build_agent();
        let mut resp = agent
            .get("https://api.digitalocean.com/v2/account/keys?per_page=200")
            .header("Authorization", &format!("Bearer {}", self.token))
            .call()?;

        let status = resp.status();
        let body: Value = resp.body_mut().read_json()?;

        if !status.is_success() {
            return Err(format!("Failed to list SSH keys (HTTP {status}): {body}").into());
        }

        body["ssh_keys"]
            .as_array()
            .ok_or("No ssh_keys array in account keys response")?
            .iter()
            .find(|k| {
                k["public_key"]
                    .as_str()
                    .map(|s| s.starts_with(&needle))
                    .unwrap_or(false)
            })
            .and_then(|k| k["fingerprint"].as_str())
            .map(str::to_string)
            .ok_or_else(|| "Could not find matching SSH key in DigitalOcean account".into())
    }
}

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

impl Provider for DigitalOceanProvider {
    /// Create a DigitalOcean Droplet.
    ///
    /// `assign_public_ip` — DigitalOcean Droplets always receive a public IP,
    /// so this parameter is accepted for interface parity but has no effect on
    /// the API call.
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
        // DigitalOcean Droplets always have a public IP; nothing extra to do.
        let _ = assign_public_ip;

        // Strip the optional "username:" prefix (written by the GCP path).
        let public_key = match ssh_keys_metadata.find(':') {
            Some(idx) => ssh_keys_metadata[idx + 1..].trim(),
            None => ssh_keys_metadata.trim(),
        };

        let mut ssh_fingerprints: Vec<String> = Vec::new();
        if !public_key.is_empty() {
            let fp = self.ensure_ssh_key(public_key)?;
            println!("    SSH key fingerprint: {fp}");
            ssh_fingerprints.push(fp);
        }

        // boot_disk_size_gb: accepted for interface parity; DO sizes are
        // fixed per slug, so this parameter is intentionally unused.
        let _ = boot_disk_size_gb;

        let request_body = serde_json::json!({
            "name":      instance_name,
            "region":    self.region,
            "size":      resolve_size(machine_type),
            "image":     resolve_image(boot_disk_image),
            "ssh_keys":  ssh_fingerprints,
            "user_data": startup_script,
            "tags":      ["maglev"],
        });

        let agent = build_agent();
        let mut resp = agent
            .post("https://api.digitalocean.com/v2/droplets")
            .header("Authorization", &format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .send_json(request_body)?;

        let status = resp.status();
        let body: Value = resp.body_mut().read_json()?;

        if !status.is_success() {
            return Err(format!("DigitalOcean API returned HTTP {status}: {body}").into());
        }

        Ok(body)
    }

    /// Delete a Droplet by name.  Returns a synthetic JSON confirmation
    /// because the DO DELETE endpoint returns 204 No Content on success.
    fn destroy_vm(&self, instance_name: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let id = self.get_droplet_id(instance_name)?;
        let url = format!("https://api.digitalocean.com/v2/droplets/{id}");

        let agent = build_agent();
        let mut resp = agent
            .delete(&url)
            .header("Authorization", &format!("Bearer {}", self.token))
            .call()?;

        let status = resp.status();

        if status.as_u16() == 204 {
            return Ok(serde_json::json!({
                "status": "deleted",
                "id":     id,
                "name":   instance_name,
            }));
        }

        let body: Value = resp.body_mut().read_json()?;
        Err(format!("DigitalOcean API returned HTTP {status}: {body}").into())
    }

    /// Return the IP address of a Droplet.
    ///
    /// `prefer_public = true`  → public IP (type `"public"`) is returned
    ///                           first; falls back to private if absent.
    /// `prefer_public = false` → private IP (type `"private"`) is preferred;
    ///                           falls back to public if no private exists.
    fn get_vm_ip(
        &self,
        instance_name: &str,
        prefer_public: bool,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let url = format!(
            "https://api.digitalocean.com/v2/droplets?name={}",
            instance_name
        );

        let agent = build_agent();
        let mut resp = agent
            .get(&url)
            .header("Authorization", &format!("Bearer {}", self.token))
            .call()?;

        let status = resp.status();
        let body: Value = resp.body_mut().read_json()?;

        if !status.is_success() {
            return Err(format!(
                "DigitalOcean API returned HTTP {status} while fetching '{instance_name}': {body}"
            )
            .into());
        }

        let droplet = body["droplets"]
            .as_array()
            .and_then(|a| a.first())
            .ok_or_else(|| format!("No droplet found with name '{instance_name}'"))?;

        let networks = droplet["networks"]["v4"]
            .as_array()
            .ok_or_else(|| format!("No v4 networks on droplet '{instance_name}'"))?;

        let (primary, fallback) = if prefer_public {
            ("public", "private")
        } else {
            ("private", "public")
        };

        networks
            .iter()
            .find(|n| n["type"] == primary)
            .or_else(|| networks.iter().find(|n| n["type"] == fallback))
            .and_then(|n| n["ip_address"].as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("No IP address found for droplet '{instance_name}'").into())
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

/// Map GCP-style image names to DigitalOcean image slugs.
fn resolve_image(image: &str) -> String {
    match image {
        "ubuntu-2404-lts-amd64" | "ubuntu-24-04-x64" => "ubuntu-24-04-x64",
        "ubuntu-2204-lts-amd64" | "ubuntu-22-04-x64" => "ubuntu-22-04-x64",
        "ubuntu-2004-lts-amd64" | "ubuntu-20-04-x64" => "ubuntu-20-04-x64",
        "debian-12-x64" | "debian-12" => "debian-12-x64",
        "debian-11-x64" | "debian-11" => "debian-11-x64",
        other => other,
    }
    .to_string()
}

/// Map GCP-style machine types to DigitalOcean size slugs.
fn resolve_size(machine_type: &str) -> String {
    if machine_type.starts_with("s-")
        || machine_type.starts_with("c-")
        || machine_type.starts_with("g-")
        || machine_type.starts_with("m-")
        || machine_type.starts_with("so-")
    {
        return machine_type.to_string();
    }

    match machine_type {
        "e2-micro" => "s-1vcpu-1gb",
        "e2-small" => "s-1vcpu-2gb",
        "e2-medium" => "s-2vcpu-2gb",
        "e2-standard-2" => "s-2vcpu-4gb",
        "e2-standard-4" => "s-4vcpu-8gb",
        "e2-standard-8" => "s-8vcpu-16gb",
        "e2-standard-16" => "s-16vcpu-64gb",
        other => other,
    }
    .to_string()
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct DoRoot {
    pub digitalocean: DoYaml,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct DoCredentialsYaml {
    pub token: String,
    pub region: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct DoYaml {
    pub group: Vec<GroupYaml>,
    pub specs: Vec<SpecYaml>,
    pub rules: Vec<RuleYaml>,
    pub credentials: DoCredentialsYaml,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioner: Option<ProvisionerYaml>,
}
