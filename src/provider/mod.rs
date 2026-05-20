use crate::provider::digitalocean::{DigitalOceanCredentials, DigitalOceanProvider, DoRoot};
use crate::provider::gcp::{GcpCredentials, GcpProvider, GcpRoot};
use crate::structs::{CommonConfig, ProvisionerYaml};
use crate::utils::{expand_tilde, validate_specs};
use std::fs;

pub mod digitalocean;
pub mod gcp;

pub enum LoadedProvider {
    Gcp {
        common: CommonConfig,
        location: String,
        provisioner: Option<ProvisionerYaml>,
        provider: GcpProvider,
    },
    DigitalOcean {
        common: CommonConfig,
        location: String,
        provisioner: Option<ProvisionerYaml>,
        provider: DigitalOceanProvider,
    },
}

impl LoadedProvider {
    pub fn common(&self) -> &CommonConfig {
        match self {
            LoadedProvider::Gcp { common, .. } => common,
            LoadedProvider::DigitalOcean { common, .. } => common,
        }
    }

    pub fn provider(&self) -> &dyn Provider {
        match self {
            LoadedProvider::Gcp { provider, .. } => provider,
            LoadedProvider::DigitalOcean { provider, .. } => provider,
        }
    }

    pub fn describe(&self) {
        match self {
            LoadedProvider::Gcp {
                location,
                provisioner,
                ..
            } => {
                println!("  Provider:        GCP");
                println!("  Zone:            {location}");
                if let Some(p) = provisioner {
                    println!("  Provisioner:     {} ({})", p.node, p.provisioner_type);
                }
            }
            LoadedProvider::DigitalOcean {
                location,
                provisioner,
                ..
            } => {
                println!("  Provider:        DigitalOcean");
                println!("  Region:          {location}");
                if let Some(p) = provisioner {
                    println!("  Provisioner:     {} ({})", p.node, p.provisioner_type);
                }
            }
        }
    }
}

/// Cloud-provider abstraction.
///
/// Each implementation holds its own authentication context and exposes the
/// three lifecycle operations Maglev needs.
pub trait Provider {
    /// Create a VM instance.
    ///
    /// `assign_public_ip` — when `true` the provider should attach an
    /// external/public IP to the new instance.  When `false` (or when the
    /// provider always assigns a public IP by default, as DigitalOcean does)
    /// the parameter may be ignored.
    fn create_vm(
        &self,
        instance_name: &str,
        machine_type: &str,
        boot_disk_image: &str,
        boot_disk_size_gb: u64,
        ssh_keys_metadata: &str,
        startup_script: &str,
        assign_public_ip: bool,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>>;

    fn destroy_vm(
        &self,
        instance_name: &str,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>>;

    /// Return the IP for `instance_name`.
    ///
    /// `prefer_public` — when `true` the external/public IP is returned;
    /// when `false` the internal/private IP is preferred (falling back to
    /// public only if no private address exists).
    fn get_vm_ip(
        &self,
        instance_name: &str,
        prefer_public: bool,
    ) -> Result<String, Box<dyn std::error::Error>>;
}

// ---------------------------------------------------------------------------
// Config loading + provider detection
// ---------------------------------------------------------------------------

pub fn load_provider(path: &str) -> Result<LoadedProvider, Box<dyn std::error::Error>> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("Cannot read config file '{path}': {e}"))?;

    let raw: serde_yaml::Value =
        serde_yaml::from_str(&content).map_err(|e| format!("YAML parse error in '{path}': {e}"))?;

    if raw.get("gcp").is_some() {
        let root: GcpRoot = serde_yaml::from_str(&content)
            .map_err(|e| format!("GCP YAML parse error in '{path}': {e}"))?;
        let yaml = root.gcp;

        validate_specs(&yaml.specs)?;

        let creds = GcpCredentials {
            client_email: yaml.credentials.client_email.clone(),
            private_key_path: expand_tilde(&yaml.credentials.private_key),
            project_id: yaml.credentials.project_id.clone(),
            zone: yaml.credentials.zone.clone(),
        };

        let location = creds.zone.clone();
        let provisioner = yaml.provisioner.clone();
        let provider = GcpProvider::new(&creds)?;

        Ok(LoadedProvider::Gcp {
            common: CommonConfig {
                groups: yaml.group,
                specs: yaml.specs,
                rules: yaml.rules,
                provisioner: yaml.provisioner,
            },
            location,
            provisioner,
            provider,
        })
    } else if raw.get("digitalocean").is_some() {
        let root: DoRoot = serde_yaml::from_str(&content)
            .map_err(|e| format!("DigitalOcean YAML parse error in '{path}': {e}"))?;
        let yaml = root.digitalocean;

        validate_specs(&yaml.specs)?;

        let creds = DigitalOceanCredentials {
            token: yaml.credentials.token.clone(),
            region: yaml.credentials.region.clone(),
        };

        let location = creds.region.clone();
        let provisioner = yaml.provisioner.clone();
        let provider = DigitalOceanProvider::new(&creds)?;

        Ok(LoadedProvider::DigitalOcean {
            common: CommonConfig {
                groups: yaml.group,
                specs: yaml.specs,
                rules: yaml.rules,
                provisioner: yaml.provisioner,
            },
            location,
            provisioner,
            provider,
        })
    } else {
        Err(format!(
            "Cannot detect provider in '{path}': \
             YAML must have a top-level 'gcp' or 'digitalocean' key"
        )
        .into())
    }
}
