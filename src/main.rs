mod provider;
mod utils;

use std::collections::HashMap;
use std::fs;

use clap::{Parser, Subcommand};

use provider::{
    Provider,
    digitalocean::{DigitalOceanCredentials, DigitalOceanProvider},
    gcp::{GcpCredentials, GcpProvider, print_build_credential},
};
use utils::{expand_tilde, prompt_yes_no, read_ssh_public_key};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Maglev — multi-cloud Kubernetes cluster manager
#[derive(Parser)]
#[command(
    name = "maglev",
    version,
    about = "Provision and manage cloud-backed Kubernetes clusters"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create VM instances described by a provider YAML config
    Apply {
        /// Path to the YAML config file (gcp.yaml or digitalocean.yaml)
        #[arg(default_value = "config/gcp.yaml")]
        config: String,
    },
    /// Permanently delete VM instances described by a provider YAML config
    Destroy {
        /// Path to the YAML config file
        #[arg(default_value = "config/gcp.yaml")]
        config: String,
    },
    /// Provision Kubernetes on control-plane nodes and join workers
    Play {
        /// Path to the YAML config file
        #[arg(default_value = "config/gcp.yaml")]
        config: String,
    },
    /// Run the interactive GCP credential builder
    Print,
}

// ---------------------------------------------------------------------------
// ip-address field type
// ---------------------------------------------------------------------------

/// Validated value for `ip-address` in a spec config block.
///
/// Accepted YAML values: `"public"` or `"private"`.
/// Omitting the field is equivalent to `"private"`.
#[derive(Debug, Clone, Copy, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
enum IpAddressType {
    Public,
    Private,
}

impl Default for IpAddressType {
    fn default() -> Self {
        IpAddressType::Private
    }
}

impl std::fmt::Display for IpAddressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpAddressType::Public => write!(f, "public"),
            IpAddressType::Private => write!(f, "private"),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared YAML types
// ---------------------------------------------------------------------------

/// A named group of node names.
///
/// `group_type` must be `"control-plane"` or `"worker"` and determines how
/// `play` treats the nodes in this group.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GroupYaml {
    name: String,
    /// Role of every node in this group.  Accepted values: `"control-plane"`,
    /// `"worker"`.
    #[serde(rename = "type")]
    group_type: String,
    node: Vec<String>,
}

/// A unified spec entry.  All fields are optional so that multiple spec
/// entries can be **merged** by a rule: a base spec (e.g. `cisak`) provides
/// the common fields (user, script, SSH key, machine type, image) while a
/// role-specific spec (e.g. `control-plane-public`) contributes only the
/// fields that differ (disk size, ip-address).
///
/// After merging, every required field must be present or `resolve_rules`
/// returns an error.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct SpecConfigYaml {
    // ── generics-origin fields ──────────────────────────────────────────────
    #[serde(
        rename = "ssh-public-key",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    ssh_public_key: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    script: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<String>,

    /// Optional stable address for the Kubernetes API server load-balancer.
    /// Format: `<host>` or `<host>:<port>` (port defaults to 6443).
    #[serde(
        rename = "control-plane-endpoint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    control_plane_endpoint: Option<String>,

    // ── specs-origin fields ─────────────────────────────────────────────────
    #[serde(
        rename = "machine-type",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    machine_type: Option<String>,

    #[serde(
        rename = "boot-disk-image",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    boot_disk_image: Option<String>,

    #[serde(
        rename = "boot-disk-size",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    boot_disk_size: Option<u64>,

    /// When absent, defaults to `private` after merging.
    #[serde(
        rename = "ip-address",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    ip_address: Option<IpAddressType>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct SpecYaml {
    name: String,
    config: Vec<SpecConfigYaml>,
}

/// A rule maps one or more group names to an ordered list of spec names.
///
/// The specs are merged left-to-right: later entries win for any field both
/// define.  The merged result must satisfy every required field.
///
/// `group` accepts either a YAML scalar (`group: my-group`) or a YAML
/// sequence (`group: [a, b]`) for maximum authoring convenience.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RuleYaml {
    #[serde(deserialize_with = "string_or_vec")]
    group: Vec<String>,
    specs: Vec<String>,
}

// ---------------------------------------------------------------------------
// Custom YAML deserializer: scalar string  OR  sequence of strings
// ---------------------------------------------------------------------------

fn string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a string or a sequence of strings")
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Vec<String>, E> {
            Ok(vec![v.to_string()])
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Vec<String>, A::Error> {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_any(Visitor)
}

// ---------------------------------------------------------------------------
// Provider-specific credential types
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GcpCredentialsYaml {
    #[serde(rename = "client-email")]
    client_email: String,
    #[serde(rename = "private-key")]
    private_key: String,
    #[serde(rename = "project-id")]
    project_id: String,
    zone: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct DoCredentialsYaml {
    token: String,
    region: String,
}

// ---------------------------------------------------------------------------
// Per-provider YAML roots
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GcpRoot {
    gcp: GcpYaml,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GcpYaml {
    group: Vec<GroupYaml>,
    specs: Vec<SpecYaml>,
    rules: Vec<RuleYaml>,
    credentials: GcpCredentialsYaml,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct DoRoot {
    digitalocean: DoYaml,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct DoYaml {
    group: Vec<GroupYaml>,
    specs: Vec<SpecYaml>,
    rules: Vec<RuleYaml>,
    credentials: DoCredentialsYaml,
}

// ---------------------------------------------------------------------------
// Unified view of a loaded config (provider-agnostic body + typed creds)
// ---------------------------------------------------------------------------

struct CommonConfig {
    groups: Vec<GroupYaml>,
    specs: Vec<SpecYaml>,
    rules: Vec<RuleYaml>,
}

enum LoadedProvider {
    Gcp {
        common: CommonConfig,
        location: String,
        identity: String,
        provider: GcpProvider,
    },
    DigitalOcean {
        common: CommonConfig,
        location: String,
        provider: DigitalOceanProvider,
    },
}

impl LoadedProvider {
    fn common(&self) -> &CommonConfig {
        match self {
            LoadedProvider::Gcp { common, .. } => common,
            LoadedProvider::DigitalOcean { common, .. } => common,
        }
    }

    fn provider(&self) -> &dyn Provider {
        match self {
            LoadedProvider::Gcp { provider, .. } => provider,
            LoadedProvider::DigitalOcean { provider, .. } => provider,
        }
    }

    fn describe(&self) {
        match self {
            LoadedProvider::Gcp {
                location, identity, ..
            } => {
                println!("  Provider:        GCP");
                println!("  Zone:            {location}");
                println!("  Service account: {identity}");
            }
            LoadedProvider::DigitalOcean { location, .. } => {
                println!("  Provider:        DigitalOcean");
                println!("  Region:          {location}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Config loading + provider detection
// ---------------------------------------------------------------------------

fn load_provider(path: &str) -> Result<LoadedProvider, Box<dyn std::error::Error>> {
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
        let identity = creds.client_email.clone();
        let provider = GcpProvider::new(&creds)?;

        Ok(LoadedProvider::Gcp {
            common: CommonConfig {
                groups: yaml.group,
                specs: yaml.specs,
                rules: yaml.rules,
            },
            location,
            identity,
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
        let provider = DigitalOceanProvider::new(&creds)?;

        Ok(LoadedProvider::DigitalOcean {
            common: CommonConfig {
                groups: yaml.group,
                specs: yaml.specs,
                rules: yaml.rules,
            },
            location,
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

// ---------------------------------------------------------------------------
// Spec validation (pre-merge, informational only)
// ---------------------------------------------------------------------------

fn validate_specs(specs: &[SpecYaml]) -> Result<(), Box<dyn std::error::Error>> {
    for spec in specs {
        for (i, cfg) in spec.config.iter().enumerate() {
            let ip_str = cfg
                .ip_address
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "private (default)".to_string());
            println!("  spec '{}' [{}]: ip-address = {}", spec.name, i, ip_str);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Spec merging
// ---------------------------------------------------------------------------

/// The fully resolved, non-optional view of a node's configuration produced
/// by merging one or more [`SpecConfigYaml`] entries left-to-right.
///
/// Every field is required; `merge_spec_configs` returns an error when any
/// mandatory field is absent after the merge pass.
#[derive(Debug, Clone)]
struct MergedSpec {
    machine_type: String,
    boot_disk_image: String,
    boot_disk_size: u64,
    /// Defaults to [`IpAddressType::Private`] when no spec sets it.
    ip_address: IpAddressType,
    ssh_public_key: String,
    script: String,
    user: String,
    control_plane_endpoint: Option<String>,
}

/// Merge `spec_names` (in order) from `specs_map` into a single
/// [`MergedSpec`].  Later entries override earlier ones for any field both
/// define.
fn merge_spec_configs(
    spec_names: &[String],
    specs_map: &HashMap<&str, &SpecConfigYaml>,
) -> Result<MergedSpec, Box<dyn std::error::Error>> {
    let mut machine_type: Option<String> = None;
    let mut boot_disk_image: Option<String> = None;
    let mut boot_disk_size: Option<u64> = None;
    let mut ip_address: Option<IpAddressType> = None;
    let mut ssh_public_key: Option<String> = None;
    let mut script: Option<String> = None;
    let mut user: Option<String> = None;
    let mut control_plane_endpoint: Option<String> = None;

    for name in spec_names {
        let cfg = specs_map
            .get(name.as_str())
            .ok_or_else(|| format!("Rule references unknown spec '{name}'"))?;

        if let Some(v) = &cfg.machine_type {
            machine_type = Some(v.clone());
        }
        if let Some(v) = &cfg.boot_disk_image {
            boot_disk_image = Some(v.clone());
        }
        if let Some(v) = cfg.boot_disk_size {
            boot_disk_size = Some(v);
        }
        if let Some(v) = cfg.ip_address {
            ip_address = Some(v);
        }
        if let Some(v) = &cfg.ssh_public_key {
            ssh_public_key = Some(v.clone());
        }
        if let Some(v) = &cfg.script {
            script = Some(v.clone());
        }
        if let Some(v) = &cfg.user {
            user = Some(v.clone());
        }
        if let Some(v) = &cfg.control_plane_endpoint {
            control_plane_endpoint = Some(v.clone());
        }
    }

    Ok(MergedSpec {
        machine_type: machine_type
            .ok_or_else(|| format!("No 'machine-type' found after merging specs {spec_names:?}"))?,
        boot_disk_image: boot_disk_image.ok_or_else(|| {
            format!("No 'boot-disk-image' found after merging specs {spec_names:?}")
        })?,
        boot_disk_size: boot_disk_size.ok_or_else(|| {
            format!("No 'boot-disk-size' found after merging specs {spec_names:?}")
        })?,
        ip_address: ip_address.unwrap_or_default(),
        ssh_public_key: ssh_public_key.ok_or_else(|| {
            format!("No 'ssh-public-key' found after merging specs {spec_names:?}")
        })?,
        script: script
            .ok_or_else(|| format!("No 'script' found after merging specs {spec_names:?}"))?,
        user: user.ok_or_else(|| format!("No 'user' found after merging specs {spec_names:?}"))?,
        control_plane_endpoint,
    })
}

// ---------------------------------------------------------------------------
// Rule resolution (provider-agnostic)
// ---------------------------------------------------------------------------

/// The fully resolved view of a single rule: group metadata, the ordered list
/// of spec names, all node names collected from the referenced groups, and the
/// merged spec ready for use.
struct ResolvedRule {
    /// Names of every group referenced by this rule.
    group_names: Vec<String>,
    /// The shared `type` of all groups in this rule (`"control-plane"` /
    /// `"worker"`).
    group_type: String,
    /// Names of every spec referenced by this rule (merge order).
    spec_names: Vec<String>,
    /// Every node name collected from all referenced groups.
    nodes: Vec<String>,
    /// Result of merging all referenced specs left-to-right.
    merged: MergedSpec,
}

fn resolve_rules(common: &CommonConfig) -> Result<Vec<ResolvedRule>, Box<dyn std::error::Error>> {
    // Index groups by name → (type, nodes)
    let groups: HashMap<&str, (&str, &[String])> = common
        .groups
        .iter()
        .map(|g| (g.name.as_str(), (g.group_type.as_str(), g.node.as_slice())))
        .collect();

    // Index specs by name → first config entry
    let specs_map: HashMap<&str, &SpecConfigYaml> = common
        .specs
        .iter()
        .filter_map(|s| s.config.first().map(|c| (s.name.as_str(), c)))
        .collect();

    common
        .rules
        .iter()
        .map(|rule| {
            // Collect nodes and validate that all groups share the same type
            let mut nodes: Vec<String> = Vec::new();
            let mut resolved_type: Option<&str> = None;

            for gname in &rule.group {
                let (gtype, gnodes) = groups
                    .get(gname.as_str())
                    .ok_or_else(|| format!("Rule references unknown group '{gname}'"))?;

                if let Some(existing) = resolved_type {
                    if existing != *gtype {
                        return Err(format!(
                            "Rule mixes groups of different types: \
                             '{existing}' (previous) vs '{gtype}' ('{gname}')"
                        )
                        .into());
                    }
                } else {
                    resolved_type = Some(gtype);
                }

                nodes.extend(gnodes.iter().cloned());
            }

            let group_type = resolved_type
                .ok_or_else(|| "Rule has an empty group list".to_string())?
                .to_string();

            // Merge specs
            let merged = merge_spec_configs(&rule.specs, &specs_map)?;

            Ok(ResolvedRule {
                group_names: rule.group.clone(),
                group_type,
                spec_names: rule.specs.clone(),
                nodes,
                merged,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// `apply` subcommand
// ---------------------------------------------------------------------------

fn apply_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Apply ===\n");
    println!("Reading config: {config_path}");

    let loaded = load_provider(config_path)?;
    let common = loaded.common();

    println!("\n── Provider settings ────────────────────────────────────────────────────");
    loaded.describe();

    let resolved = resolve_rules(common)?;

    println!("\n── Nodes to create ──────────────────────────────────────────────────────");
    let mut total = 0usize;
    for r in &resolved {
        println!(
            "\n  groups: [{}]  type: {}  (specs: [{}])",
            r.group_names.join(", "),
            r.group_type,
            r.spec_names.join(", "),
        );
        println!(
            "    machine-type: {}  image: {}  disk: {} GB  ip-address: {}",
            r.merged.machine_type,
            r.merged.boot_disk_image,
            r.merged.boot_disk_size,
            r.merged.ip_address,
        );
        println!(
            "    user: {}  ssh-public-key: {}",
            r.merged.user, r.merged.ssh_public_key
        );
        for node in &r.nodes {
            println!("      • {node}");
            total += 1;
        }
    }

    if !prompt_yes_no(&format!("\nProceed with creating {total} VM instance(s)?")) {
        println!("Aborted.");
        return Ok(());
    }

    let provider = loaded.provider();

    for r in &resolved {
        println!(
            "\n── Groups: [{}] ({}) ─────────────────────────────────────────────────────",
            r.group_names.join(", "),
            r.group_type,
        );

        let ssh_meta = read_ssh_public_key(&r.merged.ssh_public_key)
            .map(|k| format!("{}:{k}", r.merged.user))
            .unwrap_or_else(|e| {
                eprintln!("  ⚠ Could not read SSH public key: {e}");
                String::new()
            });

        let assign_public_ip = r.merged.ip_address == IpAddressType::Public;

        for node in &r.nodes {
            println!("\n  ── Creating instance: {node} ──");
            let resp = provider.create_vm(
                node,
                &r.merged.machine_type,
                &r.merged.boot_disk_image,
                r.merged.boot_disk_size,
                &ssh_meta,
                &r.merged.script,
                assign_public_ip,
            )?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }

    println!("\n✓ All {total} VM creation request(s) submitted successfully.");
    Ok(())
}

// ---------------------------------------------------------------------------
// `destroy` subcommand
// ---------------------------------------------------------------------------

fn destroy_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Destroy ===\n");
    println!("Reading config: {config_path}");

    let loaded = load_provider(config_path)?;
    let common = loaded.common();

    println!("\n── Provider settings ────────────────────────────────────────────────────");
    loaded.describe();

    println!("\n── Instances to destroy ─────────────────────────────────────────────────");

    let mut all_nodes: Vec<(&str, &str, &str)> = Vec::new(); // (group_name, group_type, node)
    for group in &common.groups {
        for node in &group.node {
            println!("  [{}] {}  →  {}", group.group_type, group.name, node);
            all_nodes.push((&group.name, &group.group_type, node));
        }
    }

    let total = all_nodes.len();
    println!();
    println!("⚠  This action is IRREVERSIBLE. All {total} VM instance(s) and their boot");
    println!("   disks will be permanently deleted.");

    if !prompt_yes_no("\nProceed with destroying all VM instances?") {
        println!("Aborted — nothing was deleted.");
        return Ok(());
    }

    let provider = loaded.provider();

    for (group_name, group_type, node) in &all_nodes {
        println!("\n  ── Deleting [{group_type}/{group_name}] {node} ──");
        match provider.destroy_vm(node) {
            Ok(body) => println!("{}", serde_json::to_string_pretty(&body)?),
            Err(e) => eprintln!("  ✗ Failed to delete {node}: {e}"),
        }
    }

    println!("\n✓ Deletion requests submitted. Operations may take a minute to complete.");
    Ok(())
}

// ---------------------------------------------------------------------------
// SSH helpers — direct
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
        .map_err(|e| format!("Failed to spawn ssh: {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "ssh exited {} — stderr: {stderr}",
            out.status.code().unwrap_or(-1)
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
        .map_err(|e| format!("Failed to spawn ssh: {e}"))?;

    if !status.success() {
        return Err(format!("Remote command exited {}", status.code().unwrap_or(-1)).into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SSH helpers — via ProxyJump (jump_host → target)
// ---------------------------------------------------------------------------

fn ssh_capture_jump(
    jump_ip: &str,
    jump_user: &str,
    target_ip: &str,
    target_user: &str,
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
            "-o",
            &format!("ProxyJump={jump_user}@{jump_ip}"),
            &format!("{target_user}@{target_ip}"),
            command,
        ])
        .output()
        .map_err(|e| format!("Failed to spawn ssh (jump): {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "ssh (jump) exited {} — stderr: {stderr}",
            out.status.code().unwrap_or(-1)
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn ssh_run_jump(
    jump_ip: &str,
    jump_user: &str,
    target_ip: &str,
    target_user: &str,
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
            "-o",
            &format!("ProxyJump={jump_user}@{jump_ip}"),
            &format!("{target_user}@{target_ip}"),
            command,
        ])
        .status()
        .map_err(|e| format!("Failed to spawn ssh (jump): {e}"))?;

    if !status.success() {
        return Err(format!(
            "Remote command (jump) exited {}",
            status.code().unwrap_or(-1)
        )
        .into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Control-plane provisioning steps
// ---------------------------------------------------------------------------

const ADMIN_KUBECONFIG: &str = "/etc/kubernetes/admin.conf";

fn provision_control_plane_node(
    cp_ip: &str,
    cp_name: &str,
    ssh_user: &str,
    ssh_priv_path: &str,
    cp_endpoint: &str,
    is_ha: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // ── Step A: kubeadm init ──────────────────────────────────────────────────
    let kubeadm_init_cmd = if is_ha {
        format!(
            "sudo kubeadm init \
             --control-plane-endpoint {cp_endpoint} \
             --upload-certs"
        )
    } else {
        "sudo kubeadm init".to_string()
    };

    println!("\n  → Step A: initialise the cluster with kubeadm");
    println!("    $ {kubeadm_init_cmd}");

    if !prompt_yes_no("  Run kubeadm init?") {
        println!("  Skipped — aborting control-plane provisioning for {cp_name}.");
        return Ok(());
    }

    println!("\n  Running kubeadm init — this may take several minutes …\n");
    ssh_run(cp_ip, ssh_user, ssh_priv_path, &kubeadm_init_cmd)?;
    println!("\n  ✓ kubeadm init complete.");

    // ── Step B: cilium install ────────────────────────────────────────────────
    let cilium_install_cmd = format!("cilium --kubeconfig {ADMIN_KUBECONFIG} install");

    println!("\n  → Step B: deploy Cilium CNI");
    println!("    $ {cilium_install_cmd}");

    if !prompt_yes_no("  Run cilium install?") {
        println!("  Skipped — Cilium CNI will not be deployed.");
        return Ok(());
    }

    ssh_run(cp_ip, ssh_user, ssh_priv_path, &cilium_install_cmd)?;
    println!("\n  ✓ Cilium CNI installed.");

    // ── Step C: cilium status --wait ──────────────────────────────────────────
    let cilium_status_cmd = format!("cilium --kubeconfig {ADMIN_KUBECONFIG} status --wait");

    println!("\n  → Step C: wait for Cilium to become ready");
    println!("    $ {cilium_status_cmd}");

    if !prompt_yes_no("  Run cilium status --wait?") {
        println!("  Skipped — continuing without confirming Cilium health.");
        return Ok(());
    }

    ssh_run(cp_ip, ssh_user, ssh_priv_path, &cilium_status_cmd)?;
    println!("\n  ✓ Cilium is ready.");

    println!("\n  ✓ {cp_name} control-plane provisioning complete.");
    Ok(())
}

// ---------------------------------------------------------------------------
// `play` subcommand
// ---------------------------------------------------------------------------

fn play_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Maglev Play ===\n");
    println!("Reading config: {config_path}");

    let loaded = load_provider(config_path)?;
    let common = loaded.common();
    let provider = loaded.provider();

    println!("\n── Provider settings ────────────────────────────────────────────────────");
    loaded.describe();

    let resolved = resolve_rules(common)?;

    // ── Partition resolved rules into CP and worker node lists ────────────────
    //
    // Each entry carries:  (node_name, prefer_public)
    // The SSH config (user, key, control-plane-endpoint) is taken from the
    // first control-plane rule's merged spec — all rules in the example share
    // the same `cisak` base spec so these values are identical across the
    // cluster.
    let mut cp_entries: Vec<(String, bool)> = Vec::new();
    let mut worker_entries: Vec<(String, bool)> = Vec::new();
    let mut first_cp_merged: Option<&MergedSpec> = None;

    for rule in &resolved {
        let prefer_public = rule.merged.ip_address == IpAddressType::Public;
        match rule.group_type.as_str() {
            "control-plane" => {
                if first_cp_merged.is_none() {
                    first_cp_merged = Some(&rule.merged);
                }
                for node in &rule.nodes {
                    cp_entries.push((node.clone(), prefer_public));
                }
            }
            "worker" => {
                for node in &rule.nodes {
                    worker_entries.push((node.clone(), prefer_public));
                }
            }
            other => {
                eprintln!("  ⚠ Unknown group type '{other}' — skipping in play.");
            }
        }
    }

    let first_cp_merged = first_cp_merged.ok_or("No control-plane rules found in config")?;

    let ssh_user = &first_cp_merged.user;
    let ssh_pub_path = first_cp_merged.ssh_public_key.as_str();
    let ssh_priv_path = expand_tilde(ssh_pub_path.strip_suffix(".pub").unwrap_or(ssh_pub_path));

    // ── Cluster-size checks ───────────────────────────────────────────────────
    let cp_count = cp_entries.len();
    if cp_count == 0 {
        return Err("No control-plane nodes found in config.".into());
    }
    if cp_count == 1 {
        println!(
            "\n  ℹ  INFO: Single control-plane node — this cluster will \
             not be highly available."
        );
    } else if cp_count % 2 == 0 {
        eprintln!(
            "\n  ⚠  WARNING: Even number of control-plane nodes ({cp_count}) detected. \
             An odd count (e.g. 3 or 5) is strongly recommended for proper \
             etcd quorum. Proceed with caution."
        );
    }

    let is_ha = cp_count >= 3;

    // Primary CP node is the first one in document order.
    let primary_cp_prefer_public = cp_entries[0].1;

    // A worker whose own IP is private and whose reachability depends on
    // tunnelling through the (public) primary CP node needs ProxyJump.
    let any_worker_needs_jump =
        worker_entries.iter().any(|(_, pp)| !pp) && primary_cp_prefer_public;

    if any_worker_needs_jump {
        println!(
            "\n  ℹ  Some workers have private IPs and the primary control-plane has a \
             public IP. Private-worker SSH will be routed through the primary \
             control-plane node via ProxyJump."
        );
    }

    // ── Resolve IPs ───────────────────────────────────────────────────────────
    println!("\n  Fetching IPs …");

    let cp_with_ips: Vec<(String, String)> = cp_entries
        .iter()
        .map(|(name, prefer_public)| {
            let ip = provider.get_vm_ip(name, *prefer_public)?;
            println!(
                "  {name:<30} →  {ip}  ({})",
                if *prefer_public { "public" } else { "private" }
            );
            Ok((name.clone(), ip))
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()?;

    let worker_with_ips: Vec<(String, String)> = worker_entries
        .iter()
        .map(|(name, prefer_public)| {
            let ip = provider.get_vm_ip(name, *prefer_public)?;
            println!(
                "  {name:<30} →  {ip}  ({})",
                if *prefer_public { "public" } else { "private" }
            );
            Ok((name.clone(), ip))
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()?;

    println!("  SSH user: {ssh_user}  private key: {ssh_priv_path}");

    let (primary_cp_name, primary_cp_ip) = cp_with_ips
        .first()
        .ok_or("No control-plane nodes available")?;

    // ── Determine the stable control-plane endpoint ───────────────────────────
    let cp_endpoint: String = match &first_cp_merged.control_plane_endpoint {
        Some(ep) if !ep.trim().is_empty() => {
            let ep = ep.trim().to_string();
            if ep.contains(':') {
                ep
            } else {
                format!("{ep}:6443")
            }
        }
        _ => format!("{primary_cp_ip}:6443"),
    };

    println!("\n  control-plane-endpoint: {cp_endpoint}");

    if is_ha && cp_endpoint.starts_with(primary_cp_ip.as_str()) {
        eprintln!(
            "\n  ⚠  WARNING: control-plane-endpoint is set to the primary node's own \
             IP ({cp_endpoint}).\n\
             This works but is not truly highly available — if that node is lost \
             the API server becomes unreachable.\n\
             Consider adding a load-balancer and setting 'control-plane-endpoint' \
             in the relevant spec block of your config."
        );
    }

    // ── Step 1 / 3 — Primary control-plane ───────────────────────────────────
    println!("\n━━ Step 1 / 3 — Primary control-plane init ({primary_cp_name}) ━━━━━━━━━━━━");
    println!("\n  [{primary_cp_name}]  ({primary_cp_ip})");

    if prompt_yes_no(&format!("  SSH-check and provision {primary_cp_name}?")) {
        ensure_cp_endpoint_resolves(
            primary_cp_name,
            &cp_endpoint,
            primary_cp_ip,
            |cmd| ssh_capture(primary_cp_ip, ssh_user, &ssh_priv_path, cmd),
            |cmd| ssh_run(primary_cp_ip, ssh_user, &ssh_priv_path, cmd),
        )?;

        let already_init = ssh_capture(
            primary_cp_ip,
            ssh_user,
            &ssh_priv_path,
            "test -f /etc/kubernetes/admin.conf && echo yes || echo no",
        )?;

        if already_init.trim() == "yes" {
            println!("  ✓ {primary_cp_name} already initialised — skipping.");
            if is_ha {
                verify_control_plane_endpoint(
                    primary_cp_ip,
                    primary_cp_name,
                    ssh_user,
                    &ssh_priv_path,
                    &cp_endpoint,
                )?;
            }
        } else {
            provision_control_plane_node(
                primary_cp_ip,
                primary_cp_name,
                ssh_user,
                &ssh_priv_path,
                &cp_endpoint,
                is_ha,
            )?;
        }
    } else {
        println!("  Skipped.");
    }

    // ── Step 2 / 3 — Additional control-plane nodes (HA join) ────────────────
    if is_ha && cp_with_ips.len() > 1 {
        println!(
            "\n━━ Step 2 / 3 — Additional control-plane nodes ({} nodes) ━━━━━━━━━━━━━━",
            cp_with_ips.len() - 1
        );

        let cp_join_script = "\
            CERT_KEY=$(sudo kubeadm certs certificate-key) && \
            sudo kubeadm init phase upload-certs \
                --upload-certs --certificate-key \"$CERT_KEY\" \
                >/dev/null 2>&1 && \
            BASE=$(sudo kubeadm token create --print-join-command) && \
            echo \"$BASE --control-plane --certificate-key $CERT_KEY\"";

        let cp_join_cmd = match ssh_capture(primary_cp_ip, ssh_user, &ssh_priv_path, cp_join_script)
        {
            Ok(cmd) if !cmd.is_empty() => cmd,
            Ok(_) => {
                eprintln!(
                    "  ✗ Empty control-plane join command from {primary_cp_name} \
                     — is it fully up?"
                );
                String::new()
            }
            Err(e) => {
                eprintln!("  ✗ Could not fetch control-plane join command: {e}");
                String::new()
            }
        };

        // cp_entries[1..] parallel-tracks cp_with_ips[1..]
        for (idx, ((name, ip), (_, prefer_public))) in cp_with_ips
            .iter()
            .skip(1)
            .zip(cp_entries.iter().skip(1))
            .enumerate()
        {
            println!("\n  [{}/{}] {name}  ({ip})", idx + 2, cp_with_ips.len());

            if !prompt_yes_no(&format!("  Check and join {name} as control-plane?")) {
                println!("  Skipped.");
                continue;
            }

            // Additional CP nodes that have private IPs are assumed to be
            // reachable directly (VPN / internal routing).  If they are not,
            // the operator will see an SSH timeout here.
            let _ = prefer_public; // used only to choose ip — already reflected in `ip`
            ensure_cp_endpoint_resolves(
                name,
                &cp_endpoint,
                primary_cp_ip,
                |cmd| ssh_capture(ip, ssh_user, &ssh_priv_path, cmd),
                |cmd| ssh_run(ip, ssh_user, &ssh_priv_path, cmd),
            )?;

            let already_joined = ssh_capture(
                ip,
                ssh_user,
                &ssh_priv_path,
                "test -f /etc/kubernetes/admin.conf && echo yes || echo no",
            )?;

            if already_joined.trim() == "yes" {
                println!("  ✓ {name} already part of the control-plane — skipping.");
                continue;
            }

            if cp_join_cmd.is_empty() {
                eprintln!("  ✗ No join command available — skipping {name}.");
                continue;
            }

            println!("  Join command: {cp_join_cmd}");
            if prompt_yes_no("  Run join command?") {
                println!("\n  Joining {name} as control-plane node …\n");
                ssh_run(ip, ssh_user, &ssh_priv_path, &format!("sudo {cp_join_cmd}"))?;
                println!("\n  ✓ {name} joined as control-plane.");
            } else {
                println!("  Skipped.");
            }
        }
    } else if !is_ha {
        println!("\n━━ Step 2 / 3 — Additional control-plane nodes ━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  Single-node cluster — no additional control-plane nodes to join.");
    }

    // ── Step 3 / 3 — Join workers ─────────────────────────────────────────────
    println!(
        "\n━━ Step 3 / 3 — Join workers ({} nodes) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        worker_with_ips.len()
    );

    let worker_join_cmd = match ssh_capture(
        primary_cp_ip,
        ssh_user,
        &ssh_priv_path,
        "sudo kubeadm token create --print-join-command",
    ) {
        Ok(cmd) if !cmd.is_empty() => cmd,
        Ok(_) => {
            eprintln!("  ✗ Empty worker join command from {primary_cp_name} — is it fully up?");
            String::new()
        }
        Err(e) => {
            eprintln!("  ✗ Could not fetch worker join command: {e}");
            String::new()
        }
    };

    // worker_entries[i] and worker_with_ips[i] are aligned
    for (idx, ((name, ip), (_, prefer_public))) in worker_with_ips
        .iter()
        .zip(worker_entries.iter())
        .enumerate()
    {
        let needs_jump = !prefer_public && primary_cp_prefer_public;

        println!("\n  [{}/{}] {name}  ({ip})", idx + 1, worker_with_ips.len());

        if needs_jump {
            println!("    (routing through {primary_cp_name} @ {primary_cp_ip} via ProxyJump)");
        }

        if !prompt_yes_no("  Fetch join command and join?") {
            println!("  Skipped.");
            continue;
        }

        // DNS guard — use the appropriate SSH path per worker topology
        if needs_jump {
            ensure_cp_endpoint_resolves(
                name,
                &cp_endpoint,
                primary_cp_ip,
                |cmd| ssh_capture_jump(primary_cp_ip, ssh_user, ip, ssh_user, &ssh_priv_path, cmd),
                |cmd| ssh_run_jump(primary_cp_ip, ssh_user, ip, ssh_user, &ssh_priv_path, cmd),
            )?;
        } else {
            ensure_cp_endpoint_resolves(
                name,
                &cp_endpoint,
                primary_cp_ip,
                |cmd| ssh_capture(ip, ssh_user, &ssh_priv_path, cmd),
                |cmd| ssh_run(ip, ssh_user, &ssh_priv_path, cmd),
            )?;
        }

        if worker_join_cmd.is_empty() {
            eprintln!("  ✗ No join command available — skipping {name}.");
            continue;
        }

        println!("  Join command: {worker_join_cmd}");

        let already_joined = if needs_jump {
            ssh_capture_jump(
                primary_cp_ip,
                ssh_user,
                ip,
                ssh_user,
                &ssh_priv_path,
                "systemctl is-active kubelet 2>/dev/null && echo yes || echo no",
            )
        } else {
            ssh_capture(
                ip,
                ssh_user,
                &ssh_priv_path,
                "systemctl is-active kubelet 2>/dev/null && echo yes || echo no",
            )
        };

        match already_joined {
            Ok(ref s) if s.trim() == "yes" => {
                println!("  ✓ {name} already has kubelet active — skipping.");
                continue;
            }
            _ => {}
        }

        println!("\n  Joining {name} …\n");
        let join_full = format!("sudo {worker_join_cmd}");

        let result = if needs_jump {
            ssh_run_jump(
                primary_cp_ip,
                ssh_user,
                ip,
                ssh_user,
                &ssh_priv_path,
                &join_full,
            )
        } else {
            ssh_run(ip, ssh_user, &ssh_priv_path, &join_full)
        };

        match result {
            Ok(()) => println!("\n  ✓ {name} joined."),
            Err(e) => eprintln!("  ✗ Failed to join {name}: {e}"),
        }
    }

    println!("\n✓ Cluster provisioning complete!");
    println!("\n  Verify from the primary control-plane:");
    println!("    ssh -i {ssh_priv_path} {ssh_user}@{primary_cp_ip}");
    println!("    kubectl get nodes -o wide");

    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let cli = Cli::parse();

    match cli.command {
        Commands::Apply { config } => apply_config(&config),
        Commands::Destroy { config } => destroy_config(&config),
        Commands::Play { config } => play_config(&config),
        Commands::Print => print_build_credential(),
    }
}

// ---------------------------------------------------------------------------
// Control-plane endpoint guard
// ---------------------------------------------------------------------------

fn verify_control_plane_endpoint(
    cp_ip: &str,
    cp_name: &str,
    ssh_user: &str,
    ssh_priv_path: &str,
    expected_endpoint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("  Verifying controlPlaneEndpoint in kubeadm-config …");

    let script = "sudo kubectl --kubeconfig=/etc/kubernetes/admin.conf \
        get configmap kubeadm-config -n kube-system \
        -o jsonpath='{.data.ClusterConfiguration}' 2>/dev/null \
        | grep 'controlPlaneEndpoint' || true";

    let output = ssh_capture(cp_ip, ssh_user, ssh_priv_path, script).unwrap_or_default();

    let stored_endpoint = output
        .split(':')
        .nth(1)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    if stored_endpoint.is_empty() {
        return Err(format!(
            "Cluster on {cp_name} has no controlPlaneEndpoint stored in kubeadm-config.\n\
             \n\
             This happens when the node was initialised without --control-plane-endpoint.\n\
             \n\
             Remediation — on every control-plane and worker node run:\n\
             \n\
             \tsudo kubeadm reset -f\n\
             \tsudo rm -rf /etc/cni /etc/kubernetes /var/lib/etcd /var/lib/kubelet\n\
             \n\
             Then re-run 'maglev play'.  Maglev will call:\n\
             \n\
             \tsudo kubeadm init \
             --control-plane-endpoint {expected_endpoint} --upload-certs\n\
             \n\
             To use a dedicated load-balancer address instead of the primary \
             node's IP, add 'control-plane-endpoint' to the relevant spec block \
             in your config."
        )
        .into());
    }

    println!("  ✓ controlPlaneEndpoint: {stored_endpoint}");

    let stored_normalised = if stored_endpoint.contains(':') {
        stored_endpoint.clone()
    } else {
        format!("{stored_endpoint}:6443")
    };

    if stored_normalised != expected_endpoint {
        eprintln!(
            "  ⚠  controlPlaneEndpoint in kubeadm-config ({stored_normalised}) \
             differs from the value in your config ({expected_endpoint}).\n\
             The join command will target the stored endpoint — this is \
             correct behaviour. Update your config if needed."
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Control-plane-endpoint DNS guard
// ---------------------------------------------------------------------------

/// Verify that the hostname inside `cp_endpoint` resolves on a remote node.
///
/// * Skipped when `cp_endpoint` is already a bare IP address.
/// * When the hostname is **unresolvable** the user is offered two choices:
///   - Let maglev append a temporary `/etc/hosts` line right now.
///   - Abort, with exact copy-paste instructions for a manual fix.
///
/// `capture` / `run` are thin closures over either the direct or the
/// ProxyJump SSH helpers so the same logic works for every node type.
fn ensure_cp_endpoint_resolves(
    node_name: &str,
    cp_endpoint: &str,
    fallback_ip: &str,
    capture: impl Fn(&str) -> Result<String, Box<dyn std::error::Error>>,
    run: impl Fn(&str) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let host = cp_endpoint.split(':').next().unwrap_or(cp_endpoint);

    // Nothing to do when the endpoint is already an IP address.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }

    println!("  Checking if '{host}' resolves on {node_name} …");

    let result = capture(&format!(
        "getent hosts {host} >/dev/null 2>&1 && echo ok || echo fail"
    ))?;

    if result.trim() == "ok" {
        println!("  ✓ '{host}' resolves.");
        return Ok(());
    }

    eprintln!(
        "\n  ⚠  '{host}' does NOT resolve on {node_name}.\n\
         \n\
         kubeadm will fail unless the name is resolvable before it starts.\n\
         \n\
         Long-term fix: provision a load-balancer, point DNS '{host}' at it,\n\
         then remove the /etc/hosts workaround from every node.\n\
         \n\
         Short-term: maglev can add  {fallback_ip}  {host}\n\
         to /etc/hosts on this node right now (idempotent — skipped if already present)."
    );

    if prompt_yes_no(&format!(
        "  Add '{fallback_ip}  {host}' to /etc/hosts on {node_name}?"
    )) {
        run(&format!(
            "grep -qF '{host}' /etc/hosts \
             || echo '{fallback_ip}  {host}' | sudo tee -a /etc/hosts"
        ))?;
        println!(
            "  ✓ Added '{fallback_ip}  {host}' to /etc/hosts on {node_name}.\n\
             \n\
             ℹ  This is a temporary placeholder pointing at the primary control-plane IP.\n\
             ℹ  Once your load-balancer is live, run on EVERY node:\n\
             \n\
             \t  sudo sed -i '/{host}/d' /etc/hosts\n\
             \n\
             ℹ  Then ensure DNS resolves '{host}' to the LB address."
        );
    } else {
        return Err(format!(
            "DNS resolution for '{host}' is required before kubeadm can run.\n\
             \n\
             Add the following line to /etc/hosts on EVERY cluster node\n\
             (all control-plane + worker nodes) before re-running 'maglev play':\n\
             \n\
             \t{fallback_ip}  {host}\n\
             \n\
             Example (run on each node):\n\
             \n\
             \techo '{fallback_ip}  {host}' | sudo tee -a /etc/hosts\n\
             \n\
             Once a real load-balancer is provisioned, update the entry to point\n\
             to the LB address, or delete it and let DNS handle resolution:\n\
             \n\
             \tsudo sed -i '/{host}/d' /etc/hosts"
        )
        .into());
    }

    Ok(())
}
