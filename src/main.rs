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
// Shared YAML types (identical structure across providers)
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GroupYaml {
    name: String,
    node: Vec<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GenericYaml {
    name: String,
    config: Vec<GenericConfigYaml>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct GenericConfigYaml {
    #[serde(rename = "ssh-public-key")]
    ssh_public_key: String,
    script: String,
    user: String,
    /// Optional stable address for the Kubernetes API server load-balancer.
    /// When omitted, the primary control-plane node's resolved IP is used.
    /// Format: `<host>` or `<host>:<port>` (port defaults to 6443).
    #[serde(
        rename = "control-plane-endpoint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    control_plane_endpoint: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct SpecYaml {
    name: String,
    config: Vec<SpecConfigYaml>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct SpecConfigYaml {
    #[serde(rename = "machine-type")]
    machine_type: String,
    #[serde(rename = "boot-disk-image")]
    boot_disk_image: String,
    #[serde(rename = "boot-disk-size")]
    boot_disk_size: u64,
    /// Controls whether a public IP is assigned/used.
    /// Accepts `"public"` or `"private"` only; defaults to `"private"`.
    #[serde(rename = "ip-address", default)]
    ip_address: IpAddressType,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RuleYaml {
    group: String,
    generics: String,
    specs: String,
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
    generics: Vec<GenericYaml>,
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
    generics: Vec<GenericYaml>,
    specs: Vec<SpecYaml>,
    rules: Vec<RuleYaml>,
    credentials: DoCredentialsYaml,
}

// ---------------------------------------------------------------------------
// Unified view of a loaded config (provider-agnostic body + typed creds)
// ---------------------------------------------------------------------------

struct CommonConfig {
    groups: Vec<GroupYaml>,
    generics: Vec<GenericYaml>,
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
                generics: yaml.generics,
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
                generics: yaml.generics,
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
// Spec validation
// ---------------------------------------------------------------------------

fn validate_specs(specs: &[SpecYaml]) -> Result<(), Box<dyn std::error::Error>> {
    for spec_yaml in specs {
        for (i, cfg) in spec_yaml.config.iter().enumerate() {
            match cfg.ip_address {
                IpAddressType::Public | IpAddressType::Private => {}
            }

            println!(
                "  spec '{}' [{}]: ip-address = {}",
                spec_yaml.name, i, cfg.ip_address
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Rule resolution (provider-agnostic)
// ---------------------------------------------------------------------------

struct ResolvedRule<'a> {
    group_name: &'a str,
    generics_name: &'a str,
    specs_name: &'a str,
    nodes: &'a [String],
    generic: &'a GenericConfigYaml,
    spec: &'a SpecConfigYaml,
}

fn resolve_rules<'a>(
    common: &'a CommonConfig,
) -> Result<Vec<ResolvedRule<'a>>, Box<dyn std::error::Error>> {
    let groups: HashMap<&str, &[String]> = common
        .groups
        .iter()
        .map(|g| (g.name.as_str(), g.node.as_slice()))
        .collect();

    let generics: HashMap<&str, &GenericConfigYaml> = common
        .generics
        .iter()
        .filter_map(|g| g.config.first().map(|c| (g.name.as_str(), c)))
        .collect();

    let specs: HashMap<&str, &SpecConfigYaml> = common
        .specs
        .iter()
        .filter_map(|s| s.config.first().map(|c| (s.name.as_str(), c)))
        .collect();

    common
        .rules
        .iter()
        .map(|rule| {
            let nodes = *groups
                .get(rule.group.as_str())
                .ok_or_else(|| format!("Rule references unknown group '{}'", rule.group))?;
            let generic = *generics
                .get(rule.generics.as_str())
                .ok_or_else(|| format!("Rule references unknown generics '{}'", rule.generics))?;
            let spec = *specs
                .get(rule.specs.as_str())
                .ok_or_else(|| format!("Rule references unknown specs '{}'", rule.specs))?;
            Ok(ResolvedRule {
                group_name: &rule.group,
                generics_name: &rule.generics,
                specs_name: &rule.specs,
                nodes,
                generic,
                spec,
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
            "\n  group: {}  (generics: {}, specs: {})",
            r.group_name, r.generics_name, r.specs_name
        );
        println!(
            "    machine-type: {}  image: {}  disk: {} GB  ip-address: {}",
            r.spec.machine_type, r.spec.boot_disk_image, r.spec.boot_disk_size, r.spec.ip_address
        );
        println!(
            "    user: {}  ssh-public-key: {}",
            r.generic.user, r.generic.ssh_public_key
        );
        for node in r.nodes {
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
            "\n── Group: {} ─────────────────────────────────────────────────────",
            r.group_name
        );

        let ssh_meta = read_ssh_public_key(&r.generic.ssh_public_key)
            .map(|k| format!("{}:{k}", r.generic.user))
            .unwrap_or_else(|e| {
                eprintln!("  ⚠ Could not read SSH public key: {e}");
                String::new()
            });

        let assign_public_ip = r.spec.ip_address == IpAddressType::Public;

        for node in r.nodes {
            println!("\n  ── Creating instance: {node} ──");
            let resp = provider.create_vm(
                node,
                &r.spec.machine_type,
                &r.spec.boot_disk_image,
                r.spec.boot_disk_size,
                &ssh_meta,
                &r.generic.script,
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

    let mut all_nodes: Vec<(&str, &str)> = Vec::new();
    for group in &common.groups {
        for node in &group.node {
            println!("  {}  →  {}", group.name, node);
            all_nodes.push((&group.name, node));
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

    for (group_name, node) in &all_nodes {
        println!("\n  ── Deleting [{group_name}] {node} ──");
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
//
// Mirrors the three actions that `cisak install --control-plane` used to
// perform, now run as individual SSH commands so maglev owns the logic
// directly and no longer depends on the deprecated cisak subcommand.
//
//  1. sudo kubeadm init  [--control-plane-endpoint <ep> --upload-certs]
//  2. cilium --kubeconfig /etc/kubernetes/admin.conf install
//  3. cilium --kubeconfig /etc/kubernetes/admin.conf status --wait
// ---------------------------------------------------------------------------

const ADMIN_KUBECONFIG: &str = "/etc/kubernetes/admin.conf";

/// Run the three control-plane bootstrap steps on `cp_ip` via SSH.
///
/// Each step is shown to the operator before execution and can be skipped
/// individually.  If the operator skips `kubeadm init` the function returns
/// immediately — there is nothing useful to do without an initialised cluster.
fn provision_control_plane_node(
    cp_ip: &str,
    cp_name: &str,
    ssh_user: &str,
    ssh_priv_path: &str,
    cp_endpoint: &str,
    is_ha: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // ── Step A: kubeadm init ──────────────────────────────────────────────────
    //
    // For HA clusters (≥ 3 control-plane nodes) we pass:
    //   --control-plane-endpoint  so all nodes share a stable API address
    //   --upload-certs            so joining CP nodes can pull certificates
    //                             automatically instead of requiring manual
    //                             distribution
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
    //
    // The Cilium CLI binary is already on the node (installed by cisak install
    // -y via the startup script).  We pass --kubeconfig explicitly so the
    // command works even before ~/.kube/config is set up for the SSH user.
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
    //
    // Blocks until all Cilium components report healthy.  This ensures the
    // cluster's networking layer is fully operational before maglev attempts
    // to join worker (or additional control-plane) nodes.
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

    let default_generic = common
        .generics
        .iter()
        .find(|g| g.name == "default")
        .and_then(|g| g.config.first())
        .ok_or("No 'default' generics entry found in config")?;

    let ssh_user = &default_generic.user;
    let ssh_pub_path = default_generic.ssh_public_key.as_str();
    let ssh_priv_path = expand_tilde(ssh_pub_path.strip_suffix(".pub").unwrap_or(ssh_pub_path));

    println!("\n── Provider settings ────────────────────────────────────────────────────");
    loaded.describe();

    // ── Build group → prefer_public map ──────────────────────────────────────
    let group_prefer_public: HashMap<&str, bool> = common
        .rules
        .iter()
        .filter_map(|rule| {
            let ip_type = common
                .specs
                .iter()
                .find(|s| s.name == rule.specs)
                .and_then(|s| s.config.first())
                .map(|c| c.ip_address)
                .unwrap_or(IpAddressType::Private);
            Some((rule.group.as_str(), ip_type == IpAddressType::Public))
        })
        .collect();

    let cp_prefer_public = *group_prefer_public.get("control-plane").unwrap_or(&false);
    let worker_prefer_public = *group_prefer_public.get("worker").unwrap_or(&false);

    // ── Collect node lists ────────────────────────────────────────────────────
    let cp_nodes: Vec<&str> = common
        .rules
        .iter()
        .find(|r| r.group == "control-plane")
        .and_then(|r| common.groups.iter().find(|g| g.name == r.group))
        .map(|g| g.node.iter().map(String::as_str).collect())
        .unwrap_or_default();

    let worker_nodes: Vec<&str> = common
        .rules
        .iter()
        .find(|r| r.group == "worker")
        .and_then(|r| common.groups.iter().find(|g| g.name == r.group))
        .map(|g| g.node.iter().map(String::as_str).collect())
        .unwrap_or_default();

    let cp_count = cp_nodes.len();

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

    let use_jump_for_workers = !worker_prefer_public && cp_prefer_public;
    if use_jump_for_workers {
        println!(
            "\n  ℹ  Workers have private IPs and control-plane has public IPs. \
             Worker SSH will be routed through the primary control-plane node \
             (ProxyJump / SSH agent forwarding)."
        );
    }

    // ── Resolve IPs ───────────────────────────────────────────────────────────
    println!("\n  Fetching IPs …");
    println!(
        "  control-plane ip-address: {}",
        if cp_prefer_public {
            "public"
        } else {
            "private"
        }
    );
    println!(
        "  worker        ip-address: {}",
        if worker_prefer_public {
            "public"
        } else {
            "private"
        }
    );

    let resolve_ips = |nodes: &[&str],
                       prefer_public: bool|
     -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
        nodes
            .iter()
            .map(|&name| {
                let ip = provider.get_vm_ip(name, prefer_public)?;
                println!(
                    "  {name:<30} →  {ip}  ({})",
                    if prefer_public { "public" } else { "private" }
                );
                Ok((name.to_string(), ip))
            })
            .collect()
    };

    let cp_with_ips: Vec<(String, String)> = resolve_ips(&cp_nodes, cp_prefer_public)?;
    let worker_with_ips: Vec<(String, String)> = resolve_ips(&worker_nodes, worker_prefer_public)?;

    println!("  SSH user: {ssh_user}  private key: {ssh_priv_path}");

    let (primary_cp_name, primary_cp_ip) = cp_with_ips
        .first()
        .ok_or("No control-plane nodes available")?;

    // ── Determine the stable control-plane endpoint ───────────────────────────
    let cp_endpoint: String = match &default_generic.control_plane_endpoint {
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
             in the generics block of your config."
        );
    }

    // ── Step 1 / 3 — Primary control-plane ───────────────────────────────────
    println!("\n━━ Step 1 / 3 — Primary control-plane init ({primary_cp_name}) ━━━━━━━━━━━━");
    println!("\n  [{primary_cp_name}]  ({primary_cp_ip})");

    if prompt_yes_no(&format!("  SSH-check and provision {primary_cp_name}?")) {
        // ── NEW: verify DNS before anything touches kubeadm ──────────────────
        ensure_cp_endpoint_resolves(
            primary_cp_name,
            &cp_endpoint,
            primary_cp_ip, // temporary stand-in for the real LB
            |cmd| ssh_capture(primary_cp_ip, ssh_user, &ssh_priv_path, cmd),
            |cmd| ssh_run(primary_cp_ip, ssh_user, &ssh_priv_path, cmd),
        )?;
        // ─────────────────────────────────────────────────────────────────────

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

        for (idx, (name, ip)) in cp_with_ips.iter().skip(1).enumerate() {
            println!("\n  [{}/{}] {name}  ({ip})", idx + 2, cp_with_ips.len());

            if !prompt_yes_no(&format!("  Check and join {name} as control-plane?")) {
                println!("  Skipped.");
                continue;
            }

            // ── NEW ──────────────────────────────────────────────────────────
            ensure_cp_endpoint_resolves(
                name,
                &cp_endpoint,
                primary_cp_ip,
                |cmd| ssh_capture(ip, ssh_user, &ssh_priv_path, cmd),
                |cmd| ssh_run(ip, ssh_user, &ssh_priv_path, cmd),
            )?;
            // ─────────────────────────────────────────────────────────────────

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

    if use_jump_for_workers {
        println!(
            "  Routing worker SSH through {primary_cp_name} ({primary_cp_ip}) \
             via ProxyJump."
        );
    }

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

    for (idx, (name, ip)) in worker_with_ips.iter().enumerate() {
        println!("\n  [{}/{}] {name}  ({ip})", idx + 1, worker_with_ips.len());

        if !prompt_yes_no("  Fetch join command and join?") {
            println!("  Skipped.");
            continue;
        }

        // ── NEW: DNS guard — direct or via jump depending on topology ────────
        if use_jump_for_workers {
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
        // ─────────────────────────────────────────────────────────────────────

        if worker_join_cmd.is_empty() {
            eprintln!("  ✗ No join command available — skipping {name}.");
            continue;
        }

        println!("  Join command: {worker_join_cmd}");

        let already_joined = if use_jump_for_workers {
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

        let result = if use_jump_for_workers {
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
             node's IP, add to the generics block in your config:\n\
             \n\
             \tcontrol-plane-endpoint: \"<lb-address-or-dns>\""
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
        // grep guards against duplicate lines on re-runs.
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
